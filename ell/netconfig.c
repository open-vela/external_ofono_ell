/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2022  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <net/if.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "private.h"
#include "useful.h"
#include "log.h"
#include "dhcp.h"
#include "dhcp-private.h"
#include "icmp6.h"
#include "icmp6-private.h"
#include "dhcp6.h"
#include "netlink.h"
#include "rtnl.h"
#include "rtnl-private.h"
#include "queue.h"
#include "time.h"
#include "idle.h"
#include "strv.h"
#include "net.h"
#include "net-private.h"
#include "acd.h"
#include "timeout.h"
#include "netconfig.h"

struct l_netconfig {
	uint32_t ifindex;
	uint32_t route_priority;

	bool v4_enabled;
	struct l_rtnl_address *v4_static_addr;
	char *v4_gateway_override;
	char **v4_dns_override;
	char **v4_domain_names_override;
	bool acd_enabled;

	bool v6_enabled;
	struct l_rtnl_address *v6_static_addr;
	char *v6_gateway_override;
	char **v6_dns_override;
	char **v6_domain_names_override;
	bool optimistic_dad_enabled;

	bool started;
	struct l_idle *do_static_work;
	bool v4_configured;
	struct l_dhcp_client *dhcp_client;
	bool v6_configured;
	struct l_icmp6_client *icmp6_client;
	struct l_dhcp6_client *dhcp6_client;
	struct l_idle *signal_expired_work;
	unsigned int ifaddr6_dump_cmd_id;
	struct l_queue *icmp_route_data;
	struct l_acd *acd;
	unsigned int orig_disable_ipv6;
	long orig_optimistic_dad;
	uint8_t mac[ETH_ALEN];
	struct l_timeout *ra_timeout;
	bool have_lla;
	enum {
		NETCONFIG_V6_METHOD_UNSET,
		NETCONFIG_V6_METHOD_DHCP,
		NETCONFIG_V6_METHOD_SLAAC,
	} v6_auto_method;
	struct l_queue *slaac_dnses;
	struct l_queue *slaac_domains;

	/* These objects, if not NULL, are owned by @addresses and @routes */
	struct l_rtnl_address *v4_address;
	struct l_rtnl_route *v4_subnet_route;
	struct l_rtnl_route *v4_default_route;
	struct l_rtnl_address *v6_address;

	struct {
		struct l_queue *current;

		/*
		 * Temporary lists for use by the UPDATED handler to avoid
		 * having to remove all entries on the interface and re-add
		 * them from @current.  Entries in @updated are those that
		 * RTM_NEWADDR/RTM_NEWROUTE will correctly identify as
		 * existing objects and replace (with NLM_F_REPLACE) or
		 * error out (without it) rather than create duplicates,
		 * for example those that only have their lifetime updated.
		 *
		 * Any entries in @added and @updated are owned by @current.
		 * Entries in @removed need to be removed with an
		 * RTM_DELADD/RTM_DELROUTE while those in @expired are only
		 * informative as the kernel will have removed them already.
		 */
		struct l_queue *added;
		struct l_queue *updated;
		struct l_queue *removed;
		struct l_queue *expired;
	} addresses, routes;

	struct {
		l_netconfig_event_cb_t callback;
		void *user_data;
		l_netconfig_destroy_cb_t destroy;
	} handler;
};

struct netconfig_route_data {
	struct l_rtnl_route *route;
	uint64_t last_ra_time;
	uint64_t kernel_expiry;
	uint64_t max_ra_interval;
};

union netconfig_addr {
	struct in_addr v4;
	struct in6_addr v6;
};

static struct l_queue *addr_wait_list;
static unsigned int rtnl_id;

static const unsigned int max_icmp6_routes = 100;
static const unsigned int max_icmp6_dnses = 10;
static const unsigned int max_icmp6_domains = 10;

static void netconfig_update_cleanup(struct l_netconfig *nc)
{
	l_queue_clear(nc->addresses.added, NULL);
	l_queue_clear(nc->addresses.updated, NULL);
	l_queue_clear(nc->addresses.removed,
			(l_queue_destroy_func_t) l_rtnl_address_free);
	l_queue_clear(nc->addresses.expired,
			(l_queue_destroy_func_t) l_rtnl_address_free);
	l_queue_clear(nc->routes.added, NULL);
	l_queue_clear(nc->routes.updated, NULL);
	l_queue_clear(nc->routes.removed,
			(l_queue_destroy_func_t) l_rtnl_route_free);
	l_queue_clear(nc->routes.expired,
			(l_queue_destroy_func_t) l_rtnl_route_free);
}

static void netconfig_emit_event(struct l_netconfig *nc, uint8_t family,
					enum l_netconfig_event event)
{
	if (!nc->handler.callback)
		return;

	nc->handler.callback(nc, family, event, nc->handler.user_data);

	if (L_IN_SET(event, L_NETCONFIG_EVENT_UPDATE,
			L_NETCONFIG_EVENT_CONFIGURE,
			L_NETCONFIG_EVENT_UNCONFIGURE))
		netconfig_update_cleanup(nc);
}

static struct l_rtnl_route *netconfig_route_new(struct l_netconfig *nc,
						uint8_t family,
						const void *dst,
						uint8_t prefix_len,
						const void *gw,
						uint8_t protocol)
{
	struct l_rtnl_route *rt = l_new(struct l_rtnl_route, 1);

	rt->family = family;
	rt->scope = (family == AF_INET && dst) ?
		RT_SCOPE_LINK : RT_SCOPE_UNIVERSE;
	rt->protocol = protocol;
	rt->lifetime = 0xffffffff;
	rt->priority = nc->route_priority;

	if (dst) {
		memcpy(&rt->dst, dst, family == AF_INET ? 4 : 16);
		rt->dst_prefix_len = prefix_len;
	}

	if (gw)
		memcpy(&rt->gw, gw, family == AF_INET ? 4 : 16);

	return rt;
}

static void netconfig_signal_expired(struct l_idle *idle, void *user_data)
{
	struct l_netconfig *nc = user_data;

	l_idle_remove(l_steal_ptr(nc->signal_expired_work));

	/*
	 * If the idle work was scheduled from within l_netconfig_get_routes
	 * or netconfig_icmp6_event_handler, the user is likely to have
	 * already received an event and had a chance to process the expired
	 * routes list.  In that case there's no need to emit a new event,
	 * and the list will have been emptied in netconfig_update_cleanup()
	 * anyway.
	 */
	if (!l_queue_isempty(nc->routes.expired))
		netconfig_emit_event(nc, AF_INET6, L_NETCONFIG_EVENT_UPDATE);
}

static void netconfig_add_v4_routes(struct l_netconfig *nc, const char *ip,
					uint8_t prefix_len, const char *gateway,
					uint8_t rtm_protocol)
{
	struct in_addr in_addr;

	/* Subnet route */

	if (L_WARN_ON(inet_pton(AF_INET, ip, &in_addr) != 1))
		return;

	in_addr.s_addr &= htonl(0xfffffffflu << (32 - prefix_len));
	nc->v4_subnet_route = netconfig_route_new(nc, AF_INET, &in_addr,
							prefix_len, NULL,
							rtm_protocol);
	l_queue_push_tail(nc->routes.current, nc->v4_subnet_route);
	l_queue_push_tail(nc->routes.added, nc->v4_subnet_route);

	/* Gateway route */

	if (nc->v4_gateway_override) {
		gateway = nc->v4_gateway_override;
		rtm_protocol = RTPROT_STATIC;
	}

	if (!gateway)
		return;

	nc->v4_default_route = l_rtnl_route_new_gateway(gateway);
	l_rtnl_route_set_protocol(nc->v4_default_route, rtm_protocol);
	L_WARN_ON(!l_rtnl_route_set_prefsrc(nc->v4_default_route, ip));
	l_rtnl_route_set_priority(nc->v4_default_route, nc->route_priority);
	l_queue_push_tail(nc->routes.current, nc->v4_default_route);
	l_queue_push_tail(nc->routes.added, nc->v4_default_route);
}

static void netconfig_add_v6_static_routes(struct l_netconfig *nc,
						const char *ip,
						uint8_t prefix_len)
{
	struct in6_addr in6_addr;
	const void *prefix;
	struct l_rtnl_route *v6_subnet_route;
	struct l_rtnl_route *v6_default_route;

	/* Subnet route */

	if (L_WARN_ON(inet_pton(AF_INET6, ip, &in6_addr) != 1))
		return;

	/*
	 * Zero out host address bits, aka. interface ID, to produce
	 * the network address or prefix.
	 */
	prefix = net_prefix_from_ipv6(in6_addr.s6_addr, prefix_len);

	/*
	 * One reason we add a subnet route instead of letting the kernel
	 * do it, by not specifying IFA_F_NOPREFIXROUTE for the address,
	 * is that that would force a 0 metric for the route.
	 */
	v6_subnet_route = netconfig_route_new(nc, AF_INET6, prefix, prefix_len,
						NULL, RTPROT_STATIC);
	l_queue_push_tail(nc->routes.current, v6_subnet_route);
	l_queue_push_tail(nc->routes.added, v6_subnet_route);

	/* Gateway route */

	if (!nc->v6_gateway_override)
		return;

	v6_default_route = l_rtnl_route_new_gateway(nc->v6_gateway_override);
	l_rtnl_route_set_protocol(v6_default_route, RTPROT_STATIC);
	/*
	 * TODO: Optimally we'd set the prefsrc on the route with:
	 * L_WARN_ON(!l_rtnl_route_set_prefsrc(v6_default_route, ip));
	 *
	 * but that means that we can only commit the route to the kernel
	 * with an RTM_NEWROUTE command after the corresponding RTM_NEWADDR
	 * has returned and the kernel has finished DAD for the address and
	 * cleared IFA_F_TENTATIVE.  That will complicate
	 * l_netconfig_apply_rtnl() significantly but may be inevitable.
	 */

	l_queue_push_tail(nc->routes.current, v6_default_route);
	l_queue_push_tail(nc->routes.added, v6_default_route);
}

static bool netconfig_address_exists(struct l_queue *list,
					const struct l_rtnl_address *address)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(list); entry;
			entry = entry->next)
		if ((const struct l_rtnl_address *) entry->data == address)
			return true;

	return false;
}

static bool netconfig_route_exists(struct l_queue *list,
					const struct l_rtnl_route *route)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(list); entry;
			entry = entry->next)
		if ((const struct l_rtnl_route *) entry->data == route)
			return true;

	return false;
}

static void netconfig_add_dhcp_address_routes(struct l_netconfig *nc)
{
	const struct l_dhcp_lease *lease =
		l_dhcp_client_get_lease(nc->dhcp_client);
	_auto_(l_free) char *ip = NULL;
	_auto_(l_free) char *broadcast = NULL;
	_auto_(l_free) char *gateway = NULL;
	uint32_t prefix_len;

	ip = l_dhcp_lease_get_address(lease);
	broadcast = l_dhcp_lease_get_broadcast(lease);

	prefix_len = l_dhcp_lease_get_prefix_length(lease);
	if (!prefix_len)
		prefix_len = 24;

	nc->v4_address = l_rtnl_address_new(ip, prefix_len);
	if (L_WARN_ON(!nc->v4_address))
		return;

	l_rtnl_address_set_noprefixroute(nc->v4_address, true);

	if (broadcast)
		l_rtnl_address_set_broadcast(nc->v4_address, broadcast);

	l_queue_push_tail(nc->addresses.current, nc->v4_address);
	l_queue_push_tail(nc->addresses.added, nc->v4_address);

	gateway = l_dhcp_lease_get_gateway(lease);
	netconfig_add_v4_routes(nc, ip, prefix_len, gateway, RTPROT_DHCP);
}

static void netconfig_set_dhcp_lifetimes(struct l_netconfig *nc, bool updated)
{
	const struct l_dhcp_lease *lease =
		l_dhcp_client_get_lease(nc->dhcp_client);
	uint32_t lifetime = l_dhcp_lease_get_lifetime(lease);
	uint64_t expiry = l_dhcp_lease_get_start_time(lease) +
		lifetime * L_USEC_PER_SEC;

	l_rtnl_address_set_lifetimes(nc->v4_address, 0, lifetime);
	l_rtnl_address_set_expiry(nc->v4_address, 0, expiry);

	if (updated && !netconfig_address_exists(nc->addresses.added,
							nc->v4_address))
		l_queue_push_tail(nc->addresses.updated, nc->v4_address);

	l_rtnl_route_set_lifetime(nc->v4_subnet_route, lifetime);
	l_rtnl_route_set_expiry(nc->v4_subnet_route, expiry);

	if (updated && !netconfig_route_exists(nc->routes.added,
						nc->v4_subnet_route))
		l_queue_push_tail(nc->routes.updated, nc->v4_subnet_route);

	if (!nc->v4_default_route)
		return;

	l_rtnl_route_set_lifetime(nc->v4_default_route, lifetime);
	l_rtnl_route_set_expiry(nc->v4_default_route, expiry);

	if (updated && !netconfig_route_exists(nc->routes.added,
						nc->v4_default_route))
		l_queue_push_tail(nc->routes.updated, nc->v4_default_route);
}

static void netconfig_remove_v4_address_routes(struct l_netconfig *nc,
						bool expired)
{
	struct l_queue *routes =
		expired ? nc->routes.expired : nc->routes.removed;

	l_queue_remove(nc->addresses.current, nc->v4_address);
	l_queue_remove(nc->addresses.updated, nc->v4_address);

	if (!l_queue_remove(nc->addresses.added, nc->v4_address))
		l_queue_push_tail(
			expired ? nc->addresses.expired : nc->addresses.removed,
			nc->v4_address);

	nc->v4_address = NULL;

	l_queue_remove(nc->routes.current, nc->v4_subnet_route);
	l_queue_remove(nc->routes.updated, nc->v4_subnet_route);

	if (!l_queue_remove(nc->routes.added, nc->v4_subnet_route))
		l_queue_push_tail(routes, nc->v4_subnet_route);

	nc->v4_subnet_route = NULL;

	if (nc->v4_default_route) {
		l_queue_remove(nc->routes.current, nc->v4_default_route);
		l_queue_remove(nc->routes.updated, nc->v4_default_route);

		if (!l_queue_remove(nc->routes.added, nc->v4_default_route))
			l_queue_push_tail(routes, nc->v4_default_route);

		nc->v4_default_route = NULL;
	}
}

static void netconfig_set_neighbor_entry_cb(int error,
						uint16_t type, const void *data,
						uint32_t len, void *user_data)
{
	/* Not critical.  TODO: log warning */
}

static int netconfig_dhcp_gateway_to_arp(struct l_netconfig *nc)
{
	const struct l_dhcp_lease *lease =
		l_dhcp_client_get_lease(nc->dhcp_client);
	_auto_(l_free) char *server_id = l_dhcp_lease_get_server_id(lease);
	_auto_(l_free) char *gw = l_dhcp_lease_get_gateway(lease);
	const uint8_t *server_mac = l_dhcp_lease_get_server_mac(lease);
	struct in_addr in_gw;

	if (!gw || strcmp(server_id, gw) || !server_mac)
		return -ENOENT;

	/* Gateway MAC is known, write it into ARP cache to save ARP traffic */
	in_gw.s_addr = l_dhcp_lease_get_gateway_u32(lease);

	if (!l_rtnl_neighbor_set_hwaddr(l_rtnl_get(), nc->ifindex, AF_INET,
					&in_gw, server_mac, ETH_ALEN,
					netconfig_set_neighbor_entry_cb, nc,
					NULL))
		return -EIO;

	return 0;
}

static void netconfig_dhcp_event_handler(struct l_dhcp_client *client,
						enum l_dhcp_client_event event,
						void *user_data)
{
	struct l_netconfig *nc = user_data;

	switch (event) {
	case L_DHCP_CLIENT_EVENT_IP_CHANGED:
		if (L_WARN_ON(!nc->v4_configured))
			break;

		netconfig_remove_v4_address_routes(nc, false);
		netconfig_add_dhcp_address_routes(nc);
		netconfig_set_dhcp_lifetimes(nc, false);
		netconfig_emit_event(nc, AF_INET, L_NETCONFIG_EVENT_UPDATE);
		break;
	case L_DHCP_CLIENT_EVENT_LEASE_OBTAINED:
		if (L_WARN_ON(nc->v4_configured))
			break;

		netconfig_add_dhcp_address_routes(nc);
		netconfig_set_dhcp_lifetimes(nc, false);
		nc->v4_configured = true;
		netconfig_emit_event(nc, AF_INET, L_NETCONFIG_EVENT_CONFIGURE);
		netconfig_dhcp_gateway_to_arp(nc);
		break;
	case L_DHCP_CLIENT_EVENT_LEASE_RENEWED:
		if (L_WARN_ON(!nc->v4_configured))
			break;

		netconfig_set_dhcp_lifetimes(nc, true);
		netconfig_emit_event(nc, AF_INET, L_NETCONFIG_EVENT_UPDATE);
		break;
	case L_DHCP_CLIENT_EVENT_LEASE_EXPIRED:
		if (L_WARN_ON(!nc->v4_configured))
			break;

		netconfig_remove_v4_address_routes(nc, true);
		nc->v4_configured = false;

		if (l_dhcp_client_start(nc->dhcp_client))
			/* TODO: also start a new timeout */
			netconfig_emit_event(nc, AF_INET,
						L_NETCONFIG_EVENT_UNCONFIGURE);
		else
			netconfig_emit_event(nc, AF_INET,
						L_NETCONFIG_EVENT_FAILED);

		break;
	case L_DHCP_CLIENT_EVENT_NO_LEASE:
		L_WARN_ON(nc->v4_configured);

		/*
		 * The requested address is no longer available, try to restart
		 * the client.
		 *
		 * TODO: this may need to be delayed so we don't flood the
		 * network with DISCOVERs and NAKs.  Also add a retry limit or
		 * better yet a configurable timeout.
		 */
		if (!l_dhcp_client_start(nc->dhcp_client))
			netconfig_emit_event(nc, AF_INET,
						L_NETCONFIG_EVENT_FAILED);

		break;
	}
}

static void netconfig_add_dhcp6_address(struct l_netconfig *nc)
{
	const struct l_dhcp6_lease *lease =
		l_dhcp6_client_get_lease(nc->dhcp6_client);
	_auto_(l_free) char *ip = NULL;
	uint32_t prefix_len;

	if (L_WARN_ON(!lease))
		return;

	ip = l_dhcp6_lease_get_address(lease);
	prefix_len = l_dhcp6_lease_get_prefix_length(lease);
	nc->v6_address = l_rtnl_address_new(ip, prefix_len);

	if (L_WARN_ON(!nc->v6_address))
		return;

	/*
	 * Assume we already have a route from a Router Advertisement
	 * covering the address from DHCPv6 + prefix length from DHCPv6.
	 * We might want to emit a warning of some sort or
	 * L_NETCONFIG_EVENT_FAILED if we don't since this would
	 * basically be fatal for IPv6 connectivity.
	 */
	l_rtnl_address_set_noprefixroute(nc->v6_address, true);

	l_queue_push_tail(nc->addresses.current, nc->v6_address);
	l_queue_push_tail(nc->addresses.added, nc->v6_address);
}

static void netconfig_set_dhcp6_address_lifetimes(struct l_netconfig *nc,
							bool updated)
{
	const struct l_dhcp6_lease *lease =
		l_dhcp6_client_get_lease(nc->dhcp6_client);
	uint32_t p, v;
	uint64_t start_time;

	if (L_WARN_ON(!lease))
		return;

	p = l_dhcp6_lease_get_preferred_lifetime(lease);
	v = l_dhcp6_lease_get_valid_lifetime(lease);
	start_time = l_dhcp6_lease_get_start_time(lease);

	l_rtnl_address_set_lifetimes(nc->v6_address, p, v);
	l_rtnl_address_set_expiry(nc->v6_address,
					start_time + p * L_USEC_PER_SEC,
					start_time + v * L_USEC_PER_SEC);

	if (updated && !netconfig_address_exists(nc->addresses.added,
							nc->v6_address))
		l_queue_push_tail(nc->addresses.updated, nc->v6_address);
}

static void netconfig_remove_dhcp6_address(struct l_netconfig *nc, bool expired)
{
	l_queue_remove(nc->addresses.current, nc->v6_address);
	l_queue_remove(nc->addresses.updated, nc->v6_address);

	if (!l_queue_remove(nc->addresses.added, nc->v6_address))
		l_queue_push_tail(
			expired ? nc->addresses.expired : nc->addresses.removed,
			nc->v6_address);

	nc->v6_address = NULL;
}

static void netconfig_dhcp6_event_handler(struct l_dhcp6_client *client,
						enum l_dhcp6_client_event event,
						void *user_data)
{
	struct l_netconfig *nc = user_data;

	switch (event) {
	case L_DHCP6_CLIENT_EVENT_LEASE_OBTAINED:
		if (L_WARN_ON(nc->v6_configured))
			break;

		netconfig_add_dhcp6_address(nc);
		netconfig_set_dhcp6_address_lifetimes(nc, false);
		nc->v6_configured = true;
		netconfig_emit_event(nc, AF_INET6, L_NETCONFIG_EVENT_CONFIGURE);
		break;
	case L_DHCP6_CLIENT_EVENT_IP_CHANGED:
		if (L_WARN_ON(!nc->v6_configured))
			break;

		netconfig_remove_dhcp6_address(nc, false);
		netconfig_add_dhcp6_address(nc);
		netconfig_set_dhcp6_address_lifetimes(nc, false);
		netconfig_emit_event(nc, AF_INET6, L_NETCONFIG_EVENT_UPDATE);
		break;
	case L_DHCP6_CLIENT_EVENT_LEASE_EXPIRED:
		if (L_WARN_ON(!nc->v6_configured))
			break;

		netconfig_remove_dhcp6_address(nc, true);
		nc->v6_configured = false;

		if (l_dhcp6_client_start(nc->dhcp6_client))
			/* TODO: also start a new timeout */
			netconfig_emit_event(nc, AF_INET6,
						L_NETCONFIG_EVENT_UNCONFIGURE);
		else
			netconfig_emit_event(nc, AF_INET6,
						L_NETCONFIG_EVENT_FAILED);

		break;
	case L_DHCP6_CLIENT_EVENT_LEASE_RENEWED:
		if (L_WARN_ON(!nc->v6_configured))
			break;

		netconfig_set_dhcp6_address_lifetimes(nc, true);
		netconfig_emit_event(nc, AF_INET6, L_NETCONFIG_EVENT_UPDATE);
		break;
	case L_DHCP6_CLIENT_EVENT_NO_LEASE:
		if (L_WARN_ON(nc->v6_configured))
			break;

		/*
		 * The requested address is no longer available, try to restart
		 * the client.
		 *
		 * TODO: this may need to be delayed so we don't flood the
		 * network with SOLICITs and DECLINEs.  Also add a retry limit
		 * or better yet a configurable timeout.
		 */
		if (!l_dhcp6_client_start(nc->dhcp6_client))
			netconfig_emit_event(nc, AF_INET6,
						L_NETCONFIG_EVENT_FAILED);

		break;
	}
}

static bool netconfig_match(const void *a, const void *b)
{
	return a == b;
}

static bool netconfig_match_addr(const void *a, const void *b)
{
	return memcmp(a, b, 16) == 0;
}

static bool netconfig_match_str(const void *a, const void *b)
{
	return strcmp(a, b) == 0;
}

static bool netconfig_check_start_dhcp6(struct l_netconfig *nc)
{
	/* Don't start DHCPv6 until we get an RA with the managed bit set */
	if (nc->ra_timeout || nc->v6_auto_method != NETCONFIG_V6_METHOD_DHCP)
		return true;

	/* Don't start DHCPv6 while waiting for the link-local address */
	if (!nc->have_lla)
		return true;

	return l_dhcp6_client_start(nc->dhcp6_client);
}

static void netconfig_ra_timeout_cb(struct l_timeout *timeout, void *user_data)
{
	struct l_netconfig *nc = user_data;

	l_timeout_remove(l_steal_ptr(nc->ra_timeout));

	/* No Router Advertisements received, assume no DHCPv6 or SLAAC */
	l_icmp6_client_stop(nc->icmp6_client);
	netconfig_emit_event(nc, AF_INET6, L_NETCONFIG_EVENT_FAILED);
}

static void netconfig_add_slaac_address(struct l_netconfig *nc,
					const struct l_icmp6_router *r)
{
	unsigned int i;
	const struct autoconf_prefix_info *longest = &r->ac_prefixes[0];
	uint8_t addr[16];
	char addr_str[INET6_ADDRSTRLEN];
	uint32_t p, v;

	/* Find the autoconfiguration prefix that offers the longest lifetime */
	for (i = 1; i < r->n_ac_prefixes; i++)
		if (r->ac_prefixes[i].preferred_lifetime >
				longest->preferred_lifetime)
			longest = &r->ac_prefixes[i];

	memcpy(addr, longest->prefix, 8);
	/* EUI-64-based Interface Identifier (RFC2464 Section 4) */
	addr[ 8] = nc->mac[0] ^ 0x02;
	addr[ 9] = nc->mac[1];
	addr[10] = nc->mac[2];
	addr[11] = 0xff;
	addr[12] = 0xfe;
	addr[13] = nc->mac[3];
	addr[14] = nc->mac[4];
	addr[15] = nc->mac[5];
	inet_ntop(AF_INET6, addr, addr_str, sizeof(addr_str));
	p = longest->preferred_lifetime;
	v = longest->valid_lifetime;

	nc->v6_address = l_rtnl_address_new(addr_str, 128);
	l_rtnl_address_set_noprefixroute(nc->v6_address, true);

	if (p != 0xffffffff || v != 0xffffffff) {
		l_rtnl_address_set_lifetimes(nc->v6_address,
					p != 0xffffffff ? p : 0,
					v != 0xffffffff ? v : 0);
		l_rtnl_address_set_expiry(nc->v6_address,
					p != 0xffffffff ?
					r->start_time + p * L_USEC_PER_SEC : 0,
					v != 0xffffffff ?
					r->start_time + v * L_USEC_PER_SEC : 0);
	}

	l_queue_push_tail(nc->addresses.current, nc->v6_address);
	l_queue_push_tail(nc->addresses.added, nc->v6_address);
	nc->v6_configured = true;
	netconfig_emit_event(nc, AF_INET6, L_NETCONFIG_EVENT_CONFIGURE);

	/* TODO: set a renew timeout */
}

static void netconfig_set_slaac_address_lifetimes(struct l_netconfig *nc,
						const struct l_icmp6_router *r)
{
	const uint8_t *addr = l_rtnl_address_get_in_addr(nc->v6_address);
	bool updated = false;
	uint64_t p_expiry;
	uint64_t v_expiry;
	uint32_t remaining = 0xffffffff;
	unsigned int i;

	if (L_WARN_ON(!addr))
		return;

	l_rtnl_address_get_expiry(nc->v6_address, &p_expiry, &v_expiry);

	if (v_expiry)
		remaining = (v_expiry - r->start_time) / L_USEC_PER_SEC;

	for (i = 0; i < r->n_ac_prefixes; i++) {
		const struct autoconf_prefix_info *prefix = &r->ac_prefixes[i];
		uint32_t p = prefix->preferred_lifetime;
		uint32_t v = prefix->valid_lifetime;

		if (memcmp(prefix->prefix, addr, 8))
			continue;

		/* RFC4862 Section 5.5.3 e) */
		if (v < 120 * 60 && v < remaining)
			v = 120 * 60; /* 2 hours */

		l_rtnl_address_set_lifetimes(nc->v6_address,
						p != 0xffffffff ? p : 0,
						v != 0xffffffff ? v : 0);
		p_expiry = p != 0xffffffff ? r->start_time + p * L_USEC_PER_SEC : 0;
		v_expiry = v != 0xffffffff ? r->start_time + v * L_USEC_PER_SEC : 0;
		l_rtnl_address_set_expiry(nc->v6_address, p_expiry, v_expiry);
		updated = true;

		/*
		 * TODO: modify the renew timeout.
		 *
		 * Also we probably want to apply a mechanism similar to that
		 * in netconfig_check_route_need_update() to avoid generating
		 * and UPDATED event for every RA that covers this prefix
		 * with constant lifetime values.
		 */
	}

	if (updated && !l_queue_find(nc->addresses.added, netconfig_match,
					nc->v6_address))
		l_queue_push_tail(nc->addresses.updated, nc->v6_address);
}

static bool netconfig_process_slaac_dns_info(struct l_netconfig *nc,
						const struct l_icmp6_router *r)
{
	bool updated = false;
	unsigned int i;
	unsigned int n_dns = l_queue_length(nc->slaac_dnses);
	unsigned int n_domains = l_queue_length(nc->slaac_domains);

	for (i = 0; i < r->n_dns; i++) {
		const struct dns_info *info = &r->dns_list[i];

		/*
		 * For simplicity don't track lifetimes (TODO), add entries
		 * when the lifetime is non-zero, remove them when the
		 * lifetime is zero.  We have no API to add time-limited
		 * entries to the system either.
		 *
		 * RFC8106 Section 5.1: "A value of zero means that the RDNSS
		 * addresses MUST no longer be used."
		 */
		if (info->lifetime) {
			if (n_dns >= max_icmp6_dnses)
				continue;

			if (l_queue_find(nc->slaac_dnses, netconfig_match_addr,
						info->address))
				continue;

			l_queue_push_tail(nc->slaac_dnses,
						l_memdup(info->address, 16));
			n_dns++;
		} else {
			void *addr = l_queue_remove_if(nc->slaac_dnses,
							netconfig_match_addr,
							info->address);

			if (!addr)
				continue;

			l_free(addr);
			n_dns--;
		}

		updated = true;
	}

	for (i = 0; i < r->n_domains; i++) {
		const struct domain_info *info = &r->domains[i];

		/*
		 * RFC8106 Section 5.2: "A value of zero means that the DNSSL
		 * domain names MUST no longer be used."
		 */
		if (info->lifetime) {
			if (n_domains >= max_icmp6_domains)
				continue;

			if (l_queue_find(nc->slaac_domains, netconfig_match_str,
						info->domain))
				continue;

			l_queue_push_tail(nc->slaac_domains,
						l_strdup(info->domain));
			n_domains++;
		} else {
			void *str = l_queue_remove_if(nc->slaac_domains,
							netconfig_match_str,
							info->domain);

			if (!str)
				continue;

			l_free(str);
			n_domains--;
		}

		updated = true;
	}

	return updated;
}

static uint64_t now;

static bool netconfig_check_route_expired(void *data, void *user_data)
{
	struct l_netconfig *nc = user_data;
	struct netconfig_route_data *rd = data;

	if (!rd->kernel_expiry || now < rd->kernel_expiry)
		return false;

	/*
	 * Since we set lifetimes on the routes we submit to the kernel with
	 * RTM_NEWROUTE, we count on them being deleted automatically so no
	 * need to send an RTM_DELROUTE.  We signal the fact that the route
	 * expired to the user by having it on the expired list but there's
	 * nothing that the user needs to do with the routes on that list
	 * like they do with the added, updated and removed lists.
	 *
	 * If for some reason the route is still on the added list, drop it
	 * from there and there's nothing to notify the user of.
	 */
	if (!l_queue_remove(nc->routes.added, rd->route))
		l_queue_push_tail(nc->routes.expired, rd->route);

	l_queue_remove(nc->routes.current, rd->route);
	l_queue_remove(nc->routes.updated, rd->route);
	l_queue_remove(nc->routes.removed, rd->route);
	return true;
}

static void netconfig_expire_routes(struct l_netconfig *nc)
{
	now = l_time_now();

	if (l_queue_foreach_remove(nc->icmp_route_data,
					netconfig_check_route_expired, nc) &&
			!l_queue_isempty(nc->routes.expired) &&
			!nc->signal_expired_work)
		nc->signal_expired_work = l_idle_create(
						netconfig_signal_expired,
						nc, NULL);
}

static struct netconfig_route_data *netconfig_find_icmp6_route(
						struct l_netconfig *nc,
						const uint8_t *gateway,
						const struct route_info *dst)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(nc->icmp_route_data); entry;
			entry = entry->next) {
		struct netconfig_route_data *rd = entry->data;
		const uint8_t *route_gateway;
		const uint8_t *route_dst;
		uint8_t route_prefix_len = 0;

		route_gateway = l_rtnl_route_get_gateway_in_addr(rd->route);
		if ((gateway || route_gateway) &&
				(!gateway || !route_gateway ||
				 memcmp(gateway, route_gateway, 16)))
			continue;

		route_dst = l_rtnl_route_get_dst_in_addr(rd->route,
							&route_prefix_len);
		if ((dst || route_prefix_len) &&
				(!dst || !route_prefix_len ||
				 dst->prefix_len != route_prefix_len ||
				 memcmp(dst->address, route_dst, 16)))
			continue;

		return rd;
	}

	return NULL;
}

static struct netconfig_route_data *netconfig_add_icmp6_route(
						struct l_netconfig *nc,
						const uint8_t *gateway,
						const struct route_info *dst,
						uint8_t preference)
{
	struct netconfig_route_data *rd;
	struct l_rtnl_route *rt;

	if (l_queue_length(nc->icmp_route_data) >= max_icmp6_routes)
		return NULL;	/* TODO: log a warning the first time */

	rt = netconfig_route_new(nc, AF_INET6, dst ? dst->address : NULL,
					dst ? dst->prefix_len : 0, gateway,
					RTPROT_RA);
	if (L_WARN_ON(!rt))
		return NULL;

	l_rtnl_route_set_preference(rt, preference);
	l_queue_push_tail(nc->routes.current, rt);
	l_queue_push_tail(nc->routes.added, rt);

	rd = l_new(struct netconfig_route_data, 1);
	rd->route = rt;
	l_queue_push_tail(nc->icmp_route_data, rd);
	return rd;
}

static bool netconfig_check_route_need_update(
					const struct netconfig_route_data *rd,
					const struct l_icmp6_router *ra,
					uint64_t new_expiry,
					uint64_t old_expiry)
{
	/*
	 * Decide whether the route is close enough to its expiry time that,
	 * based on the expected Router Advertisement frequency, we should
	 * notify the user and have them update the route's lifetime in the
	 * kernel.  This is an optimization to avoid triggering a syscall and
	 * potentially multiple context-switches in case we expect to have
	 * many more opportunities to update the lifetime before we even get
	 * close to the last expiry time we passed to the kernel.  Without
	 * this we might be wasting a lot of cycles over time if the RAs are
	 * frequent.
	 *
	 * Always update if we have no RA interval information or if the
	 * expiry is moved forward.
	 */
	if (!rd->max_ra_interval || new_expiry < rd->kernel_expiry)
		return true;

	return rd->kernel_expiry < ra->start_time + rd->max_ra_interval * 10;
}

static void netconfig_set_icmp6_route_data(struct l_netconfig *nc,
						struct netconfig_route_data *rd,
						const struct l_icmp6_router *ra,
						uint32_t valid_lifetime,
						uint32_t mtu, bool updated)
{
	uint64_t expiry = ra->start_time + valid_lifetime * L_USEC_PER_SEC;
	uint64_t old_expiry = l_rtnl_route_get_expiry(rd->route);
	bool differs = false;

	if (mtu != l_rtnl_route_get_mtu(rd->route)) {
		l_rtnl_route_set_mtu(rd->route, mtu);
		differs = true;
	}

	/*
	 * The route's lifetime is pretty useless on its own but keep it
	 * updated with the value from the last RA.  Routers can send the same
	 * lifetime in every RA, keep decreasing the lifetimes linearly or
	 * implement any other policy, regardless of whether the resulting
	 * expiry time varies or not.
	 */
	l_rtnl_route_set_lifetime(rd->route, valid_lifetime);

	if (rd->last_ra_time) {
		uint64_t interval = ra->start_time - rd->last_ra_time;

		if (interval > rd->max_ra_interval)
			rd->max_ra_interval = interval;
	}

	rd->last_ra_time = ra->start_time;

	/*
	 * valid_lifetime of 0 from a route_info means the route is being
	 * removed so we wouldn't be here.  valid_lifetime of 0xffffffff
	 * means no timeout.  Check if the lifetime is changing between
	 * finite and infinite, or two finite values that result in expiry
	 * time difference of more than a second -- to avoid emitting
	 * updates for changes resulting only from the valid_lifetime one
	 * second resolution and RA transmission jitter.  As RFC4861
	 * Section 6.2.7 puts it: "Due to link propagation delays and
	 * potentially poorly synchronized clocks between the routers such
	 * comparison SHOULD allow some time skew."  The RFC talks about
	 * routers processing one another's RAs but the same logic applies
	 * here.
	 */
	if (valid_lifetime == 0xffffffff)
		expiry = 0;

	if ((expiry || old_expiry) &&
			(!expiry || !old_expiry ||
			 l_time_diff(expiry, old_expiry) > L_USEC_PER_SEC)) {
		l_rtnl_route_set_expiry(rd->route, expiry);

		differs = differs || !expiry || !old_expiry ||
			netconfig_check_route_need_update(rd, ra,
							expiry, old_expiry);
	}

	if (updated && differs && !netconfig_route_exists(nc->routes.added,
								rd->route)) {
		l_queue_push_tail(nc->routes.updated, rd->route);
		rd->kernel_expiry = expiry;
	}
}

static void netconfig_remove_icmp6_route(struct l_netconfig *nc,
						struct netconfig_route_data *rd)
{
	l_queue_remove(nc->icmp_route_data, rd);
	l_queue_remove(nc->routes.current, rd->route);
	l_queue_remove(nc->routes.updated, rd->route);

	if (!l_queue_remove(nc->routes.added, rd->route))
		l_queue_push_tail(nc->routes.removed, rd->route);
}

static void netconfig_icmp6_event_handler(struct l_icmp6_client *client,
						enum l_icmp6_client_event event,
						void *event_data,
						void *user_data)
{
	struct l_netconfig *nc = user_data;
	const struct l_icmp6_router *r;
	struct netconfig_route_data *default_rd;
	unsigned int i;
	bool dns_updated = false;

	if (event != L_ICMP6_CLIENT_EVENT_ROUTER_FOUND)
		return;

	r = event_data;

	if (nc->ra_timeout)
		l_timeout_remove(l_steal_ptr(nc->ra_timeout));

	netconfig_expire_routes(nc);

	if (nc->v6_gateway_override)
		goto process_nondefault_routes;

	/* Process the default gateway information */
	default_rd = netconfig_find_icmp6_route(nc, r->address, NULL);

	if (!default_rd && r->lifetime) {
		default_rd = netconfig_add_icmp6_route(nc, r->address, NULL,
								r->pref);
		if (unlikely(!default_rd))
			return;

		/*
		 * r->lifetime is 16-bit only so there's no risk it gets
		 * confused for the special 0xffffffff value in
		 * netconfig_set_icmp6_route_data.
		 */
		netconfig_set_icmp6_route_data(nc, default_rd, r, r->lifetime,
						r->mtu, false);
	} else if (default_rd && r->lifetime)
		netconfig_set_icmp6_route_data(nc, default_rd, r, r->lifetime,
						r->mtu, true);
	else if (default_rd && !r->lifetime)
		netconfig_remove_icmp6_route(nc, default_rd);

process_nondefault_routes:
	/*
	 * Process the onlink and offlink routes, from the Router
	 * Advertisement's Prefix Information options and Route
	 * Information options respectively.
	 */
	for (i = 0; i < r->n_routes; i++) {
		const struct route_info *info = &r->routes[i];
		const uint8_t *gateway = info->onlink ? NULL : r->address;
		struct netconfig_route_data *rd =
			netconfig_find_icmp6_route(nc, gateway, info);

		if (!rd && info->valid_lifetime) {
			rd = netconfig_add_icmp6_route(nc, gateway, info,
							info->preference);
			if (unlikely(!rd))
				continue;

			netconfig_set_icmp6_route_data(nc, rd, r,
						info->valid_lifetime,
						gateway ? r->mtu : 0, false);
		} else if (rd && info->valid_lifetime)
			netconfig_set_icmp6_route_data(nc, rd, r,
						info->valid_lifetime,
						gateway ? r->mtu : 0, true);
		else if (rd && !info->valid_lifetime)
			netconfig_remove_icmp6_route(nc, rd);
	}

	/*
	 * For lack of a better policy, select between DHCPv6 and SLAAC based
	 * on the first RA received.  Prefer DHCPv6.
	 *
	 * Just like we currently only request one address in l_dhcp6_client,
	 * we only set up one address using SLAAC regardless of how many
	 * prefixes are available.  Generate the address in the prefix that
	 * offers the longest preferred_lifetime.
	 */
	if (nc->v6_auto_method == NETCONFIG_V6_METHOD_UNSET &&
			l_icmp6_router_get_managed(r)) {
		nc->v6_auto_method = NETCONFIG_V6_METHOD_DHCP;

		if (!netconfig_check_start_dhcp6(nc)) {
			netconfig_emit_event(nc, AF_INET6,
						L_NETCONFIG_EVENT_FAILED);
			return;
		}

		goto emit_event;
	}

	/*
	 * DHCP not available according to this router, check if any of the
	 * prefixes allow SLAAC.
	 */
	if (nc->v6_auto_method == NETCONFIG_V6_METHOD_UNSET &&
			r->n_ac_prefixes) {
		nc->v6_auto_method = NETCONFIG_V6_METHOD_SLAAC;

		/*
		 * Do this first so that any changes are included in the
		 * CONFIGURE event emitted next.
		 */
		nc->slaac_dnses = l_queue_new();
		nc->slaac_domains = l_queue_new();
		netconfig_process_slaac_dns_info(nc, r);

		/*
		 * The DAD for the link-local address may be still running
		 * but again we can generate the global address already and
		 * commit it to start in-kernel DAD for it.
		 *
		 * The global address alone should work for most uses.  On
		 * the other hand since both the link-local address and the
		 * global address are based on the same MAC, there's some
		 * correlation between one failing DAD and the other
		 * failing DAD due to another host using the same address.
		 * As RFC4862 Section 5.4 notes we can't rely on that to
		 * skip DAD for one of the addresses.
		 */

		netconfig_add_slaac_address(nc, r);
		return;
	}

	/* Neither method seems available, fail */
	if (nc->v6_auto_method == NETCONFIG_V6_METHOD_UNSET) {
		netconfig_emit_event(nc, AF_INET6, L_NETCONFIG_EVENT_FAILED);
		return;
	}

	/* DHCP already started or waiting for the LL address, nothing to do */
	if (nc->v6_auto_method == NETCONFIG_V6_METHOD_DHCP)
		goto emit_event;

	/*
	 * Otherwise we already have a SLAAC address, just check if any of the
	 * auto-configuration prefixes in this RA covers our existing address
	 * and allows us to extend its lifetime.
	 */
	netconfig_set_slaac_address_lifetimes(nc, r);
	dns_updated = netconfig_process_slaac_dns_info(nc, r);

emit_event:
	/*
	 * Note: we may be emitting this before L_NETCONFIG_EVENT_CONFIGURE.
	 * We should probably instead save the affected routes in separate
	 * lists and add them to the _CONFIGURE event, suppressing any _UPDATE
	 * events while nc->v6_configured is false.
	 */
	if (!l_queue_isempty(nc->routes.added) ||
			!l_queue_isempty(nc->routes.updated) ||
			!l_queue_isempty(nc->routes.removed) ||
			!l_queue_isempty(nc->routes.expired) ||
			!l_queue_isempty(nc->addresses.updated) ||
			dns_updated)
		netconfig_emit_event(nc, AF_INET6, L_NETCONFIG_EVENT_UPDATE);
}

static int netconfig_proc_write_ipv6_uint_setting(struct l_netconfig *nc,
							const char *setting,
							unsigned int value)
{
	char ifname[IF_NAMESIZE];
	_auto_(l_free) char *filename = NULL;
	_auto_(close) int fd = -1;
	int r;
	char valuestr[20];

	if (unlikely(!if_indextoname(nc->ifindex, ifname)))
		return -errno;

	filename = l_strdup_printf("/proc/sys/net/ipv6/conf/%s/%s",
					ifname, setting);

	fd = L_TFR(open(filename, O_WRONLY));
	if (unlikely(fd < 0))
		return -errno;

	snprintf(valuestr, sizeof(valuestr), "%u", value);
	r = L_TFR(write(fd, valuestr, strlen(valuestr)));
	return r > 0 ? 0 : -errno;
}

static long netconfig_proc_read_ipv6_uint_setting(struct l_netconfig *nc,
							const char *setting)
{
	char ifname[IF_NAMESIZE];
	_auto_(l_free) char *filename = NULL;
	_auto_(close) int fd = -1;
	int r;
	char valuestr[20];
	long value;
	char *endp;

	if (unlikely(!if_indextoname(nc->ifindex, ifname)))
		return -errno;

	filename = l_strdup_printf("/proc/sys/net/ipv6/conf/%s/%s",
					ifname, setting);

	fd = L_TFR(open(filename, O_RDONLY));
	if (unlikely(fd < 0))
		return -errno;

	r = L_TFR(read(fd, valuestr, sizeof(valuestr) - 1));
	if (unlikely(r < 1))
		return r == 0 ? -EINVAL : -errno;

	valuestr[r - 1] = '\0';
	errno = 0;
	value = strtoul(valuestr, &endp, 10);

	if (unlikely(errno || !L_IN_SET(*endp, '\n', '\0')))
		return -EINVAL;

	return value;
}

LIB_EXPORT struct l_netconfig *l_netconfig_new(uint32_t ifindex)
{
	struct l_netconfig *nc;

	nc = l_new(struct l_netconfig, 1);
	nc->ifindex = ifindex;

	nc->addresses.current = l_queue_new();
	nc->addresses.added = l_queue_new();
	nc->addresses.updated = l_queue_new();
	nc->addresses.removed = l_queue_new();
	nc->routes.current = l_queue_new();
	nc->routes.added = l_queue_new();
	nc->routes.updated = l_queue_new();
	nc->routes.removed = l_queue_new();
	nc->icmp_route_data = l_queue_new();

	nc->dhcp_client = l_dhcp_client_new(ifindex);
	l_dhcp_client_set_event_handler(nc->dhcp_client,
					netconfig_dhcp_event_handler,
					nc, NULL);

	nc->dhcp6_client = l_dhcp6_client_new(ifindex);
	l_dhcp6_client_set_nora(nc->dhcp6_client, true);
	l_dhcp6_client_set_event_handler(nc->dhcp6_client,
					netconfig_dhcp6_event_handler,
					nc, NULL);

	nc->icmp6_client = l_dhcp6_client_get_icmp6(nc->dhcp6_client);
	l_icmp6_client_add_event_handler(nc->icmp6_client,
					netconfig_icmp6_event_handler,
					nc, NULL);

	/* Disable in-kernel autoconfiguration for the interface */
	netconfig_proc_write_ipv6_uint_setting(nc, "accept_ra", 0);

	l_netconfig_reset_config(nc);
	return nc;
}

LIB_EXPORT void l_netconfig_destroy(struct l_netconfig *netconfig)
{
	if (unlikely(!netconfig))
		return;

	l_netconfig_stop(netconfig);

	l_netconfig_set_static_addr(netconfig, AF_INET, NULL);
	l_netconfig_set_gateway_override(netconfig, AF_INET, NULL);
	l_netconfig_set_dns_override(netconfig, AF_INET, NULL);
	l_netconfig_set_domain_names_override(netconfig, AF_INET, NULL);
	l_netconfig_set_static_addr(netconfig, AF_INET6, NULL);
	l_netconfig_set_gateway_override(netconfig, AF_INET6, NULL);
	l_netconfig_set_dns_override(netconfig, AF_INET6, NULL);
	l_netconfig_set_domain_names_override(netconfig, AF_INET6, NULL);

	l_dhcp_client_destroy(netconfig->dhcp_client);
	l_dhcp6_client_destroy(netconfig->dhcp6_client);
	l_netconfig_set_event_handler(netconfig, NULL, NULL, NULL);
	l_queue_destroy(netconfig->addresses.current, NULL);
	l_queue_destroy(netconfig->addresses.added, NULL);
	l_queue_destroy(netconfig->addresses.updated, NULL);
	l_queue_destroy(netconfig->addresses.removed, NULL);
	l_queue_destroy(netconfig->routes.current, NULL);
	l_queue_destroy(netconfig->routes.added, NULL);
	l_queue_destroy(netconfig->routes.updated, NULL);
	l_queue_destroy(netconfig->routes.removed, NULL);
	l_queue_destroy(netconfig->icmp_route_data, NULL);
	l_free(netconfig);
}

/*
 * The following l_netconfig_set_* functions configure the l_netconfig's
 * client settings.  The setters can be called independently, without
 * following a specific order.  Most of the setters will not validate the
 * values passed, l_netconfig_start() will fail if settings are incorrect
 * or inconsistent between themselves, e.g. if the static local IP and
 * gateway IP are not in the same subnet.  Alternatively
 * l_netconfig_check_config() can be called at any point to validate the
 * current configuration.  The configuration can only be changed while
 * the l_netconfig state machine is stopped, i.e. before
 * l_netconfig_start() and after l_netconfig_stop().
 *
 * l_netconfig_set_hostname, l_netconfig_set_static_addr,
 * l_netconfig_set_gateway_override, l_netconfig_set_dns_override and
 * l_netconfig_set_domain_names_override can be passed NULL to unset a
 * value that had been set before (revert to auto).  This is why the
 * family parameter is needed even when it could otherwise be derived
 * from the new value that is passed.
 */
LIB_EXPORT bool l_netconfig_set_family_enabled(struct l_netconfig *netconfig,
						uint8_t family, bool enabled)
{
	if (unlikely(!netconfig || netconfig->started))
		return false;

	switch (family) {
	case AF_INET:
		netconfig->v4_enabled = enabled;
		return true;
	case AF_INET6:
		netconfig->v6_enabled = enabled;
		return true;
	}

	return false;
}

LIB_EXPORT bool l_netconfig_set_hostname(struct l_netconfig *netconfig,
						const char *hostname)
{
	if (unlikely(!netconfig || netconfig->started))
		return false;

	return l_dhcp_client_set_hostname(netconfig->dhcp_client, hostname);
}

LIB_EXPORT bool l_netconfig_set_route_priority(struct l_netconfig *netconfig,
						uint32_t priority)
{
	if (unlikely(!netconfig || netconfig->started))
		return false;

	netconfig->route_priority = priority;
	return true;
}

LIB_EXPORT bool l_netconfig_set_static_addr(struct l_netconfig *netconfig,
					uint8_t family,
					const struct l_rtnl_address *addr)
{
	struct l_rtnl_address **ptr;

	if (unlikely(!netconfig || netconfig->started))
		return false;

	if (addr && l_rtnl_address_get_family(addr) != family)
		return false;

	switch (family) {
	case AF_INET:
		ptr = &netconfig->v4_static_addr;
		break;
	case AF_INET6:
		ptr = &netconfig->v6_static_addr;
		break;
	default:
		return false;
	}

	l_rtnl_address_free(*ptr);
	*ptr = NULL;

	if (!addr)
		return true;

	*ptr = l_rtnl_address_clone(addr);
	l_rtnl_address_set_lifetimes(*ptr, 0, 0);
	l_rtnl_address_set_noprefixroute(*ptr, true);
	return true;
}

LIB_EXPORT bool l_netconfig_set_gateway_override(struct l_netconfig *netconfig,
							uint8_t family,
							const char *gateway_str)
{
	char **ptr;

	if (unlikely(!netconfig || netconfig->started))
		return false;

	switch (family) {
	case AF_INET:
		ptr = &netconfig->v4_gateway_override;
		break;
	case AF_INET6:
		ptr = &netconfig->v6_gateway_override;
		break;
	default:
		return false;
	}

	l_free(*ptr);
	*ptr = NULL;

	if (!gateway_str)
		return true;

	*ptr = l_strdup(gateway_str);
	return true;
}

LIB_EXPORT bool l_netconfig_set_dns_override(struct l_netconfig *netconfig,
						uint8_t family, char **dns_list)
{
	char ***ptr;

	if (unlikely(!netconfig || netconfig->started))
		return false;

	switch (family) {
	case AF_INET:
		ptr = &netconfig->v4_dns_override;
		break;
	case AF_INET6:
		ptr = &netconfig->v6_dns_override;
		break;
	default:
		return false;
	}

	l_strv_free(*ptr);
	*ptr = NULL;

	if (!dns_list)
		return true;

	*ptr = l_strv_copy(dns_list);
	return true;
}

LIB_EXPORT bool l_netconfig_set_domain_names_override(
						struct l_netconfig *netconfig,
						uint8_t family, char **names)
{
	char ***ptr;

	if (unlikely(!netconfig || netconfig->started))
		return false;

	switch (family) {
	case AF_INET:
		ptr = &netconfig->v4_domain_names_override;
		break;
	case AF_INET6:
		ptr = &netconfig->v6_domain_names_override;
		break;
	default:
		return false;
	}

	l_strv_free(*ptr);
	*ptr = NULL;

	if (!names)
		return true;

	*ptr = l_strv_copy(names);
	return true;
}

LIB_EXPORT bool l_netconfig_set_acd_enabled(struct l_netconfig *netconfig,
						bool enabled)
{
	if (unlikely(!netconfig || netconfig->started))
		return false;

	netconfig->acd_enabled = enabled;
	return true;
}

LIB_EXPORT bool l_netconfig_set_optimistic_dad_enabled(
						struct l_netconfig *netconfig,
						bool enabled)
{
	if (unlikely(!netconfig || netconfig->started))
		return false;

	netconfig->optimistic_dad_enabled = enabled;
	return true;
}

static bool netconfig_check_family_config(struct l_netconfig *nc,
						uint8_t family)
{
	struct l_rtnl_address *static_addr = (family == AF_INET) ?
		nc->v4_static_addr : nc->v6_static_addr;
	char *gateway_override = (family == AF_INET) ?
		nc->v4_gateway_override : nc->v6_gateway_override;
	char **dns_override = (family == AF_INET) ?
		nc->v4_dns_override : nc->v6_dns_override;
	unsigned int dns_num = 0;

	if (static_addr && family == AF_INET) {
		uint8_t prefix_len =
			l_rtnl_address_get_prefix_length(static_addr);

		if (prefix_len > 30)
			return false;
	}

	if (gateway_override) {
		union netconfig_addr gateway;

		if (inet_pton(family, gateway_override, &gateway) != 1)
			return false;
	}

	if (dns_override && (dns_num = l_strv_length(dns_override))) {
		unsigned int i;
		_auto_(l_free) union netconfig_addr *dns_list =
			l_new(union netconfig_addr, dns_num);

		for (i = 0; i < dns_num; i++)
			if (inet_pton(family, dns_override[i],
					&dns_list[i]) != 1)
				return false;
	}

	return true;
}

static bool netconfig_check_config(struct l_netconfig *nc)
{
	/* TODO: error reporting through a debug log handler or otherwise */

	return netconfig_check_family_config(nc, AF_INET) &&
		netconfig_check_family_config(nc, AF_INET6);
}

LIB_EXPORT bool l_netconfig_check_config(struct l_netconfig *netconfig)
{
	if (unlikely(!netconfig || netconfig->started))
		return false;

	return netconfig_check_config(netconfig);
}

LIB_EXPORT bool l_netconfig_reset_config(struct l_netconfig *netconfig)
{
	if (unlikely(!netconfig || netconfig->started))
		return false;

	l_netconfig_set_hostname(netconfig, NULL);
	l_netconfig_set_route_priority(netconfig, 0);
	l_netconfig_set_family_enabled(netconfig, AF_INET, true);
	l_netconfig_set_static_addr(netconfig, AF_INET, NULL);
	l_netconfig_set_gateway_override(netconfig, AF_INET, NULL);
	l_netconfig_set_dns_override(netconfig, AF_INET, NULL);
	l_netconfig_set_domain_names_override(netconfig, AF_INET, NULL);
	l_netconfig_set_acd_enabled(netconfig, true);
	l_netconfig_set_family_enabled(netconfig, AF_INET6, false);
	l_netconfig_set_static_addr(netconfig, AF_INET6, NULL);
	l_netconfig_set_gateway_override(netconfig, AF_INET6, NULL);
	l_netconfig_set_dns_override(netconfig, AF_INET6, NULL);
	l_netconfig_set_domain_names_override(netconfig, AF_INET6, NULL);
	return true;
}

static void netconfig_add_v4_static_address_routes(struct l_netconfig *nc)
{
	char ip[INET_ADDRSTRLEN];
	uint32_t prefix_len;

	nc->v4_address = l_rtnl_address_clone(nc->v4_static_addr);
	l_queue_push_tail(nc->addresses.current, nc->v4_address);
	l_queue_push_tail(nc->addresses.added, nc->v4_address);

	l_rtnl_address_get_address(nc->v4_static_addr, ip);
	prefix_len = l_rtnl_address_get_prefix_length(nc->v4_static_addr);
	netconfig_add_v4_routes(nc, ip, prefix_len, NULL, RTPROT_STATIC);
}

/*
 * Just mirror the IPv4 behaviour with static IPv6 configuration.  It would
 * be more logical to let the user choose between static IPv6 address and
 * DHCPv6, and, completely independently, choose between static routes
 * (if a static prefix length and/or gateway address is set) and ICMPv6.
 * Yet a mechanism identical with IPv4 is easier to understand for a typical
 * user so providing a static address just disables all automatic
 * configuration.
 */
static void netconfig_add_v6_static_address_routes(struct l_netconfig *nc)
{
	char ip[INET6_ADDRSTRLEN];
	uint32_t prefix_len;

	nc->v6_address = l_rtnl_address_clone(nc->v6_static_addr);
	l_queue_push_tail(nc->addresses.current, nc->v6_address);
	l_queue_push_tail(nc->addresses.added, nc->v6_address);

	l_rtnl_address_get_address(nc->v6_static_addr, ip);
	prefix_len = l_rtnl_address_get_prefix_length(nc->v6_static_addr);
	netconfig_add_v6_static_routes(nc, ip, prefix_len);
}

static void netconfig_ipv4_acd_event(enum l_acd_event event, void *user_data)
{
	struct l_netconfig *nc = user_data;

	switch (event) {
	case L_ACD_EVENT_AVAILABLE:
		if (L_WARN_ON(nc->v4_configured))
			break;

		netconfig_add_v4_static_address_routes(nc);
		nc->v4_configured = true;
		netconfig_emit_event(nc, AF_INET, L_NETCONFIG_EVENT_CONFIGURE);
		break;
	case L_ACD_EVENT_CONFLICT:
		if (L_WARN_ON(nc->v4_configured))
			break;

		/*
		 * Conflict found, no IP was actually set or routes added so
		 * just emit the event.
		 */
		netconfig_emit_event(nc, AF_INET, L_NETCONFIG_EVENT_FAILED);
		break;
	case L_ACD_EVENT_LOST:
		if (L_WARN_ON(!nc->v4_configured))
			break;

		/*
		 * Set IP but lost it some time later.  Reset IPv4 in this
		 * case and emit the FAILED event since we have no way to
		 * recover from here.
		 */
		netconfig_remove_v4_address_routes(nc, false);
		nc->v4_configured = false;
		netconfig_emit_event(nc, AF_INET, L_NETCONFIG_EVENT_FAILED);
		break;
	}
}

static void netconfig_do_static_config(struct l_idle *idle, void *user_data)
{
	struct l_netconfig *nc = user_data;

	l_idle_remove(l_steal_ptr(nc->do_static_work));

	if (nc->v4_static_addr && !nc->v4_configured) {
		if (nc->acd_enabled) {
			char ip[INET_ADDRSTRLEN];

			l_rtnl_address_get_address(nc->v4_static_addr, ip);

			nc->acd = l_acd_new(nc->ifindex);
			l_acd_set_event_handler(nc->acd,
						netconfig_ipv4_acd_event, nc,
						NULL);

			if (l_acd_start(nc->acd, ip))
				goto configure_ipv6;

			l_acd_destroy(l_steal_ptr(nc->acd));
			/* Configure right now as a fallback */
		}

		netconfig_add_v4_static_address_routes(nc);
		nc->v4_configured = true;
		netconfig_emit_event(nc, AF_INET, L_NETCONFIG_EVENT_CONFIGURE);
	}

configure_ipv6:
	if (nc->v6_static_addr && !nc->v6_configured) {
		netconfig_add_v6_static_address_routes(nc);
		nc->v6_configured = true;
		netconfig_emit_event(nc, AF_INET6, L_NETCONFIG_EVENT_CONFIGURE);
	}
}

static void netconfig_rtnl_unregister(void *user_data)
{
	struct l_netlink *rtnl = user_data;

	if (!addr_wait_list || !l_queue_isempty(addr_wait_list))
		return;

	l_queue_destroy(l_steal_ptr(addr_wait_list), NULL);
	l_netlink_unregister(rtnl, rtnl_id);
	rtnl_id = 0;
}

static void netconfig_addr_wait_unregister(struct l_netconfig *nc,
						bool in_notify)
{
	struct l_netlink *rtnl = l_rtnl_get();

	if (nc->ifaddr6_dump_cmd_id) {
		unsigned int cmd_id = nc->ifaddr6_dump_cmd_id;

		nc->ifaddr6_dump_cmd_id = 0;
		l_netlink_cancel(rtnl, cmd_id);
	}

	if (!l_queue_remove(addr_wait_list, nc))
		return;

	if (!l_queue_isempty(addr_wait_list))
		return;

	/* We can't do l_netlink_unregister() inside a notification */
	if (in_notify)
		l_idle_oneshot(netconfig_rtnl_unregister, rtnl, NULL);
	else
		netconfig_rtnl_unregister(rtnl);
}

static void netconfig_ifaddr_ipv6_added(struct l_netconfig *nc,
					const struct ifaddrmsg *ifa,
					uint32_t len)
{
	struct in6_addr in6;
	_auto_(l_free) char *ip = NULL;
	bool new_lla;

	if ((ifa->ifa_flags & IFA_F_TENTATIVE) &&
			!(ifa->ifa_flags & IFA_F_OPTIMISTIC))
		return;

	if (!nc->started)
		return;

	l_rtnl_ifaddr6_extract(ifa, len, &ip);
	inet_pton(AF_INET6, ip, &in6);

	if (!IN6_IS_ADDR_LINKLOCAL(&in6))
		return;

	new_lla = !nc->have_lla;
	nc->have_lla = true;

	if (!(ifa->ifa_flags & IFA_F_TENTATIVE))
		netconfig_addr_wait_unregister(nc, true);
	else if (nc->ifaddr6_dump_cmd_id) {
		struct l_netlink *rtnl = l_rtnl_get();
		unsigned int cmd_id = nc->ifaddr6_dump_cmd_id;

		nc->ifaddr6_dump_cmd_id = 0;
		l_netlink_cancel(rtnl, cmd_id);
	}

	l_dhcp6_client_set_link_local_address(nc->dhcp6_client, ip);
	l_icmp6_client_set_link_local_address(nc->icmp6_client, ip,
					!!(ifa->ifa_flags & IFA_F_OPTIMISTIC));

	/*
	 * Only now that we have a link-local address see if we can start
	 * actual DHCPv6 setup.
	 */
	if (new_lla && netconfig_check_start_dhcp6(nc))
		return;

	netconfig_emit_event(nc, AF_INET6, L_NETCONFIG_EVENT_FAILED);
}

static void netconfig_ifaddr_ipv6_notify(uint16_t type, const void *data,
						uint32_t len, void *user_data)
{
	const struct ifaddrmsg *ifa = data;
	uint32_t bytes = len - NLMSG_ALIGN(sizeof(struct ifaddrmsg));
	const struct l_queue_entry *entry, *next;

	switch (type) {
	case RTM_NEWADDR:
		/* Iterate safely since elements may be removed */
		for (entry = l_queue_get_entries(addr_wait_list); entry;
				entry = next) {
			struct l_netconfig *nc = entry->data;

			next = entry->next;

			if (ifa->ifa_index == nc->ifindex)
				netconfig_ifaddr_ipv6_added(nc, ifa, bytes);
		}

		break;
	}
}

static void netconfig_ifaddr_ipv6_dump_cb(int error, uint16_t type,
						const void *data, uint32_t len,
						void *user_data)
{
	struct l_netconfig *nc = user_data;

	if (!nc->ifaddr6_dump_cmd_id || !nc->started)
		return;

	if (error) {
		netconfig_addr_wait_unregister(nc, false);
		netconfig_emit_event(nc, AF_INET6, L_NETCONFIG_EVENT_FAILED);
		return;
	}

	if (type != RTM_NEWADDR)
		return;

	netconfig_ifaddr_ipv6_notify(type, data, len, user_data);
}

static void netconfig_ifaddr_ipv6_dump_done_cb(void *user_data)
{
	struct l_netconfig *nc = user_data;

	/*
	 * Handle the case of no link-local address having been found during
	 * the dump.  If nc->ifaddr6_dump_cmd_id is 0, we have found one or
	 * the dump is being cancelled.  Otherwise try disabing the
	 * "disable_ipv6" setting for the interface since it may have been
	 * enabled.  Also write "addr_gen_mode" which triggers regerating
	 * the link-local addresss on the interface in the kernel if it
	 * was previously removed.
	 */
	if (!nc->ifaddr6_dump_cmd_id || !nc->started)
		return;

	nc->ifaddr6_dump_cmd_id = 0;

	/* "do not generate a link-local address" */
	netconfig_proc_write_ipv6_uint_setting(nc, "addr_gen_mode", 1);
	/* "generate address based on EUI64 (default)" */
	netconfig_proc_write_ipv6_uint_setting(nc, "addr_gen_mode", 0);

	/* "enable IPv6 operation" */
	nc->orig_disable_ipv6 =
		netconfig_proc_read_ipv6_uint_setting(nc, "disable_ipv6");
	if (nc->orig_disable_ipv6)
		netconfig_proc_write_ipv6_uint_setting(nc, "disable_ipv6", 0);
}

LIB_EXPORT bool l_netconfig_start(struct l_netconfig *netconfig)
{
	bool optimistic_dad;

	if (unlikely(!netconfig || netconfig->started))
		return false;

	if (!netconfig_check_config(netconfig))
		return false;

	if (!netconfig->v4_enabled)
		goto configure_ipv6;

	if (netconfig->v4_static_addr) {
		/*
		 * We're basically ready to configure the interface
		 * but do this in an idle callback.
		 */
		netconfig->do_static_work = l_idle_create(
						netconfig_do_static_config,
						netconfig, NULL);
		goto configure_ipv6;
	}

	if (!l_dhcp_client_start(netconfig->dhcp_client))
		return false;

configure_ipv6:
	if (!netconfig->v6_enabled)
		goto done;

	/*
	 * Enable optimistic DAD if the user has requested it *and* it is
	 * recommended by RFC 4429 Section 3.1 for the address generation
	 * method in use:
	 *   * mac-based Interface ID such as EUI-64
	 *   * random
	 *   * well-distributed hash function
	 *   * DHCPv6
	 * i.e. all autoconfiguration methods.  In any other case disable
	 * it.
	 */
	optimistic_dad = netconfig->optimistic_dad_enabled &&
		!netconfig->v6_static_addr;
	netconfig->orig_optimistic_dad =
		netconfig_proc_read_ipv6_uint_setting(netconfig,
							"optimistic_dad");

	if (netconfig->orig_optimistic_dad >= 0 &&
			!!netconfig->orig_optimistic_dad != optimistic_dad)
		netconfig_proc_write_ipv6_uint_setting(netconfig,
							"optimistic_dad",
							optimistic_dad ? 1 : 0);

	if (netconfig->v6_static_addr) {
		/*
		 * We're basically ready to configure the interface
		 * but do this in an idle callback.
		 */
		if (!netconfig->do_static_work)
			netconfig->do_static_work = l_idle_create(
						netconfig_do_static_config,
						netconfig, NULL);

		goto done;
	}

	netconfig->v6_auto_method = NETCONFIG_V6_METHOD_UNSET;

	/*
	 * We only care about being on addr_wait_list if we're waiting for
	 * the link-local address for DHCP6.  Add ourself to the list here
	 * before we start the dump, instead of after it ends, to eliminate
	 * the possibility of missing an RTM_NEWADDR between the end of
	 * the dump command and registering for the events.
	 *
	 * We stay on that list until we receive a non-tentative LL address.
	 * Note that we may set .have_lla earlier, specifically when we
	 * receive a tentative LL address that is also optimistic.  We will
	 * however stay on addr_wait_list because we want to notify
	 * l_icmp6_client again when the LL address completes DAD and becomes
	 * non-tentative.
	 */
	if (!addr_wait_list) {
		addr_wait_list = l_queue_new();

		rtnl_id = l_netlink_register(l_rtnl_get(), RTNLGRP_IPV6_IFADDR,
						netconfig_ifaddr_ipv6_notify,
						netconfig, NULL);
		if (!rtnl_id)
			goto unregister;
	}

	netconfig->ifaddr6_dump_cmd_id = l_rtnl_ifaddr6_dump(l_rtnl_get(),
					netconfig_ifaddr_ipv6_dump_cb,
					netconfig,
					netconfig_ifaddr_ipv6_dump_done_cb);
	if (!netconfig->ifaddr6_dump_cmd_id)
		goto unregister;

	l_queue_push_tail(addr_wait_list, netconfig);
	netconfig->have_lla = false;

	if (!l_net_get_mac_address(netconfig->ifindex, netconfig->mac))
		goto unregister;

	l_dhcp6_client_set_address(netconfig->dhcp6_client, ARPHRD_ETHER,
					netconfig->mac, ETH_ALEN);
	l_icmp6_client_set_address(netconfig->icmp6_client, netconfig->mac);

	/*
	 * RFC4862 Section 4: "To speed the autoconfiguration process, a host
	 * may generate its link-local address (and verify its uniqueness) in
	 * parallel with waiting for a Router Advertisement.  Because a router
	 * may delay responding to a Router Solicitation for a few seconds,
	 * the total time needed to complete autoconfiguration can be
	 * significantly longer if the two steps are done serially."
	 *
	 * We don't know whether we have the LL address yet.  The interface
	 * may have been just brought up and DAD may still running or the LL
	 * address may have been deleted and won't be added until
	 * netconfig_ifaddr_ipv6_dump_done_cb() writes the /proc settings.
	 * In any case the Router Solicitation doesn't depend on having the
	 * LL address so send it now.  We won't start DHCPv6 however until we
	 * have both the LL address and the Router Advertisement.
	 */
	if (!l_icmp6_client_start(netconfig->icmp6_client))
		goto unregister;

	netconfig->ra_timeout = l_timeout_create(10, netconfig_ra_timeout_cb,
							netconfig, NULL);

done:
	netconfig->started = true;
	return true;

unregister:
	netconfig_addr_wait_unregister(netconfig, false);

	if (netconfig->v4_enabled) {
		if (netconfig->v4_static_addr)
			l_idle_remove(l_steal_ptr(netconfig->do_static_work));
		else
			l_dhcp_client_stop(netconfig->dhcp_client);
	}

	return false;
}

LIB_EXPORT void l_netconfig_stop(struct l_netconfig *netconfig)
{
	bool optimistic_dad;

	if (unlikely(!netconfig || !netconfig->started))
		return;

	netconfig->started = false;

	if (netconfig->do_static_work)
		l_idle_remove(l_steal_ptr(netconfig->do_static_work));

	if (netconfig->signal_expired_work)
		l_idle_remove(l_steal_ptr(netconfig->signal_expired_work));

	if (netconfig->ra_timeout)
		l_timeout_remove(l_steal_ptr(netconfig->ra_timeout));

	netconfig_addr_wait_unregister(netconfig, false);

	netconfig_update_cleanup(netconfig);
	l_queue_clear(netconfig->addresses.current,
			(l_queue_destroy_func_t) l_rtnl_address_free);
	l_queue_clear(netconfig->routes.current,
			(l_queue_destroy_func_t) l_rtnl_route_free);
	l_queue_clear(netconfig->icmp_route_data, l_free);
	l_queue_clear(netconfig->slaac_dnses, l_free);
	l_queue_clear(netconfig->slaac_domains, l_free);
	netconfig->v4_address = NULL;
	netconfig->v4_subnet_route = NULL;
	netconfig->v4_default_route = NULL;
	netconfig->v6_address = NULL;
	netconfig->v4_configured = false;
	netconfig->v6_configured = false;

	l_dhcp_client_stop(netconfig->dhcp_client);
	l_dhcp6_client_stop(netconfig->dhcp6_client);
	l_icmp6_client_stop(netconfig->icmp6_client);

	l_acd_destroy(l_steal_ptr(netconfig->acd));

	if (netconfig->orig_disable_ipv6) {
		netconfig_proc_write_ipv6_uint_setting(netconfig,
						"disable_ipv6",
						netconfig->orig_disable_ipv6);
		netconfig->orig_disable_ipv6 = 0;
	}

	optimistic_dad = netconfig->optimistic_dad_enabled &&
		!netconfig->v6_static_addr;
	if (netconfig->orig_optimistic_dad >= 0 &&
			!!netconfig->orig_optimistic_dad != optimistic_dad)
		netconfig_proc_write_ipv6_uint_setting(netconfig,
						"optimistic_dad",
						netconfig->orig_optimistic_dad);
}

/*
 * Undo any configuration already applied to the interface by previous
 * calls to the event handler, by synchronously emitting
 * L_NETCONFIG_EVENT_UNCONFIGURE events.  This can be called before
 * l_netconfig_stop() which won't emit any events.  It mainly makes
 * sense if the interface isn't being removed or brought DOWN, which
 * would otherwise implicitly remove routes and addresses.
 */
LIB_EXPORT void l_netconfig_unconfigure(struct l_netconfig *netconfig)
{
	const struct l_queue_entry *entry;

	if (netconfig->v4_configured) {
		netconfig_remove_v4_address_routes(netconfig, false);
		netconfig->v4_configured = false;

		netconfig_emit_event(netconfig, AF_INET,
					L_NETCONFIG_EVENT_UNCONFIGURE);
	}

	if (netconfig->v6_configured) {
		netconfig_remove_dhcp6_address(netconfig, false);
		netconfig->v6_configured = false;
	}

	/* Bulk remove any other routes or addresses */
	for (entry = l_queue_get_entries(netconfig->addresses.current); entry;
			entry = entry->next)
		l_queue_push_tail(netconfig->addresses.removed, entry->data);

	l_queue_clear(netconfig->addresses.added, NULL);
	l_queue_clear(netconfig->addresses.updated, NULL);
	l_queue_clear(netconfig->addresses.current, NULL);

	for (entry = l_queue_get_entries(netconfig->routes.current); entry;
			entry = entry->next)
		l_queue_push_tail(netconfig->routes.removed, entry->data);

	l_queue_clear(netconfig->routes.added, NULL);
	l_queue_clear(netconfig->routes.updated, NULL);
	l_queue_clear(netconfig->routes.current, NULL);
	l_queue_clear(netconfig->icmp_route_data, l_free);

	if (!l_queue_isempty(netconfig->addresses.removed) ||
			!l_queue_isempty(netconfig->routes.removed))
		netconfig_emit_event(netconfig, AF_INET6,
					L_NETCONFIG_EVENT_UNCONFIGURE);
}

LIB_EXPORT struct l_dhcp_client *l_netconfig_get_dhcp_client(
						struct l_netconfig *netconfig)
{
	if (unlikely(!netconfig))
		return NULL;

	return netconfig->dhcp_client;
}

LIB_EXPORT struct l_dhcp6_client *l_netconfig_get_dhcp6_client(
						struct l_netconfig *netconfig)
{
	if (unlikely(!netconfig))
		return NULL;

	return netconfig->dhcp6_client;
}

LIB_EXPORT struct l_icmp6_client *l_netconfig_get_icmp6_client(
						struct l_netconfig *netconfig)
{
	if (unlikely(!netconfig))
		return NULL;

	return netconfig->icmp6_client;
}

LIB_EXPORT void l_netconfig_set_event_handler(struct l_netconfig *netconfig,
					l_netconfig_event_cb_t handler,
					void *user_data,
					l_netconfig_destroy_cb_t destroy)
{
	if (unlikely(!netconfig))
		return;

	if (netconfig->handler.destroy)
		netconfig->handler.destroy(netconfig->handler.user_data);

	netconfig->handler.callback = handler;
	netconfig->handler.user_data = user_data;
	netconfig->handler.destroy = destroy;
}

LIB_EXPORT void l_netconfig_apply_rtnl(struct l_netconfig *netconfig)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(netconfig->addresses.removed); entry;
			entry = entry->next)
		l_rtnl_ifaddr_delete(l_rtnl_get(), netconfig->ifindex,
					entry->data, NULL, NULL, NULL);

	for (entry = l_queue_get_entries(netconfig->addresses.added); entry;
			entry = entry->next)
		l_rtnl_ifaddr_add(l_rtnl_get(), netconfig->ifindex,
					entry->data, NULL, NULL, NULL);

	/* We can use l_rtnl_ifaddr_add here since that uses NLM_F_REPLACE */
	for (entry = l_queue_get_entries(netconfig->addresses.updated); entry;
			entry = entry->next)
		l_rtnl_ifaddr_add(l_rtnl_get(), netconfig->ifindex,
					entry->data, NULL, NULL, NULL);

	for (entry = l_queue_get_entries(netconfig->routes.removed); entry;
			entry = entry->next)
		l_rtnl_route_delete(l_rtnl_get(), netconfig->ifindex,
					entry->data, NULL, NULL, NULL);

	for (entry = l_queue_get_entries(netconfig->routes.added); entry;
			entry = entry->next)
		l_rtnl_route_add(l_rtnl_get(), netconfig->ifindex,
					entry->data, NULL, NULL, NULL);

	/* We can use l_rtnl_route_add here since that uses NLM_F_REPLACE */
	for (entry = l_queue_get_entries(netconfig->routes.updated); entry;
			entry = entry->next)
		l_rtnl_route_add(l_rtnl_get(), netconfig->ifindex,
					entry->data, NULL, NULL, NULL);
}

LIB_EXPORT const struct l_queue_entry *l_netconfig_get_addresses(
					struct l_netconfig *netconfig,
					const struct l_queue_entry **out_added,
					const struct l_queue_entry **out_updated,
					const struct l_queue_entry **out_removed,
					const struct l_queue_entry **out_expired)
{
	if (out_added)
		*out_added = l_queue_get_entries(netconfig->addresses.added);

	if (out_updated)
		*out_updated = l_queue_get_entries(netconfig->addresses.updated);

	if (out_removed)
		*out_removed = l_queue_get_entries(netconfig->addresses.removed);

	if (out_expired)
		*out_expired = l_queue_get_entries(netconfig->addresses.expired);

	return l_queue_get_entries(netconfig->addresses.current);
}

LIB_EXPORT const struct l_queue_entry *l_netconfig_get_routes(
					struct l_netconfig *netconfig,
					const struct l_queue_entry **out_added,
					const struct l_queue_entry **out_updated,
					const struct l_queue_entry **out_removed,
					const struct l_queue_entry **out_expired)
{
	netconfig_expire_routes(netconfig);

	if (out_added)
		*out_added = l_queue_get_entries(netconfig->routes.added);

	if (out_updated)
		*out_updated = l_queue_get_entries(netconfig->routes.updated);

	if (out_removed)
		*out_removed = l_queue_get_entries(netconfig->routes.removed);

	if (out_expired)
		*out_expired = l_queue_get_entries(netconfig->routes.expired);

	return l_queue_get_entries(netconfig->routes.current);
}

static void netconfig_strv_cat(char ***dest, char **src, bool free)
{
	unsigned int dest_len;
	unsigned int src_len;

	if (!src)
		return;

	if (!free)
		src = l_strv_copy(src);

	if (!*dest) {
		*dest = src;
		return;
	}

	dest_len = l_strv_length(*dest);
	src_len = l_strv_length(src);
	*dest = l_realloc(*dest, sizeof(char *) * (dest_len + src_len + 1));
	memcpy(*dest + dest_len, src, sizeof(char *) * (src_len + 1));
	l_free(src);
}

/* Returns a new strv array to be freed by the caller */
LIB_EXPORT char **l_netconfig_get_dns_list(struct l_netconfig *netconfig)
{
	char **ret = NULL;
	const struct l_dhcp_lease *v4_lease;
	const struct l_dhcp6_lease *v6_lease;

	if (!netconfig->v4_configured)
		goto append_v6;

	if (netconfig->v4_dns_override)
		netconfig_strv_cat(&ret, netconfig->v4_dns_override, false);
	else if ((v4_lease =
			l_dhcp_client_get_lease(netconfig->dhcp_client)))
		netconfig_strv_cat(&ret, l_dhcp_lease_get_dns(v4_lease), true);

append_v6:
	if (!netconfig->v6_configured)
		goto done;

	if (netconfig->v6_dns_override)
		netconfig_strv_cat(&ret, netconfig->v6_dns_override, false);
	else if (netconfig->v6_auto_method == NETCONFIG_V6_METHOD_DHCP &&
			(v6_lease = l_dhcp6_client_get_lease(
						netconfig->dhcp6_client)))
		netconfig_strv_cat(&ret, l_dhcp6_lease_get_dns(v6_lease), true);
	else if (netconfig->v6_auto_method == NETCONFIG_V6_METHOD_SLAAC &&
			!l_queue_isempty(netconfig->slaac_dnses)) {
		unsigned int dest_len = l_strv_length(ret);
		unsigned int src_len = l_queue_length(netconfig->slaac_dnses);
		char **i;
		const struct l_queue_entry *entry;

		ret = l_realloc(ret, sizeof(char *) * (dest_len + src_len + 1));
		i = ret + dest_len;

		for (entry = l_queue_get_entries(netconfig->slaac_dnses);
				entry; entry = entry->next) {
			char addr_str[INET6_ADDRSTRLEN];

			if (inet_ntop(AF_INET6, entry->data, addr_str,
					sizeof(addr_str)))
				*i++ = l_strdup(addr_str);
		}

		*i = NULL;
	}

done:
	return ret;
}

/* Returns a new strv array to be freed by the caller */
LIB_EXPORT char **l_netconfig_get_domain_names(struct l_netconfig *netconfig)
{
	char **ret = NULL;
	const struct l_dhcp_lease *v4_lease;
	const struct l_dhcp6_lease *v6_lease;
	char *dn;

	if (!netconfig->v4_configured)
		goto append_v6;

	if (netconfig->v4_domain_names_override)
		netconfig_strv_cat(&ret, netconfig->v4_domain_names_override,
					false);
	else if ((v4_lease =
			l_dhcp_client_get_lease(netconfig->dhcp_client)) &&
			(dn = l_dhcp_lease_get_domain_name(v4_lease))) {
		ret = l_new(char *, 2);
		ret[0] = dn;
	}

append_v6:
	if (!netconfig->v6_configured)
		goto done;

	if (netconfig->v6_domain_names_override)
		netconfig_strv_cat(&ret, netconfig->v6_domain_names_override,
					false);
	else if (netconfig->v6_auto_method == NETCONFIG_V6_METHOD_DHCP &&
			(v6_lease = l_dhcp6_client_get_lease(
						netconfig->dhcp6_client)))
		netconfig_strv_cat(&ret, l_dhcp6_lease_get_domains(v6_lease),
					true);
	else if (netconfig->v6_auto_method == NETCONFIG_V6_METHOD_SLAAC &&
			!l_queue_isempty(netconfig->slaac_domains)) {
		unsigned int dest_len = l_strv_length(ret);
		unsigned int src_len = l_queue_length(netconfig->slaac_domains);
		char **i;
		const struct l_queue_entry *entry;

		ret = l_realloc(ret, sizeof(char *) * (dest_len + src_len + 1));
		i = ret + dest_len;

		for (entry = l_queue_get_entries(netconfig->slaac_domains);
				entry; entry = entry->next)
			*i++ = l_strdup(entry->data);

		*i = NULL;
	}

done:
	return ret;
}
