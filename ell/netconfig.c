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

#include <linux/types.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>

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
#include "netconfig.h"

struct l_netconfig {
	uint32_t ifindex;
	uint32_t route_priority;

	bool v4_enabled;
	struct l_rtnl_address *v4_static_addr;
	char *v4_gateway_override;
	char **v4_dns_override;
	char **v4_domain_names_override;

	bool v6_enabled;
	struct l_rtnl_address *v6_static_addr;
	char *v6_gateway_override;
	char **v6_dns_override;
	char **v6_domain_names_override;

	bool started;
	struct l_idle *do_static_work;
	bool v4_configured;
	struct l_dhcp_client *dhcp_client;
	bool v6_configured;
	struct l_icmp6_client *icmp6_client;
	struct l_dhcp6_client *dhcp6_client;

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
		 */
		struct l_queue *added;
		struct l_queue *updated;
		struct l_queue *removed;
	} addresses, routes;

	struct {
		l_netconfig_event_cb_t callback;
		void *user_data;
		l_netconfig_destroy_cb_t destroy;
	} handler;
};

union netconfig_addr {
	struct in_addr v4;
	struct in6_addr v6;
};

static void netconfig_update_cleanup(struct l_netconfig *nc)
{
	l_queue_clear(nc->addresses.added, NULL);
	l_queue_clear(nc->addresses.updated, NULL);
	l_queue_clear(nc->addresses.removed,
			(l_queue_destroy_func_t) l_rtnl_address_free);
	l_queue_clear(nc->routes.added, NULL);
	l_queue_clear(nc->routes.updated, NULL);
	l_queue_clear(nc->routes.removed,
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

static void netconfig_add_v4_routes(struct l_netconfig *nc, const char *ip,
					uint8_t prefix_len, const char *gateway,
					uint8_t rtm_protocol)
{
	struct in_addr in_addr;
	char network[INET_ADDRSTRLEN];

	/* Subnet route */

	if (L_WARN_ON(inet_pton(AF_INET, ip, &in_addr) != 1))
		return;

	in_addr.s_addr &= htonl(0xfffffffflu << (32 - prefix_len));
	nc->v4_subnet_route = netconfig_route_new(nc, AF_INET, network,
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
	L_WARN_ON(!l_rtnl_route_set_prefsrc(v6_default_route, ip));
	l_queue_push_tail(nc->routes.current, v6_default_route);
	l_queue_push_tail(nc->routes.added, v6_default_route);
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

	if (updated)
		l_queue_push_tail(nc->addresses.updated, nc->v4_address);

	l_rtnl_route_set_lifetime(nc->v4_subnet_route, lifetime);
	l_rtnl_route_set_expiry(nc->v4_subnet_route, expiry);

	if (updated)
		l_queue_push_tail(nc->routes.updated, nc->v4_subnet_route);

	if (!nc->v4_default_route)
		return;

	l_rtnl_route_set_lifetime(nc->v4_default_route, lifetime);
	l_rtnl_route_set_expiry(nc->v4_default_route, expiry);

	if (updated)
		l_queue_push_tail(nc->routes.updated, nc->v4_default_route);
}

static void netconfig_remove_dhcp_address_routes(struct l_netconfig *nc)
{
	l_queue_remove(nc->addresses.current, nc->v4_address);
	l_queue_push_tail(nc->addresses.removed, nc->v4_address);
	nc->v4_address = NULL;

	l_queue_remove(nc->routes.current, nc->v4_subnet_route);
	l_queue_push_tail(nc->routes.removed, nc->v4_subnet_route);
	nc->v4_subnet_route = NULL;

	if (nc->v4_default_route) {
		l_queue_remove(nc->routes.current, nc->v4_default_route);
		l_queue_push_tail(nc->routes.removed, nc->v4_default_route);
		nc->v4_default_route = NULL;
	}
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

		netconfig_remove_dhcp_address_routes(nc);
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

		netconfig_remove_dhcp_address_routes(nc);
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

	if (updated)
		l_queue_push_tail(nc->addresses.updated, nc->v6_address);
}

static void netconfig_remove_dhcp6_address(struct l_netconfig *nc)
{
	l_queue_remove(nc->addresses.current, nc->v6_address);
	l_queue_push_tail(nc->addresses.removed, nc->v6_address);
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

		netconfig_remove_dhcp6_address(nc);
		netconfig_add_dhcp6_address(nc);
		netconfig_set_dhcp6_address_lifetimes(nc, false);
		netconfig_emit_event(nc, AF_INET6, L_NETCONFIG_EVENT_UPDATE);
		break;
	case L_DHCP6_CLIENT_EVENT_LEASE_EXPIRED:
		if (L_WARN_ON(!nc->v6_configured))
			break;

		netconfig_remove_dhcp6_address(nc);
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

static struct l_rtnl_route *netconfig_find_icmp6_route(
						struct l_netconfig *nc,
						const uint8_t *gateway,
						const struct route_info *dst)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(nc->routes.current); entry;
			entry = entry->next) {
		struct l_rtnl_route *route = entry->data;
		const uint8_t *route_gateway;
		const uint8_t *route_dst;
		uint8_t route_prefix_len = 0;

		if (l_rtnl_route_get_family(route) != AF_INET6 ||
				l_rtnl_route_get_protocol(route) != RTPROT_RA)
			continue;

		route_gateway = l_rtnl_route_get_gateway_in_addr(route);
		if ((gateway || route_gateway) &&
				(!gateway || !route_gateway ||
				 memcmp(gateway, route_gateway, 16)))
			continue;

		route_dst = l_rtnl_route_get_dst_in_addr(route,
							&route_prefix_len);
		if ((dst || route_prefix_len) &&
				(!dst || !route_prefix_len ||
				 dst->prefix_len != route_prefix_len ||
				 memcmp(dst->address, route_dst, 16)))
			continue;

		return route;
	}

	return NULL;
}

static struct l_rtnl_route *netconfig_add_icmp6_route(struct l_netconfig *nc,
						const uint8_t *gateway,
						const struct route_info *dst,
						uint8_t preference)
{
	struct l_rtnl_route *rt;

	rt = netconfig_route_new(nc, AF_INET6, dst->address, dst->prefix_len,
					gateway, RTPROT_RA);
	if (L_WARN_ON(!rt))
		return NULL;

	l_rtnl_route_set_preference(rt, preference);
	l_queue_push_tail(nc->routes.current, rt);
	l_queue_push_tail(nc->routes.added, rt);
	return rt;
}

static void netconfig_set_icmp6_route_data(struct l_netconfig *nc,
						struct l_rtnl_route *rt,
						uint64_t start_time,
						uint32_t preferred_lifetime,
						uint32_t valid_lifetime,
						uint32_t mtu, bool updated)
{
	uint64_t expiry = start_time + valid_lifetime * L_USEC_PER_SEC;
	uint64_t old_expiry = l_rtnl_route_get_expiry(rt);
	bool differs = false;

	if (mtu != l_rtnl_route_get_mtu(rt)) {
		l_rtnl_route_set_mtu(rt, mtu);
		differs = true;
	}

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
		l_rtnl_route_set_lifetime(rt, valid_lifetime);
		l_rtnl_route_set_expiry(rt, expiry);
		differs = true;
	}

	if (updated && differs && !netconfig_route_exists(nc->routes.added, rt))
		l_queue_push_tail(nc->routes.updated, rt);
}

static void netconfig_remove_icmp6_route(struct l_netconfig *nc,
						struct l_rtnl_route *route)
{
	l_queue_remove(nc->routes.current, route);
	l_queue_push_tail(nc->routes.removed, route);
}

static void netconfig_icmp6_event_handler(struct l_icmp6_client *client,
						enum l_icmp6_client_event event,
						void *event_data,
						void *user_data)
{
	struct l_netconfig *nc = user_data;
	const struct l_icmp6_router *r;
	struct l_rtnl_route *default_route;
	unsigned int i;

	if (event != L_ICMP6_CLIENT_EVENT_ROUTER_FOUND)
		return;

	r = event_data;

	/*
	 * Note: If this is the first RA received, the l_dhcp6_client
	 * will have received the event before us and will be acting
	 * on it by now.
	 */

	if (nc->v6_gateway_override)
		return;

	/* Process the default gateway information */
	default_route = netconfig_find_icmp6_route(nc, r->address, NULL);

	if (!default_route && r->lifetime) {
		default_route = netconfig_add_icmp6_route(nc, r->address, NULL,
								r->pref);
		if (unlikely(!default_route))
			return;

		/*
		 * r->lifetime is 16-bit only so there's no risk it gets
		 * confused for the special 0xffffffff value in
		 * netconfig_set_icmp6_route_data.
		 */
		netconfig_set_icmp6_route_data(nc, default_route, r->start_time,
						r->lifetime, r->lifetime,
						r->mtu, false);
	} else if (default_route && r->lifetime)
		netconfig_set_icmp6_route_data(nc, default_route, r->start_time,
						r->lifetime, r->lifetime,
						r->mtu, true);
	else if (default_route && !r->lifetime)
		netconfig_remove_icmp6_route(nc, default_route);

	/*
	 * Process the onlink and offlink routes, from the Router
	 * Advertisement's Prefix Information options and Route
	 * Information options respectively.
	 */
	for (i = 0; i < r->n_routes; i++) {
		const struct route_info *info = &r->routes[i];
		const uint8_t *gateway = info->onlink ? NULL : r->address;
		struct l_rtnl_route *route =
			netconfig_find_icmp6_route(nc, gateway, info);

		if (!route && info->valid_lifetime) {
			route = netconfig_add_icmp6_route(nc, gateway, info,
							info->preference);
			if (unlikely(!route))
				continue;

			netconfig_set_icmp6_route_data(nc, route, r->start_time,
						info->preferred_lifetime,
						info->valid_lifetime,
						gateway ? r->mtu : 0, false);
		} else if (route && info->valid_lifetime)
			netconfig_set_icmp6_route_data(nc, route, r->start_time,
						info->preferred_lifetime,
						info->valid_lifetime,
						gateway ? r->mtu : 0, true);
		else if (route && !info->valid_lifetime)
			netconfig_remove_icmp6_route(nc, route);
	}

	/*
	 * Note: we may be emitting this before L_NETCONFIG_EVENT_CONFIGURE.
	 * We should probably instead save the affected routes in separate
	 * lists and add them to the _CONFIGURE event, suppressing any _UPDATE
	 * events while nc->v6_configured is false.
	 */
	if (!l_queue_isempty(nc->routes.added) ||
			!l_queue_isempty(nc->routes.updated) ||
			!l_queue_isempty(nc->routes.removed))
		netconfig_emit_event(nc, AF_INET6, L_NETCONFIG_EVENT_UPDATE);
}

LIB_EXPORT struct l_netconfig *l_netconfig_new(uint32_t ifindex)
{
	struct l_netconfig *nc;

	nc = l_new(struct l_netconfig, 1);
	nc->ifindex = ifindex;
	nc->v4_enabled = true;

	nc->addresses.current = l_queue_new();
	nc->addresses.added = l_queue_new();
	nc->addresses.updated = l_queue_new();
	nc->addresses.removed = l_queue_new();
	nc->routes.current = l_queue_new();
	nc->routes.added = l_queue_new();
	nc->routes.updated = l_queue_new();
	nc->routes.removed = l_queue_new();

	nc->dhcp_client = l_dhcp_client_new(ifindex);
	l_dhcp_client_set_event_handler(nc->dhcp_client,
					netconfig_dhcp_event_handler,
					nc, NULL);

	nc->dhcp6_client = l_dhcp6_client_new(ifindex);
	l_dhcp6_client_set_event_handler(nc->dhcp6_client,
					netconfig_dhcp6_event_handler,
					nc, NULL);

	nc->icmp6_client = l_dhcp6_client_get_icmp6(nc->dhcp6_client);
	l_icmp6_client_add_event_handler(nc->icmp6_client,
					netconfig_icmp6_event_handler,
					nc, NULL);

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

static void netconfig_do_static_config(struct l_idle *idle, void *user_data)
{
	struct l_netconfig *nc = user_data;

	l_idle_remove(l_steal_ptr(nc->do_static_work));

	if (nc->v4_static_addr && !nc->v4_configured) {
		netconfig_add_v4_static_address_routes(nc);
		nc->v4_configured = true;
		netconfig_emit_event(nc, AF_INET, L_NETCONFIG_EVENT_CONFIGURE);
	}

	if (nc->v6_static_addr && !nc->v6_configured) {
		netconfig_add_v6_static_address_routes(nc);
		nc->v6_configured = true;
		netconfig_emit_event(nc, AF_INET6, L_NETCONFIG_EVENT_CONFIGURE);
	}
}

LIB_EXPORT bool l_netconfig_start(struct l_netconfig *netconfig)
{
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

	if (!l_dhcp6_client_start(netconfig->dhcp6_client))
		goto stop_ipv4;

done:
	netconfig->started = true;
	return true;

stop_ipv4:
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
	if (unlikely(!netconfig || !netconfig->started))
		return;

	netconfig->started = false;

	if (netconfig->do_static_work)
		l_idle_remove(l_steal_ptr(netconfig->do_static_work));

	netconfig_update_cleanup(netconfig);
	l_queue_clear(netconfig->routes.current,
			(l_queue_destroy_func_t) l_rtnl_route_free);
	l_queue_clear(netconfig->addresses.current,
			(l_queue_destroy_func_t) l_rtnl_address_free);
	netconfig->v4_address = NULL;
	netconfig->v4_subnet_route = NULL;
	netconfig->v4_default_route = NULL;
	netconfig->v6_address = NULL;

	l_dhcp_client_stop(netconfig->dhcp_client);
	l_dhcp6_client_stop(netconfig->dhcp6_client);
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

LIB_EXPORT void l_netconfig_apply_rtnl(struct l_netconfig *netconfig,
					struct l_netlink *rtnl)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(netconfig->addresses.removed); entry;
			entry = entry->next)
		l_rtnl_ifaddr_delete(rtnl, netconfig->ifindex, entry->data,
					NULL, NULL, NULL);

	for (entry = l_queue_get_entries(netconfig->addresses.added); entry;
			entry = entry->next)
		l_rtnl_ifaddr_add(rtnl, netconfig->ifindex, entry->data,
					NULL, NULL, NULL);

	/* We can use l_rtnl_ifaddr_add here since that uses NLM_F_REPLACE */
	for (entry = l_queue_get_entries(netconfig->addresses.updated); entry;
			entry = entry->next)
		l_rtnl_ifaddr_add(rtnl, netconfig->ifindex, entry->data,
					NULL, NULL, NULL);

	for (entry = l_queue_get_entries(netconfig->routes.removed); entry;
			entry = entry->next)
		l_rtnl_route_delete(rtnl, netconfig->ifindex, entry->data,
					NULL, NULL, NULL);

	for (entry = l_queue_get_entries(netconfig->routes.added); entry;
			entry = entry->next)
		l_rtnl_route_add(rtnl, netconfig->ifindex, entry->data,
					NULL, NULL, NULL);

	/* We can use l_rtnl_route_add here since that uses NLM_F_REPLACE */
	for (entry = l_queue_get_entries(netconfig->routes.updated); entry;
			entry = entry->next)
		l_rtnl_route_add(rtnl, netconfig->ifindex, entry->data,
					NULL, NULL, NULL);
}

LIB_EXPORT struct l_queue *l_netconfig_get_addresses(
						struct l_netconfig *netconfig,
						struct l_queue **out_added,
						struct l_queue **out_updated,
						struct l_queue **out_removed)
{
	if (out_added)
		*out_added = netconfig->addresses.added;

	if (out_updated)
		*out_updated = netconfig->addresses.updated;

	if (out_removed)
		*out_removed = netconfig->addresses.removed;

	return netconfig->addresses.current;
}

LIB_EXPORT struct l_queue *l_netconfig_get_routes(struct l_netconfig *netconfig,
						struct l_queue **out_added,
						struct l_queue **out_updated,
						struct l_queue **out_removed)
{
	if (out_added)
		*out_added = netconfig->routes.added;

	if (out_updated)
		*out_updated = netconfig->routes.updated;

	if (out_removed)
		*out_removed = netconfig->routes.removed;

	return netconfig->routes.current;
}
