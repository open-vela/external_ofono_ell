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

#include "private.h"
#include "useful.h"
#include "log.h"
#include "dhcp.h"
#include "dhcp-private.h"
#include "netlink.h"
#include "rtnl.h"
#include "queue.h"
#include "time.h"
#include "netconfig.h"

struct l_netconfig {
	uint32_t ifindex;
	bool v4_enabled;
	bool started;
	uint32_t route_priority;

	bool v4_configured;
	struct l_dhcp_client *dhcp_client;
	/* These objects, if not NULL, are owned by @addresses and @routes */
	struct l_rtnl_address *v4_address;
	struct l_rtnl_route *v4_subnet_route;
	struct l_rtnl_route *v4_default_route;

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
	if (L_WARN_ON(!inet_ntop(AF_INET, &in_addr, network, INET_ADDRSTRLEN)))
		return;

	nc->v4_subnet_route = l_rtnl_route_new_prefix(network, prefix_len);
	l_rtnl_route_set_protocol(nc->v4_subnet_route, rtm_protocol);
	l_rtnl_route_set_priority(nc->v4_subnet_route, nc->route_priority);
	l_queue_push_tail(nc->routes.current, nc->v4_subnet_route);
	l_queue_push_tail(nc->routes.added, nc->v4_subnet_route);

	/* Gateway route */

	if (!gateway)
		return;

	nc->v4_default_route = l_rtnl_route_new_gateway(gateway);
	l_rtnl_route_set_protocol(nc->v4_default_route, rtm_protocol);
	L_WARN_ON(!l_rtnl_route_set_prefsrc(nc->v4_default_route, ip));
	l_queue_push_tail(nc->routes.current, nc->v4_default_route);
	l_queue_push_tail(nc->routes.added, nc->v4_default_route);
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
		L_WARN_ON(!nc->v4_configured);
		netconfig_remove_dhcp_address_routes(nc);
		netconfig_add_dhcp_address_routes(nc);
		netconfig_set_dhcp_lifetimes(nc, false);
		netconfig_emit_event(nc, AF_INET, L_NETCONFIG_EVENT_UPDATE);
		break;
	case L_DHCP_CLIENT_EVENT_LEASE_OBTAINED:
	{
		L_WARN_ON(nc->v4_configured);
		netconfig_add_dhcp_address_routes(nc);
		netconfig_set_dhcp_lifetimes(nc, false);
		nc->v4_configured = true;
		netconfig_emit_event(nc, AF_INET, L_NETCONFIG_EVENT_CONFIGURE);
		break;
	}
	case L_DHCP_CLIENT_EVENT_LEASE_RENEWED:
		L_WARN_ON(!nc->v4_configured);
		netconfig_set_dhcp_lifetimes(nc, true);
		netconfig_emit_event(nc, AF_INET, L_NETCONFIG_EVENT_UPDATE);
		break;
	case L_DHCP_CLIENT_EVENT_LEASE_EXPIRED:
		L_WARN_ON(!nc->v4_configured);
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

	return nc;
}

LIB_EXPORT void l_netconfig_destroy(struct l_netconfig *netconfig)
{
	if (unlikely(!netconfig))
		return;

	l_netconfig_stop(netconfig);

	l_dhcp_client_destroy(netconfig->dhcp_client);
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

LIB_EXPORT bool l_netconfig_start(struct l_netconfig *netconfig)
{
	if (unlikely(!netconfig || netconfig->started))
		return false;

	if (netconfig->v4_enabled &&
			!l_dhcp_client_start(netconfig->dhcp_client))
		return false;

	netconfig->started = true;

	return true;
}

LIB_EXPORT void l_netconfig_stop(struct l_netconfig *netconfig)
{
	if (unlikely(!netconfig || !netconfig->started))
		return;

	netconfig->started = false;

	netconfig_update_cleanup(netconfig);
	l_queue_clear(netconfig->routes.current,
			(l_queue_destroy_func_t) l_rtnl_route_free);
	l_queue_clear(netconfig->addresses.current,
			(l_queue_destroy_func_t) l_rtnl_address_free);
	netconfig->v4_address = NULL;
	netconfig->v4_subnet_route = NULL;
	netconfig->v4_default_route = NULL;

	l_dhcp_client_stop(netconfig->dhcp_client);
}

LIB_EXPORT struct l_dhcp_client *l_netconfig_get_dhcp_client(
						struct l_netconfig *netconfig)
{
	if (unlikely(!netconfig))
		return NULL;

	return netconfig->dhcp_client;
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
