/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2020  Intel Corporation. All rights reserved.
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

#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>

#include "private.h"
#include "time.h"
#include "net.h"
#include "dhcp.h"
#include "dhcp-private.h"
#include "queue.h"
#include "util.h"
#include "strv.h"

/* 8 hours */
#define DEFAULT_DHCP_LEASE_SEC (8*60*60)

struct l_dhcp_server {
	bool started;
	int ifindex;
	char *ifname;
	uint32_t start_ip;
	uint32_t end_ip;
	uint32_t address;
	uint32_t netmask;
	uint32_t gateway;
	uint32_t *dns_list;
	uint32_t lease_seconds;

	struct l_queue *lease_list;

	l_dhcp_debug_cb_t debug_handler;
	void *debug_data;
	l_dhcp_destroy_cb_t debug_destroy;

	l_dhcp_server_event_cb_t event_handler;
	void *user_data;
	l_dhcp_destroy_cb_t event_destroy;
};

#define MAC "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_STR(a) a[0], a[1], a[2], a[3], a[4], a[5]

#define IP_STR(uint_ip) \
({ \
	struct in_addr _in; \
	char *_out; \
	_in.s_addr = uint_ip; \
	_out = inet_ntoa(_in); \
	_out; \
})

#define SERVER_DEBUG(fmt, args...)					\
	l_util_debug(server->debug_handler, server->debug_data,		\
			"%s:%i " fmt, __func__, __LINE__, ## args)

LIB_EXPORT struct l_dhcp_server *l_dhcp_server_new(int ifindex)
{
	struct l_dhcp_server *server = l_new(struct l_dhcp_server, 1);
	if (!server)
		return NULL;

	server->lease_list = l_queue_new();

	server->started = false;

	server->lease_seconds = DEFAULT_DHCP_LEASE_SEC;

	server->ifindex = ifindex;
	server->debug_handler = NULL;
	server->debug_data = NULL;

	return server;
}

LIB_EXPORT void l_dhcp_server_destroy(struct l_dhcp_server *server)
{
	if (unlikely(!server))
		return;

	l_dhcp_server_stop(server);

	if (server->event_destroy)
		server->event_destroy(server->user_data);

	l_free(server->ifname);

	l_queue_destroy(server->lease_list,
				(l_queue_destroy_func_t) _dhcp_lease_free);

	if (server->dns_list)
		l_free(server->dns_list);

	l_free(server);
}

LIB_EXPORT bool l_dhcp_server_start(struct l_dhcp_server *server)
{
	struct in_addr ia;

	if (unlikely(!server))
		return false;

	if (server->started)
		return false;

	if (!server->address) {
		if (!l_net_get_address(server->ifindex, &ia))
			return false;

		server->address = ia.s_addr;
	}

	/* Assign a default gateway if not already set */
	if (!server->gateway)
		server->gateway = server->address;

	/* Assign a default netmask if not already */
	if (!server->netmask) {
		if (inet_aton("255.255.255.0", &ia) < 0)
			return false;

		server->netmask = ia.s_addr;
	}

	/*
	 * Assign a default ip range if not already. This will default to
	 * server->address + 1 ... 254
	 */
	if (!server->start_ip) {
		server->start_ip = L_BE32_TO_CPU(server->address) + 1;
		server->end_ip = (server->start_ip & 0xffffff00) | 0xfe;
	}

	if (!server->ifname) {
		server->ifname = l_net_get_name(server->ifindex);

		if (!server->ifname)
			return false;
	}

	SERVER_DEBUG("Starting DHCP server on %s", server->ifname);

	server->started = true;

	return true;
}

LIB_EXPORT bool l_dhcp_server_stop(struct l_dhcp_server *server)
{
	if (unlikely(!server))
		return false;

	if (!server->started)
		return true;

	server->started = false;

	/* TODO: Add ability to save leases */

	return true;
}

LIB_EXPORT bool l_dhcp_server_set_ip_range(struct l_dhcp_server *server,
				const char *start_ip,
				const char *end_ip)
{
	struct in_addr _host_addr;
	uint32_t start;

	if (unlikely(!server || !start_ip || !end_ip))
		return false;

	if (inet_aton((const char *)start_ip, &_host_addr) == 0)
		return false;

	start = ntohl(_host_addr.s_addr);

	if (inet_aton((const char *) end_ip, &_host_addr) == 0)
		return false;

	server->start_ip = start;
	server->end_ip = ntohl(_host_addr.s_addr);

	return true;
}

LIB_EXPORT bool l_dhcp_server_set_debug(struct l_dhcp_server *server,
				l_dhcp_debug_cb_t function,
				void *user_data, l_dhcp_destroy_cb_t destory)
{
	if (unlikely(!server))
		return false;

	server->debug_handler = function;
	server->debug_data = user_data;
	server->debug_destroy = destory;

	return true;
}

LIB_EXPORT bool l_dhcp_server_set_lease_time(struct l_dhcp_server *server,
					unsigned int lease_time)
{
	if (unlikely(!server))
		return false;

	server->lease_seconds = lease_time;

	return true;
}

LIB_EXPORT bool l_dhcp_server_set_event_handler(struct l_dhcp_server *server,
					l_dhcp_server_event_cb_t handler,
					void *user_data,
					l_dhcp_destroy_cb_t destroy)
{
	if (unlikely(!server))
		return false;

	server->event_handler = handler;
	server->user_data = user_data;
	server->event_destroy = destroy;

	return true;
}

LIB_EXPORT bool l_dhcp_server_set_ip_address(struct l_dhcp_server *server,
						const char *ip)
{
	struct in_addr ia;

	if (unlikely(!server))
		return false;

	if (inet_aton(ip, &ia) < 0)
		return false;

	server->address = ia.s_addr;

	return true;
}

LIB_EXPORT bool l_dhcp_server_set_interface_name(struct l_dhcp_server *server,
							const char *ifname)
{
	if (unlikely(!server || !ifname))
		return false;

	l_free(server->ifname);
	server->ifname = l_strdup(ifname);

	return true;
}

LIB_EXPORT bool l_dhcp_server_set_netmask(struct l_dhcp_server *server,
						const char *mask)
{
	struct in_addr ia;

	if (unlikely(!server || !mask))
		return false;

	if (inet_aton(mask, &ia) < 0)
		return false;

	server->netmask = ia.s_addr;

	return true;
}

LIB_EXPORT bool l_dhcp_server_set_gateway(struct l_dhcp_server *server,
						const char *ip)
{
	struct in_addr ia;

	if (unlikely(!server || !ip))
		return false;

	if (inet_aton(ip, &ia) < 0)
		return false;

	server->gateway = ia.s_addr;

	return true;
}

LIB_EXPORT bool l_dhcp_server_set_dns(struct l_dhcp_server *server, char **dns)
{
	unsigned int i;
	uint32_t *dns_list;

	if (unlikely(!server || !dns))
		return false;

	dns_list = l_new(uint32_t, l_strv_length(dns) + 1);

	for (i = 0; dns[i]; i++) {
		struct in_addr ia;

		if (inet_aton(dns[i], &ia) < 0)
			goto failed;

		dns_list[i] = ia.s_addr;
	}

	if (server->dns_list)
		l_free(server->dns_list);

	server->dns_list = dns_list;

	return true;

failed:
	l_free(dns_list);
	return false;
}
