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

#ifndef __ELL_ICMP6_H
#define __ELL_ICMP6_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

struct l_icmp6_client;
struct l_icmp6_router;
struct l_netlink;

enum l_icmp6_client_event {
	L_ICMP6_CLIENT_EVENT_ROUTER_FOUND = 0,
};

typedef void (*l_icmp6_debug_cb_t)(const char *str, void *user_data);
typedef void (*l_icmp6_destroy_cb_t)(void *user_data);
typedef void (*l_icmp6_client_event_cb_t)(struct l_icmp6_client *client,
					enum l_icmp6_client_event event,
					void *event_data, void *user_data);

struct l_icmp6_client *l_icmp6_client_new(uint32_t ifindex);
void l_icmp6_client_free(struct l_icmp6_client *client);

bool l_icmp6_client_start(struct l_icmp6_client *client);
bool l_icmp6_client_stop(struct l_icmp6_client *client);

const struct l_icmp6_router *l_icmp6_client_get_router(
						struct l_icmp6_client *client);
bool l_icmp6_client_add_event_handler(struct l_icmp6_client *client,
					l_icmp6_client_event_cb_t handler,
					void *user_data,
					l_icmp6_destroy_cb_t destroy);
bool l_icmp6_client_set_debug(struct l_icmp6_client *client,
				l_icmp6_debug_cb_t function,
				void *user_data, l_icmp6_destroy_cb_t destroy);
bool l_icmp6_client_set_address(struct l_icmp6_client *client,
					const uint8_t addr[static 6]);
bool l_icmp6_client_set_nodelay(struct l_icmp6_client *client, bool nodelay);
bool l_icmp6_client_set_rtnl(struct l_icmp6_client *client,
						struct l_netlink *rtnl);
bool l_icmp6_client_set_route_priority(struct l_icmp6_client *client,
						uint32_t priority);
bool l_icmp6_client_set_link_local_address(struct l_icmp6_client *client,
						const char *ll,
						bool optimistic);

char *l_icmp6_router_get_address(const struct l_icmp6_router *r);
bool l_icmp6_router_get_managed(const struct l_icmp6_router *r);
bool l_icmp6_router_get_other(const struct l_icmp6_router *r);
uint16_t l_icmp6_router_get_lifetime(const struct l_icmp6_router *r);
uint64_t l_icmp6_router_get_start_time(const struct l_icmp6_router *r);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_ICMP6_H */
