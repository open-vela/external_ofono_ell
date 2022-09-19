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

#ifndef __ELL_NETCONFIG_H
#define __ELL_NETCONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

struct l_dhcp_client;
struct l_dhcp6_client;
struct l_icmp6_client;
struct l_netlink;
struct l_queue_entry;
struct l_netconfig;
struct l_rtnl_address;
struct l_rtnl_route;

enum l_netconfig_event {
	L_NETCONFIG_EVENT_CONFIGURE,
	L_NETCONFIG_EVENT_UPDATE,
	L_NETCONFIG_EVENT_UNCONFIGURE,
	L_NETCONFIG_EVENT_FAILED,
};

typedef void (*l_netconfig_event_cb_t)(struct l_netconfig *netconfig,
					uint8_t family,
					enum l_netconfig_event event,
					void *user_data);
typedef void (*l_netconfig_destroy_cb_t)(void *user_data);

struct l_netconfig *l_netconfig_new(uint32_t ifindex);
void l_netconfig_destroy(struct l_netconfig *netconfig);
bool l_netconfig_set_family_enabled(struct l_netconfig *netconfig,
					uint8_t family, bool enabled);
bool l_netconfig_set_hostname(struct l_netconfig *netconfig,
				const char *hostname);
bool l_netconfig_set_route_priority(struct l_netconfig *netconfig,
					uint32_t priority);
bool l_netconfig_set_static_addr(struct l_netconfig *netconfig, uint8_t family,
					const struct l_rtnl_address *addr);
bool l_netconfig_set_gateway_override(struct l_netconfig *netconfig,
					uint8_t family,
					const char *gateway_str);
bool l_netconfig_set_dns_override(struct l_netconfig *netconfig, uint8_t family,
					char **dns_list);
bool l_netconfig_set_domain_names_override(struct l_netconfig *netconfig,
						uint8_t family, char **names);
bool l_netconfig_set_acd_enabled(struct l_netconfig *netconfig, bool enabled);
bool l_netconfig_set_optimistic_dad_enabled(struct l_netconfig *netconfig,
						bool enabled);
bool l_netconfig_check_config(struct l_netconfig *netconfig);
bool l_netconfig_reset_config(struct l_netconfig *netconfig);

bool l_netconfig_start(struct l_netconfig *netconfig);
void l_netconfig_stop(struct l_netconfig *netconfig);
void l_netconfig_unconfigure(struct l_netconfig *netconfig);

struct l_dhcp_client *l_netconfig_get_dhcp_client(
						struct l_netconfig *netconfig);
struct l_dhcp6_client *l_netconfig_get_dhcp6_client(
						struct l_netconfig *netconfig);
struct l_icmp6_client *l_netconfig_get_icmp6_client(
						struct l_netconfig *netconfig);

void l_netconfig_set_event_handler(struct l_netconfig *netconfig,
					l_netconfig_event_cb_t handler,
					void *user_data,
					l_netconfig_destroy_cb_t destroy);

void l_netconfig_apply_rtnl(struct l_netconfig *netconfig);
const struct l_queue_entry *l_netconfig_get_addresses(
				struct l_netconfig *netconfig,
				const struct l_queue_entry **out_added,
				const struct l_queue_entry **out_updated,
				const struct l_queue_entry **out_removed,
				const struct l_queue_entry **out_expired);
const struct l_queue_entry *l_netconfig_get_routes(
				struct l_netconfig *netconfig,
				const struct l_queue_entry **out_added,
				const struct l_queue_entry **out_updated,
				const struct l_queue_entry **out_removed,
				const struct l_queue_entry **out_expired);
char **l_netconfig_get_dns_list(struct l_netconfig *netconfig);
char **l_netconfig_get_domain_names(struct l_netconfig *netconfig);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_NETCONFIG_H */
