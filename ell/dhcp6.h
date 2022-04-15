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

#ifndef __ELL_DHCP6_H
#define __ELL_DHCP6_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

struct l_dhcp6_client;
struct l_dhcp6_lease;
struct l_netlink;
struct l_icmp6_client;

enum l_dhcp6_option {
	L_DHCP6_OPTION_DNS_SERVERS		= 23,
	L_DHCP6_OPTION_DOMAIN_LIST		= 24,
	L_DHCP6_OPTION_SNTP_SERVERS		= 31,
	L_DHCP6_OPTION_NTP_SERVER		= 56,
};

enum l_dhcp6_client_event {
	L_DHCP6_CLIENT_EVENT_LEASE_OBTAINED = 0,
	L_DHCP6_CLIENT_EVENT_IP_CHANGED,
	L_DHCP6_CLIENT_EVENT_LEASE_EXPIRED,
	L_DHCP6_CLIENT_EVENT_LEASE_RENEWED,
	L_DHCP6_CLIENT_EVENT_NO_LEASE,
};

typedef void (*l_dhcp6_client_event_cb_t)(struct l_dhcp6_client *client,
						enum l_dhcp6_client_event event,
						void *userdata);
typedef void (*l_dhcp6_debug_cb_t)(const char *str, void *user_data);
typedef void (*l_dhcp6_destroy_cb_t)(void *userdata);

struct l_dhcp6_client *l_dhcp6_client_new(uint32_t ifindex);
void l_dhcp6_client_destroy(struct l_dhcp6_client *client);

const struct l_dhcp6_lease *l_dhcp6_client_get_lease(
					const struct l_dhcp6_client *client);
bool l_dhcp6_client_set_address(struct l_dhcp6_client *client, uint8_t type,
				const uint8_t *addr, size_t addr_len);
bool l_dhcp6_client_set_link_local_address(struct l_dhcp6_client *client,
						const char *ll);
bool l_dhcp6_client_set_debug(struct l_dhcp6_client *client,
				l_dhcp6_debug_cb_t function,
				void *user_data, l_dhcp6_destroy_cb_t destroy);
bool l_dhcp6_client_set_event_handler(struct l_dhcp6_client *client,
					l_dhcp6_client_event_cb_t handler,
					void *userdata,
					l_dhcp6_destroy_cb_t destroy);
bool l_dhcp6_client_set_lla_randomized(struct l_dhcp6_client *client,
						bool randomized);
bool l_dhcp6_client_set_nodelay(struct l_dhcp6_client *client, bool nodelay);
bool l_dhcp6_client_set_nora(struct l_dhcp6_client *client, bool nora);
bool l_dhcp6_client_set_no_rapid_commit(struct l_dhcp6_client *client,
							bool no_rapid_commit);
bool l_dhcp6_client_set_rtnl(struct l_dhcp6_client *client,
						struct l_netlink *rtnl);
bool l_dhcp6_client_set_stateless(struct l_dhcp6_client *client,
								bool stateless);

struct l_icmp6_client *l_dhcp6_client_get_icmp6(struct l_dhcp6_client *client);

bool l_dhcp6_client_add_request_option(struct l_dhcp6_client *client,
						enum l_dhcp6_option option);

bool l_dhcp6_client_start(struct l_dhcp6_client *client);
bool l_dhcp6_client_stop(struct l_dhcp6_client *client);

char *l_dhcp6_lease_get_address(const struct l_dhcp6_lease *lease);
char **l_dhcp6_lease_get_dns(const struct l_dhcp6_lease *lease);
char **l_dhcp6_lease_get_domains(const struct l_dhcp6_lease *lease);
uint8_t l_dhcp6_lease_get_prefix_length(const struct l_dhcp6_lease *lease);
uint32_t l_dhcp6_lease_get_valid_lifetime(const struct l_dhcp6_lease *lease);
uint32_t l_dhcp6_lease_get_preferred_lifetime(
					const struct l_dhcp6_lease *lease);
uint64_t l_dhcp6_lease_get_start_time(const struct l_dhcp6_lease *lease);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_DHCP6_H */
