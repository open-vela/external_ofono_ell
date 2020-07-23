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

enum l_dhcp6_option {
	L_DHCP6_OPTION_CLIENT_ID		= 1,
	L_DHCP6_OPTION_SERVER_ID		= 2,
	L_DHCP6_OPTION_IA_NA			= 3,
	L_DHCP6_OPTION_IA_TA			= 4,
	L_DHCP6_OPTION_IA_ADDR			= 5,
	L_DHCP6_OPTION_REQUEST_OPTION		= 6,
	L_DHCP6_OPTION_PREFERENCE		= 7,
	L_DHCP6_OPTION_ELAPSED_TIME		= 8,
	L_DHCP6_OPTION_RELAY_MSG		= 9,
	L_DHCP6_OPTION_AUTH			= 11,
	L_DHCP6_OPTION_UNICAST			= 12,
	L_DHCP6_OPTION_STATUS_CODE		= 13,
	L_DHCP6_OPTION_RAPID_COMMIT		= 14,
	L_DHCP6_OPTION_USER_CLASS		= 15,
	L_DHCP6_OPTION_VENDOR_CLASS		= 16,
	L_DHCP6_OPTION_VENDOR_OPTS		= 17,
	L_DHCP6_OPTION_INTERFACE_ID		= 18,
	L_DHCP6_OPTION_RECONF_MSG		= 19,
	L_DHCP6_OPTION_RECONF_ACCEPT		= 20,
	L_DHCP6_OPTION_DNS_SERVERS		= 23,
	L_DHCP6_OPTION_DOMAIN_LIST		= 24,
	L_DHCP6_OPTION_IA_PD			= 25,
	L_DHCP6_OPTION_IA_PREFIX		= 26,
	L_DHCP6_OPTION_SNTP_SERVERS		= 31,
	L_DHCP6_OPTION_INF_RT			= 32,
	L_DHCP6_OPTION_NTP_SERVER		= 56,
	L_DHCP6_OPTION_SOL_MAX_RT		= 82,
	L_DHCP6_OPTION_INF_MAX_RT		= 83,
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

bool l_dhcp6_client_set_address(struct l_dhcp6_client *client, uint8_t type,
				const uint8_t *addr, size_t addr_len);
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
bool l_dhcp6_client_set_stateless(struct l_dhcp6_client *client,
								bool stateless);

bool l_dhcp6_client_add_request_option(struct l_dhcp6_client *client,
						enum l_dhcp6_option option);

bool l_dhcp6_client_start(struct l_dhcp6_client *client);
bool l_dhcp6_client_stop(struct l_dhcp6_client *client);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_DHCP6_H */
