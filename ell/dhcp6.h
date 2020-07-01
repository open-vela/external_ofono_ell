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

typedef void (*l_dhcp6_debug_cb_t)(const char *str, void *user_data);
typedef void (*l_dhcp6_destroy_cb_t)(void *userdata);

struct l_dhcp6_client *l_dhcp6_client_new(uint32_t ifindex);
void l_dhcp6_client_destroy(struct l_dhcp6_client *client);

bool l_dhcp6_client_set_address(struct l_dhcp6_client *client, uint8_t type,
				const uint8_t *addr, size_t addr_len);
bool l_dhcp6_client_set_debug(struct l_dhcp6_client *client,
				l_dhcp6_debug_cb_t function,
				void *user_data, l_dhcp6_destroy_cb_t destroy);

bool l_dhcp6_client_start(struct l_dhcp6_client *client);
bool l_dhcp6_client_stop(struct l_dhcp6_client *client);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_DHCP6_H */
