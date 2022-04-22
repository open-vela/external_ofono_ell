/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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

#ifndef __ELL_NET_H
#define __ELL_NET_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

struct in_addr;
struct in6_addr;

#ifdef __cplusplus
extern "C" {
#endif

bool l_net_get_mac_address(uint32_t ifindex, uint8_t *out_addr);
char *l_net_get_name(uint32_t ifindex);
bool l_net_hostname_is_root(const char *hostname);
bool l_net_hostname_is_localhost(const char *hostname);
bool l_net_get_address(int ifindex, struct in_addr *out);
bool l_net_get_link_local_address(int ifindex, struct in6_addr *out);

static inline bool l_net_prefix_matches(const void *a, const void *b,
					uint8_t prefix_len)
{
	uint8_t bytes = prefix_len / 8;
	uint8_t bits = prefix_len & 7;
	uint8_t left = ((const uint8_t *) a)[bytes];
	uint8_t right = ((const uint8_t *) b)[bytes];

	/*
	 * @a and @b are network byte order IPv4 or IPv6 addresses.
	 * We want to check if the initial (top) @prefix_len bits match.
	 * memcmp the whole bytes, then compare the final byte's top
	 * bits by anding with a mask.
	 */
	if (memcmp(a, b, bytes))
		return false;

	return !bits || ((left ^ right) & (0xff00u >> bits)) == 0;
}

#ifdef __cplusplus
}
#endif

#endif /* __ELL_NET_H */
