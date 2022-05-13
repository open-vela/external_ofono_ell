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

struct l_rtnl_route {
	uint8_t family;
	uint8_t scope;
	uint8_t protocol;
	union {
		struct in6_addr in6_addr;
		struct in_addr in_addr;
	} gw;
	union {
		struct in6_addr in6_addr;
		struct in_addr in_addr;
	} dst;
	uint8_t dst_prefix_len;
	union {
		struct in6_addr in6_addr;
		struct in_addr in_addr;
	} prefsrc;
	uint32_t lifetime;
	uint64_t expiry_time;
	uint32_t mtu;
	uint32_t priority;
	uint8_t preference;
};
