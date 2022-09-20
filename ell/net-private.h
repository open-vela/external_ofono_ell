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

char *net_domain_name_parse(const uint8_t *raw, size_t raw_len);
char **net_domain_list_parse(const uint8_t *raw, size_t raw_len, bool padded);

static inline const void *net_prefix_from_ipv6(const uint8_t *address,
						uint8_t prefix_len)
{
	uint8_t last_byte = prefix_len / 8;
	uint8_t bits = prefix_len & 7;
	static uint8_t prefix[16];

	memcpy(prefix, address, last_byte);

	if (prefix_len & 7) {
		prefix[last_byte] = address[last_byte] & (0xff00 >> bits);
		last_byte++;
	}

	memset(prefix + last_byte, 0, 16 - last_byte);
	return prefix;
}
