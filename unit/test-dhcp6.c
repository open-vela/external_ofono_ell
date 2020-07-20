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

#include <assert.h>
#include <linux/types.h>
#include <netinet/ip.h>

#include <ell/ell.h>
#include "ell/dhcp6-private.h"

static const uint8_t advertise_no_address[] = {
	0x02, 0xfc, 0xd6, 0xaf, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01,
	0x26, 0xa3, 0x58, 0x38, 0x08, 0x00, 0x27, 0x2c, 0x64, 0xc8, 0x00, 0x02,
	0x00, 0x12, 0x00, 0x02, 0x00, 0x00, 0x0d, 0xe9, 0x47, 0x32, 0x30, 0x41,
	0x33, 0x32, 0x38, 0x30, 0x30, 0x30, 0x30, 0x32, 0x00, 0x11, 0x00, 0x27,
	0x00, 0x00, 0x0d, 0xe9, 0x00, 0x01, 0x00, 0x1f, 0x68, 0x74, 0x74, 0x70,
	0x73, 0x3a, 0x2f, 0x2f, 0x61, 0x63, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x64,
	0x2e, 0x67, 0x66, 0x73, 0x76, 0x63, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63,
	0x77, 0x6d, 0x70, 0x00, 0x0d, 0x00, 0x02, 0x00, 0x06, 0x00, 0x0d, 0x00,
	0x02, 0x00, 0x02, 0x00, 0x17, 0x00, 0x10, 0xfd, 0xaa, 0x88, 0x52, 0x00,
	0x88, 0x00, 0x01, 0xfa, 0x8f, 0xca, 0xff, 0xfe, 0x40, 0x87, 0x0c, 0x00,
	0x18, 0x00, 0x06, 0x04, 0x68, 0x6f, 0x6d, 0x65, 0x00
};

static void test_option_parsing(const void *data)
{
	struct dhcp6_message *message =
		(struct dhcp6_message *) advertise_no_address;
	size_t len = sizeof(advertise_no_address);
	struct dhcp6_option_iter iter;
	uint16_t t;
	uint16_t l;
	const void *v;

	assert(_dhcp6_option_iter_init(&iter, message, len));

	assert(_dhcp6_option_iter_next(&iter, &t, &l, &v));
	assert(t == L_DHCP6_OPTION_CLIENT_ID);
	assert(l == 14);

	assert(_dhcp6_option_iter_next(&iter, &t, &l, &v));
	assert(t == L_DHCP6_OPTION_SERVER_ID);
	assert(l == 18);

	assert(_dhcp6_option_iter_next(&iter, &t, &l, &v));
	assert(t == L_DHCP6_OPTION_VENDOR_OPTS);
	assert(l == 39);

	assert(_dhcp6_option_iter_next(&iter, &t, &l, &v));
	assert(t == L_DHCP6_OPTION_STATUS_CODE);
	assert(l == 2);

	assert(_dhcp6_option_iter_next(&iter, &t, &l, &v));
	assert(t == L_DHCP6_OPTION_STATUS_CODE);
	assert(l == 2);

	assert(_dhcp6_option_iter_next(&iter, &t, &l, &v));
	assert(t == L_DHCP6_OPTION_DNS_SERVERS);
	assert(l == 16);

	assert(_dhcp6_option_iter_next(&iter, &t, &l, &v));
	assert(t == L_DHCP6_OPTION_DOMAIN_LIST);
	assert(l == 6);

	assert(!_dhcp6_option_iter_next(&iter, &t, &l, &v));
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("option parsing", test_option_parsing, NULL);

	return l_test_run();
}
