/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
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
#include <stdio.h>

#include <ell/ell.h>
#include "ell/net-private.h"

static void test_net_hostname_is_localhost(const void *data)
{
	assert(l_net_hostname_is_localhost("localhost"));
	assert(l_net_hostname_is_localhost("localhost."));
	assert(l_net_hostname_is_localhost("localhost.localdomain"));
	assert(l_net_hostname_is_localhost("localhost.localdomain."));
	assert(l_net_hostname_is_localhost("other.localhost"));
	assert(l_net_hostname_is_localhost("other.localhost."));
	assert(l_net_hostname_is_localhost("other.localhost.localdomain"));
	assert(l_net_hostname_is_localhost("other.localhost.localdomain."));

	assert(l_net_hostname_is_localhost("LOCALHOST"));

	assert(!l_net_hostname_is_localhost("notsolocalhost"));
	assert(!l_net_hostname_is_localhost("localhost.com"));
	assert(!l_net_hostname_is_localhost(""));
}

static void test_net_hostname_is_root(const void *data)
{
	assert(l_net_hostname_is_root(""));
	assert(l_net_hostname_is_root("."));
	assert(!l_net_hostname_is_root("notsoroot"));
}

static void test_net_domain_name_parse(const void *data)
{
	static const uint8_t d1[] = { 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
					3, 'c', 'o', 'm', 0 };
	static const uint8_t d2[] = { 0 };
	static const uint8_t d3[] = { 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
					0, 0 };
	static const uint8_t d4[] = { 7, 'f', 'o', 'o', 'b', 'a', 'r', 0 };
	uint8_t d5[] = {
		[0] = 63,
		[1] = 'v',
		[2 ... 61] = 'e',
		[62] = 'r',
		[63] = 'y',
		[64] = 63,
		[65] = 'v',
		[66 ... 125] = 'e',
		[126] = 'r',
		[127] = 'y',
		[128] = 63,
		[129] = 'l',
		[130 ... 189] = 'o',
		[190] = 'n',
		[191] = 'g',
		[192] = 62,
		[193] = 'c',
		[194 ... 253] = 'o',
		[254] = 'm',
		[255] = 0
	};

	char *domain;

	domain = net_domain_name_parse(d1, sizeof(d1));
	assert(domain);
	assert(!strcmp(domain, "example.com"));
	l_free(domain);

	assert(!net_domain_name_parse(d1, sizeof(d1) - 1));
	assert(!net_domain_name_parse(d2, sizeof(d2)));
	assert(!net_domain_name_parse(d3, sizeof(d3)));
	assert(!net_domain_name_parse(d4, sizeof(d4)));
	assert(!net_domain_name_parse(d5, sizeof(d5)));

	d5[192] = 61;
	d5[253] = 'm';
	d5[254] = 0;

	domain = net_domain_name_parse(d5, sizeof(d5) - 1);
	assert(domain);
	l_free(domain);
}

static void test_net_domain_list_parse(const void *data)
{
	static const uint8_t l1[] = { 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
					3, 'c', 'o', 'm', 0,
					4, 't', 'e', 's', 't', 0 };
	static const uint8_t l2[] = { 0, 0 };
	static const uint8_t l3[] = { 4, '.', '=', '2', '3', 0 };
	static const uint8_t l4[] = { 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
					3, 'c', 'o', 'm', 0, 0 };
	char **domains;

	domains = net_domain_list_parse(l1, sizeof(l1), false);
	assert(domains);
	assert(domains[0]);
	assert(!strcmp(domains[0], "example.com"));
	assert(domains[1]);
	assert(!strcmp(domains[1], "test"));
	assert(!domains[2]);
	l_strfreev(domains);

	assert(!net_domain_list_parse(l2, sizeof(l2), false));

	domains = net_domain_list_parse(l3, sizeof(l3), false);
	assert(domains);
	assert(domains[0]);
	assert(!strcmp(domains[0], "\\.\\06123"));
	assert(!domains[1]);
	l_strfreev(domains);

	domains = net_domain_list_parse(l4, sizeof(l4), true);
	assert(domains);
	assert(domains[0]);
	assert(!strcmp(domains[0], "example.com"));
	assert(!domains[1]);
	l_strfreev(domains);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("net/hostname_is_localhost", test_net_hostname_is_localhost,
									NULL);
	l_test_add("net/hostname_is_root", test_net_hostname_is_root,
									NULL);

	l_test_add("net/domain_name_parse", test_net_domain_name_parse, NULL);
	l_test_add("net/domain_list_parse", test_net_domain_list_parse, NULL);

	return l_test_run();
}
