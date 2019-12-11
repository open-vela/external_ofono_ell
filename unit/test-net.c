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

#include <ell/ell.h>

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

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("net/hostname_is_localhost", test_net_hostname_is_localhost,
									NULL);
	l_test_add("net/hostname_is_root", test_net_hostname_is_root,
									NULL);

	return l_test_run();
}
