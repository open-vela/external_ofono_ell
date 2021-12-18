/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2014  Intel Corporation. All rights reserved.
 *  Copyright (C) 2020  Daniel Wagner <dwagner@suse.de>
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

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>

#include <ell/ell.h>
#include "ell/dbus-private.h"

static void signal_handler(uint32_t signo, void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_info("Terminate");
		l_main_quit();
		break;
	}
}

static struct l_netlink *rtnl;

struct rtnl_test {
	const char *name;
	void (*start)(struct l_netlink *rtnl, void *);
	void *data;
};

static bool success;
static struct l_queue *tests;
static const struct l_queue_entry *current;

static void test_add(const char *name,
			void (*start)(struct l_netlink *rtnl, void *),
			void *user_data)
{
	struct rtnl_test *test = l_new(struct rtnl_test, 1);

	test->name = name;
	test->start = start;
	test->data = user_data;

	if (!tests)
		tests = l_queue_new();

	l_queue_push_tail(tests, test);
}

static void test_next()
{
	struct rtnl_test *test;

	if (current)
		current = current->next;
	else
		current = l_queue_get_entries(tests);

	if (!current) {
		success = true;
		l_main_quit();
		return;
	}

	test = current->data;

	l_info("TEST: %s", test->name);

	test->start(rtnl, test->data);
}

#define test_assert(cond)	\
	do {	\
		if (!(cond)) {	\
			l_info("TEST FAILED in %s at %s:%i: %s",	\
				__func__, __FILE__, __LINE__,	\
				L_STRINGIFY(cond));	\
			l_main_quit();	\
			return;	\
		}	\
	} while (0)


static void route4_dump_cb(int error,
			uint16_t type, const void *data,
			uint32_t len, void *user_data)
{
	const struct rtmsg *rtmsg = data;
	char *dst = NULL, *gateway = NULL, *src = NULL;
	uint32_t table, ifindex;

	test_assert(!error);
	test_assert(type == RTM_NEWROUTE);

	l_rtnl_route4_extract(rtmsg, len, &table, &ifindex,
				&dst, &gateway, &src);

	l_info("table %d ifindex %d dst %s gateway %s src %s",
		table, ifindex, dst, gateway, src);

	l_free(dst);
	l_free(gateway);
	l_free(src);
}

static void route4_dump_destroy_cb(void *user_data)
{
	test_next();
}

static void test_route4_dump(struct l_netlink *rtnl, void *user_data)
{
	test_assert(l_rtnl_route4_dump(rtnl, route4_dump_cb,
					NULL, route4_dump_destroy_cb));
}

static void route6_dump_cb(int error,
			uint16_t type, const void *data,
			uint32_t len, void *user_data)
{
	const struct rtmsg *rtmsg = data;
	char *dst = NULL, *gateway = NULL, *src = NULL;
	uint32_t table = 0, ifindex = 0;

	test_assert(!error);
	test_assert(type == RTM_NEWROUTE);

	l_rtnl_route6_extract(rtmsg, len, &table, &ifindex,
				&dst, &gateway, &src);

	l_info("table %d ifindex %d dst %s gateway %s src %s",
		table, ifindex, dst, gateway, src);

	l_free(dst);
	l_free(gateway);
	l_free(src);
}

static void route6_dump_destroy_cb(void *user_data)
{
	test_next();
}

static void test_route6_dump(struct l_netlink *rtnl, void *user_data)
{
	test_assert(l_rtnl_route6_dump(rtnl, route6_dump_cb,
					NULL, route6_dump_destroy_cb));
}

static void ifaddr4_dump_cb(int error,
				uint16_t type, const void *data,
				uint32_t len, void *user_data)
{
	const struct ifaddrmsg *ifa = data;
	char *label = NULL, *ip = NULL, *broadcast = NULL;

	test_assert(!error);
	test_assert(type == RTM_NEWADDR);

	l_rtnl_ifaddr4_extract(ifa, len, &label, &ip, &broadcast);

	l_info("label %s ip %s broadcast %s", label, ip, broadcast);

	l_free(label);
	l_free(ip);
	l_free(broadcast);
}

static void ifaddr4_dump_destroy_cb(void *user_data)
{
	test_next();
}

static void test_ifaddr4_dump(struct l_netlink *rntl, void *user_data)
{
	test_assert(l_rtnl_ifaddr4_dump(rtnl, ifaddr4_dump_cb,
					NULL, ifaddr4_dump_destroy_cb));
}

static void ifaddr6_dump_cb(int error,
				uint16_t type, const void *data,
				uint32_t len, void *user_data)
{
	const struct ifaddrmsg *ifa = data;
	char *ip = NULL;

	test_assert(!error);
	test_assert(type == RTM_NEWADDR);

	l_rtnl_ifaddr6_extract(ifa, len, &ip);

	l_info("ip %s", ip);

	l_free(ip);
}

static void ifaddr6_dump_destroy_cb(void *user_data)
{
	test_next();
}

static void test_ifaddr6_dump(struct l_netlink *rntl, void *user_data)
{
	test_assert(l_rtnl_ifaddr6_dump(rtnl, ifaddr6_dump_cb,
					NULL, ifaddr6_dump_destroy_cb));
}

static void test_run(void)
{
	success = false;

	l_idle_oneshot(test_next, NULL, NULL);
	l_main_run_with_signal(signal_handler, NULL);
}

int main(int argc, char *argv[])
{
	if (!l_main_init())
		return -1;

	test_add("Dump IPv4 routing table", test_route4_dump, NULL);
	test_add("Dump IPv6 routing table", test_route6_dump, NULL);
	test_add("Dump IPv4 addresses", test_ifaddr4_dump, NULL);
	test_add("Dump IPv6 addresses", test_ifaddr6_dump, NULL);

	l_log_set_stderr();

	rtnl = l_netlink_new(NETLINK_ROUTE);
	if (!rtnl)
		goto done;

	test_run();

	l_netlink_destroy(rtnl);

done:
	l_queue_destroy(tests, l_free);

	l_main_exit();

	if (!success)
		abort();

	return 0;
}
