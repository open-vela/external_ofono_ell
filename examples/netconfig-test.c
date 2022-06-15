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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <errno.h>

#include <ell/ell.h>

static bool apply;

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

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

static void log_addresses(const char *af_str, const char *action,
				const struct l_queue_entry *entry)
{
	if (!entry)
		return;

	l_info("[netconfig%s] Addresses %s:", af_str, action);

	for (; entry; entry = entry->next) {
		struct l_rtnl_address *addr = entry->data;
		char ip_str[INET6_ADDRSTRLEN];

		l_rtnl_address_get_address(addr, ip_str);
		l_info("[netconfig%s] \t%s/%i, orig lifetime %i s",
			af_str, ip_str,
			l_rtnl_address_get_prefix_length(addr),
			l_rtnl_address_get_valid_lifetime(addr));
	}
}

static void log_routes(const char *af_str, const char *action,
			const struct l_queue_entry *entry)
{
	if (!entry)
		return;

	l_info("[netconfig%s] Routes %s:", af_str, action);

	for (; entry; entry = entry->next) {
		struct l_rtnl_route *rt = entry->data;
		char subnet_str[INET6_ADDRSTRLEN] = "unknown";
		char gateway_str[INET6_ADDRSTRLEN];
		uint8_t prefix_len;
		bool onlink;

		l_rtnl_route_get_dst(rt, subnet_str, &prefix_len);
		onlink = !l_rtnl_route_get_gateway(rt, gateway_str);
		l_info("[netconfig%s] \t%s/%i, %s%s, orig lifetime %i s",
			af_str, subnet_str, prefix_len,
			onlink ? "onlink" : "next-hop ",
			onlink ? "" : gateway_str,
			l_rtnl_route_get_lifetime(rt));
	}
}

static void event_handler(struct l_netconfig *netconfig, uint8_t family,
				enum l_netconfig_event event, void *user_data)
{
	const char *af_str = family == AF_INET ? "v4" : "v6";
	const struct l_queue_entry *added, *updated, *removed, *expired;

	switch (event) {
	case L_NETCONFIG_EVENT_CONFIGURE:
		l_info("[netconfig%s] Configure", af_str);
		break;
	case L_NETCONFIG_EVENT_UPDATE:
		l_info("[netconfig%s] Update", af_str);
		break;
	case L_NETCONFIG_EVENT_UNCONFIGURE:
		l_info("[netconfig%s] Unconfigure", af_str);
		break;
	case L_NETCONFIG_EVENT_FAILED:
		l_info("[netconfig%s] Failed", af_str);
		l_main_quit();
		return;
	}

	l_netconfig_get_addresses(netconfig, &added, &updated,
					&removed, &expired);
	log_addresses(af_str, "added", added);
	log_addresses(af_str, "updated", updated);
	log_addresses(af_str, "removed", removed);
	log_addresses(af_str, "expired", expired);

	l_netconfig_get_routes(netconfig, &added, &updated, &removed, &expired);
	log_routes(af_str, "added", added);
	log_routes(af_str, "updated", updated);
	log_routes(af_str, "removed", removed);
	log_routes(af_str, "expired", expired);

	if (apply)
		l_netconfig_apply_rtnl(netconfig);
}

static const struct option main_options[] = {
	{ "apply",	 no_argument,		NULL, 'a' },
	{ }
};

int main(int argc, char *argv[])
{
	struct l_netconfig *netconfig;
	int ifindex;

	if (argc < 2) {
                printf("Usage: %s <interface> [options]\n", argv[0]);
		return EXIT_SUCCESS;
        }

	ifindex = if_nametoindex(argv[1]);
	if (!ifindex) {
		fprintf(stderr, "if_nametoindex(%s): %s\n", argv[1],
			strerror(errno));
		return EXIT_FAILURE;
	}

	for (;;) {
		int opt = getopt_long(argc - 2, argv + 2, "a", main_options,
					NULL);

		if (opt < 0)
			break;

		switch (opt) {
		case 'a':
			apply = true;
			break;
		}
	}

	if (!l_main_init())
		return EXIT_FAILURE;

	l_log_set_stderr();
	l_debug_enable("*");

	netconfig = l_netconfig_new(ifindex);
	l_netconfig_set_event_handler(netconfig, event_handler, NULL, NULL);
	l_dhcp_client_set_debug(l_netconfig_get_dhcp_client(netconfig),
				do_debug, "[DHCPv4] ", NULL, L_LOG_DEBUG);
	l_netconfig_start(netconfig);

	l_main_run_with_signal(signal_handler, NULL);

	l_netconfig_destroy(netconfig);
	l_main_exit();

	return EXIT_SUCCESS;
}
