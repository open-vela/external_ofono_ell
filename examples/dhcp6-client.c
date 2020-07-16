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

#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <linux/if_arp.h>

#include <ell/ell.h>

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

static void event_handler(struct l_dhcp6_client *client,
					enum l_dhcp6_client_event event,
					void *userdata)
{
}

int main(int argc, char *argv[])
{
	struct l_dhcp6_client *client;
	int ifindex;
	uint8_t mac[6];

	if (argc < 2) {
		l_info("Usage: %s <interface index>\n", argv[0]);
		return EXIT_FAILURE;
	}

	ifindex = atoi(argv[1]);

	if (!l_net_get_mac_address(ifindex, mac)) {
		printf("Unable to get address from interface %d\n", ifindex);
		return EXIT_FAILURE;
	}

	l_log_set_stderr();
	l_debug_enable("*");

	if (!l_main_init())
		return EXIT_FAILURE;

	client = l_dhcp6_client_new(ifindex);
	l_dhcp6_client_set_address(client, ARPHRD_ETHER, mac, 6);
	l_dhcp6_client_set_event_handler(client, event_handler, NULL, NULL);
	l_dhcp6_client_set_debug(client, do_debug, "[DHCP6] ", NULL);
	l_dhcp6_client_start(client);

	l_main_run_with_signal(signal_handler, NULL);

	l_dhcp6_client_destroy(client);
	l_main_exit();

	return EXIT_SUCCESS;
}
