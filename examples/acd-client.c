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
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <sys/socket.h>
#include <linux/if_arp.h>
#include <getopt.h>

#include <ell/ell.h>

static enum l_acd_defend_policy policy = L_ACD_DEFEND_POLICY_DEFEND;

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

static void event_handler(enum l_acd_event event, void *user_data)
{
	char *ip = user_data;

	switch (event) {
	case L_ACD_EVENT_CONFLICT:
		l_info("IP %s conflicts with another host", ip);
		break;
	case L_ACD_EVENT_AVAILABLE:
		l_info("IP %s is available", ip);
		break;
	case L_ACD_EVENT_LOST:
		l_info("IP %s has been lost", ip);
		l_main_quit();
		break;
	}

	if (policy == L_ACD_DEFEND_POLICY_NONE)
		l_main_quit();
}

static void usage(void)
{
	printf("acd-client usage\n"
		"Usage:\n");
	printf("\tacd-client <ifindex> <ip> [options]\n");
	printf("Options:\n"
		"\t-D, --defend [=policy] Keep running to defend address, "
			"optionally by policy:\n"
			"\t\tnone: never defend\n"
			"\t\tdefend: defend once (default)\n"
			"\t\tinfinite: defend infinitely\n"
		"\t-n, --no-probes       Disable initial probe stage\n"
		"\t-d, --debug           Run with debugging on\n");
}

static const struct option main_options[] = {
	{ "defend",	 optional_argument,	NULL, 'D' },
	{ "no-probes",	 no_argument,		NULL, 'n' },
	{ "debug",	 no_argument,		NULL, 'd' },
	{ }
};

int main(int argc, char *argv[])
{
	struct l_acd *acd;
	int ifindex;
	bool debug = false;
	bool no_probe = false;

	l_log_set_stderr();
	l_debug_enable("*");

	if (argc < 3) {
		usage();
		exit(0);
	}

	for (;;) {
		int opt;

		opt = getopt_long(argc - 2, argv + 2, "ndD::",
					main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'D':
			if (optarg) {
				if (!strcmp(optarg, "infinite"))
					policy = L_ACD_DEFEND_POLICY_INFINITE;
				else if (!strcmp(optarg, "none"))
					policy = L_ACD_DEFEND_POLICY_NONE;
			}

			break;
		case 'n':
			no_probe = true;
			break;
		case 'd':
			debug = true;
			break;
		}
	}

	ifindex = atoi(argv[1]);

	if (!l_main_init())
		return -1;

	acd = l_acd_new(ifindex);
	l_acd_set_skip_probes(acd, no_probe);
	l_acd_set_defend_policy(acd, policy);

	if (debug) {
		l_acd_set_debug(acd, do_debug, "[ACD] ", NULL);
		l_info("Set debug");
	}
	l_acd_set_event_handler(acd, event_handler, argv[2], NULL);
	l_acd_start(acd, argv[2]);

	l_main_run_with_signal(signal_handler, NULL);

	l_acd_destroy(acd);
	l_main_exit();

	return 0;
}
