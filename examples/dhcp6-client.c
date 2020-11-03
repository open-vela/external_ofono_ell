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
#include <arpa/inet.h>

#include <ell/ell.h>

static bool terminating;
static struct l_timeout *timeout;
static struct l_dhcp6_client *client;

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void main_loop_quit(struct l_timeout *timeout, void *user_data)
{
	l_main_quit();
}

static void client_shutdown(void)
{
	if (terminating)
		return;

	terminating = true;

	timeout = l_timeout_create(1, main_loop_quit, NULL, NULL);
	l_dhcp6_client_stop(client);
}

static void signal_handler(uint32_t signo, void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_info("Terminate");
		client_shutdown();
		break;
	}
}

static void print_lease(const struct l_dhcp6_lease *lease)
{
	char *ip = l_dhcp6_lease_get_address(lease);
	char **dns = l_dhcp6_lease_get_dns(lease);
	uint32_t prefix_length = l_dhcp6_lease_get_prefix_length(lease);

	l_info("Lease Obtained:");

	l_info("\tIP: %s/%u", ip, prefix_length);
	l_free(ip);

	if (dns) {
		char *dns_concat = l_strjoinv(dns, ',');
		l_info("\tDNS List: %s", dns_concat);
		l_free(dns_concat);
		l_strfreev(dns);
	} else
		l_info("\tNo DNS information obtained");
}

static void event_handler(struct l_dhcp6_client *client,
					enum l_dhcp6_client_event event,
					void *userdata)
{
	switch (event) {
	case L_DHCP6_CLIENT_EVENT_IP_CHANGED:
		l_info("IP changed");
		/* Fall through */
	case L_DHCP6_CLIENT_EVENT_LEASE_OBTAINED:
		print_lease(l_dhcp6_client_get_lease(client));
		break;
	case L_DHCP6_CLIENT_EVENT_LEASE_EXPIRED:
		l_info("Lease expired");
		break;
	case L_DHCP6_CLIENT_EVENT_LEASE_RENEWED:
		l_info("Lease Renewed");
		break;
	case L_DHCP6_CLIENT_EVENT_NO_LEASE:
		l_info("No lease available");
		break;
	}
}

int main(int argc, char *argv[])
{
	struct in6_addr in6;
	struct l_netlink *rtnl;
	struct l_icmp6_client *icmp6;
	int ifindex;
	uint8_t mac[6];
	char ll_str[INET6_ADDRSTRLEN];

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <interface index>\n", argv[0]);
		return EXIT_FAILURE;
	}

	ifindex = atoi(argv[1]);

	if (!l_net_get_mac_address(ifindex, mac)) {
		fprintf(stderr, "Unable to get address from interface %d\n",
				ifindex);
		return EXIT_FAILURE;
	}

	if (!l_net_get_link_local_address(ifindex, &in6)) {
		fprintf(stderr, "Unable to get link-local address\n");
		return EXIT_FAILURE;
	}

	inet_ntop(AF_INET6, &in6, ll_str, sizeof(ll_str));
	fprintf(stdout, "Binding to Link-Local address:  %s\n", ll_str);

	l_log_set_stderr();
	l_debug_enable("*");

	if (!l_main_init())
		return EXIT_FAILURE;

	rtnl = l_netlink_new(NETLINK_ROUTE);
	if (!rtnl) {
		fprintf(stderr, "Failed to open RTNL\n");
		return EXIT_FAILURE;
	}

	client = l_dhcp6_client_new(ifindex);
	l_dhcp6_client_set_address(client, ARPHRD_ETHER, mac, 6);
	l_dhcp6_client_set_link_local_address(client, ll_str);
	l_dhcp6_client_set_event_handler(client, event_handler, NULL, NULL);
	l_dhcp6_client_set_debug(client, do_debug, "[DHCP6] ", NULL);
	l_dhcp6_client_set_lla_randomized(client, true);
	l_dhcp6_client_set_rtnl(client, rtnl);

	icmp6 = l_dhcp6_client_get_icmp6(client);
	l_icmp6_client_set_rtnl(icmp6, rtnl);
	l_icmp6_client_set_route_priority(icmp6, 300);

	l_dhcp6_client_start(client);

	l_main_run_with_signal(signal_handler, NULL);

	l_timeout_remove(timeout);
	l_dhcp6_client_destroy(client);
	l_main_exit();

	l_netlink_destroy(rtnl);

	return EXIT_SUCCESS;
}
