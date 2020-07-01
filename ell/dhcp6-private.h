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

struct l_dhcp6_client;

enum {
	DHCP6_PORT_SERVER = 547,
	DHCP6_PORT_CLIENT = 546,
};

typedef void (*dhcp6_transport_rx_cb_t)(const void *, size_t, void *);

struct dhcp6_transport {
	int (*open)(struct dhcp6_transport *s);
	int (*send)(struct dhcp6_transport *transport,
						const struct in6_addr *dest,
						const void *data, size_t len);
	void (*close)(struct dhcp6_transport *transport);
	uint32_t ifindex;
	dhcp6_transport_rx_cb_t rx_cb;
	void *rx_data;
};

struct dhcp6_transport *_dhcp6_default_transport_new(uint32_t ifindex,
								uint16_t port);
void _dhcp6_transport_free(struct dhcp6_transport *transport);
void _dhcp6_transport_set_rx_callback(struct dhcp6_transport *transport,
					dhcp6_transport_rx_cb_t rx_cb,
					void *userdata);

bool _dhcp6_client_set_transport(struct l_dhcp6_client *client,
					struct dhcp6_transport *transport);
