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

#include <netinet/in.h>
#include <linux/types.h>
#include <linux/if_arp.h>
#include <errno.h>

#include "ell/net.h"
#include "ell/private.h"
#include "ell/dhcp6-private.h"
#include "ell/dhcp6.h"

#define CLIENT_DEBUG(fmt, args...)					\
	l_util_debug(client->debug_handler, client->debug_data,		\
			"%s:%i " fmt, __func__, __LINE__, ## args)

enum dhcp6_state {
	DHCP6_STATE_INIT,
	DHCP6_STATE_SOLICITING,
	DHCP6_STATE_REQUESTING_INFORMATION,
	DHCP6_STATE_REQUESTING,
	DHCP6_STATE_RENEWING,
	DHCP6_STATE_RELEASING,
};

struct l_dhcp6_client {
	enum dhcp6_state state;

	uint32_t ifindex;

	struct dhcp6_transport *transport;

	uint8_t addr[6];
	uint8_t addr_len;
	uint8_t addr_type;

	l_dhcp6_debug_cb_t debug_handler;
	l_dhcp6_destroy_cb_t debug_destroy;
	void *debug_data;
};

LIB_EXPORT struct l_dhcp6_client *l_dhcp6_client_new(uint32_t ifindex)
{
	struct l_dhcp6_client *client;

	client = l_new(struct l_dhcp6_client, 1);

	client->state = DHCP6_STATE_INIT;
	client->ifindex = ifindex;

	return client;
}

LIB_EXPORT void l_dhcp6_client_destroy(struct l_dhcp6_client *client)
{
	if (unlikely(!client))
		return;

	l_dhcp6_client_stop(client);

	l_free(client);
}

LIB_EXPORT bool l_dhcp6_client_set_address(struct l_dhcp6_client *client,
						uint8_t type,
						const uint8_t *addr,
						size_t addr_len)
{
	if (unlikely(!client))
		return false;

	switch (type) {
	case ARPHRD_ETHER:
		if (addr_len != ETH_ALEN)
			return false;
		break;
	default:
		return false;
	}

	client->addr_len = addr_len;
	memcpy(client->addr, addr, addr_len);
	client->addr_type = type;

	return true;
}

LIB_EXPORT bool l_dhcp6_client_set_debug(struct l_dhcp6_client *client,
						l_dhcp6_debug_cb_t function,
						void *user_data,
						l_dhcp6_destroy_cb_t destroy)
{
	if (unlikely(!client))
		return false;

	if (client->debug_destroy)
		client->debug_destroy(client->debug_data);

	client->debug_handler = function;
	client->debug_destroy = destroy;
	client->debug_data = user_data;

	return true;
}

LIB_EXPORT bool l_dhcp6_client_start(struct l_dhcp6_client *client)
{
	if (unlikely(!client))
		return false;

	if (unlikely(client->state != DHCP6_STATE_INIT))
		return false;

	if (!client->addr_len) {
		uint8_t mac[6];

		if (!l_net_get_mac_address(client->ifindex, mac))
			return false;

		l_dhcp6_client_set_address(client, ARPHRD_ETHER, mac, ETH_ALEN);
	}

	return true;
}

LIB_EXPORT bool l_dhcp6_client_stop(struct l_dhcp6_client *client)
{
	if (unlikely(!client))
		return false;

	return true;
}

bool _dhcp6_client_set_transport(struct l_dhcp6_client *client,
					struct dhcp6_transport *transport)
{
	if (unlikely(!client))
		return false;

	if (unlikely(client->state != DHCP6_STATE_INIT))
		return false;

	if (client->transport)
		_dhcp6_transport_free(client->transport);

	client->transport = transport;
	return true;
}
