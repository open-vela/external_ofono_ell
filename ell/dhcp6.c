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
#include <time.h>

#include "ell/net.h"
#include "ell/uintset.h"
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

	struct duid *duid;
	uint16_t duid_len;

	struct l_uintset *request_options;

	uint32_t ifindex;

	struct dhcp6_transport *transport;

	uint8_t addr[6];
	uint8_t addr_len;
	uint8_t addr_type;

	l_dhcp6_debug_cb_t debug_handler;
	l_dhcp6_destroy_cb_t debug_destroy;
	void *debug_data;
};

static void client_enable_option(struct l_dhcp6_client *client,
						enum l_dhcp6_option option)
{
	size_t i;

	static const struct {
		enum l_dhcp6_option option;
	} options_to_ignore[] = {
		{ L_DHCP6_OPTION_CLIENT_ID },
		{ L_DHCP6_OPTION_SERVER_ID },
		{ L_DHCP6_OPTION_IA_NA },
		{ L_DHCP6_OPTION_IA_TA },
		{ L_DHCP6_OPTION_IA_PD },
		{ L_DHCP6_OPTION_IA_ADDR },
		{ L_DHCP6_OPTION_IA_PREFIX },
		{ L_DHCP6_OPTION_REQUEST_OPTION },
		{ L_DHCP6_OPTION_ELAPSED_TIME },
		{ L_DHCP6_OPTION_PREFERENCE },
		{ L_DHCP6_OPTION_RELAY_MSG },
		{ L_DHCP6_OPTION_AUTH },
		{ L_DHCP6_OPTION_UNICAST },
		{ L_DHCP6_OPTION_STATUS_CODE },
		{ L_DHCP6_OPTION_RAPID_COMMIT },
		{ L_DHCP6_OPTION_USER_CLASS },
		{ L_DHCP6_OPTION_VENDOR_CLASS },
		{ L_DHCP6_OPTION_INTERFACE_ID },
		{ L_DHCP6_OPTION_RECONF_MSG },
		{ L_DHCP6_OPTION_RECONF_ACCEPT },
		{ }
	};

	for (i = 0; options_to_ignore[i].option; i++)
		if (options_to_ignore[i].option == option)
			return;

	l_uintset_put(client->request_options, option);
}

static void client_duid_generate_addr_plus_time(struct l_dhcp6_client *client)
{
	uint16_t duid_len;
	uint32_t time_stamp;
	static const time_t JAN_FIRST_2000_IN_SEC = 946684800UL;

	if (client->duid)
		return;

	duid_len = 2 + 2 + 4 + client->addr_len;

	/*
	 * The time value is the time that the DUID is generated, represented in
	 * seconds since midnight (UTC), January 1, 2000, modulo 2^32
	 */
	time_stamp = (time(NULL) - JAN_FIRST_2000_IN_SEC) & 0xFFFFFFFFU;

	client->duid = l_malloc(duid_len);
	client->duid_len = duid_len;

	client->duid->type = L_CPU_TO_BE16(DUID_TYPE_LINK_LAYER_ADDR_PLUS_TIME);
	l_put_be16(client->addr_type, client->duid->identifier);
	l_put_be32(time_stamp, client->duid->identifier + 2);
	memcpy(client->duid->identifier + 2 + 4, client->addr,
							client->addr_len);
}

bool _dhcp6_option_iter_init(struct dhcp6_option_iter *iter,
				const struct dhcp6_message *message, size_t len)
{
	if (!message)
		return false;

	if (len < sizeof(struct dhcp6_message))
		return false;

	memset(iter, 0, sizeof(*iter));
	iter->max = len - sizeof(struct dhcp6_message);
	iter->options = message->options;

	return true;
}

static bool option_next(struct dhcp6_option_iter *iter,
				uint16_t *t, uint16_t *l, const void **v)
{
	uint16_t type;
	uint16_t len;

	while (iter->pos + 4 <= iter->max) {
		type = l_get_be16(iter->options + iter->pos);
		len = l_get_be16(iter->options + iter->pos + 2);

		if (iter->pos + 4 + len > iter->max)
			return false;

		*t = type;
		*l = len;
		*v = &iter->options[iter->pos + 4];

		iter->pos += 4 + len;
		return true;
	}

	return false;
}

bool _dhcp6_option_iter_next(struct dhcp6_option_iter *iter, uint16_t *type,
				uint16_t *len, const void **data)
{
	bool r;
	uint16_t t;
	uint16_t l;
	const void *v;

	r = option_next(iter, &t, &l, &v);

	if (!r)
		return false;

	if (type)
		*type = t;

	if (len)
		*len = l;

	if (data)
		*data = v;

	return true;
}

LIB_EXPORT struct l_dhcp6_client *l_dhcp6_client_new(uint32_t ifindex)
{
	struct l_dhcp6_client *client;

	client = l_new(struct l_dhcp6_client, 1);

	client->state = DHCP6_STATE_INIT;
	client->ifindex = ifindex;

	client->request_options = l_uintset_new(256);
	client_enable_option(client, L_DHCP6_OPTION_DOMAIN_LIST);
	client_enable_option(client, L_DHCP6_OPTION_DNS_SERVERS);

	return client;
}

LIB_EXPORT void l_dhcp6_client_destroy(struct l_dhcp6_client *client)
{
	if (unlikely(!client))
		return;

	l_dhcp6_client_stop(client);

	l_uintset_free(client->request_options);
	l_free(client->duid);
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

LIB_EXPORT bool l_dhcp6_client_add_request_option(struct l_dhcp6_client *client,
						enum l_dhcp6_option option)
{
	if (unlikely(!client))
		return false;

	if (unlikely(client->state != DHCP6_STATE_INIT))
		return false;

	client_enable_option(client, option);

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

	client_duid_generate_addr_plus_time(client);

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
