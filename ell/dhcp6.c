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

#include "ell/random.h"
#include "ell/time.h"
#include "ell/net.h"
#include "ell/timeout.h"
#include "ell/uintset.h"
#include "ell/private.h"
#include "ell/dhcp6-private.h"
#include "ell/dhcp6.h"

#define CLIENT_DEBUG(fmt, args...)					\
	l_util_debug(client->debug_handler, client->debug_data,		\
			"%s:%i " fmt, __func__, __LINE__, ## args)
#define CLIENT_ENTER_STATE(s)						\
	l_util_debug(client->debug_handler, client->debug_data,		\
			"%s:%i Entering state: " #s,			\
			__func__, __LINE__);				\
	client->state = (s)

/*
 * RFC8415: Table 1 - Transmission and Retransmission Parameters
 */
#define SOL_MAX_DELAY	1
#define SOL_TIMEOUT	1
#define SOL_MAX_RT	3600
#define INF_MAX_DELAY	1
#define INF_TIMEOUT	1
#define INF_MAX_RT	3600
#define REQ_MAX_RC	10
#define REQ_TIMEOUT	1
#define REQ_MAX_RT	30
#define REN_TIMEOUT	10
#define REN_MAX_RT	600
#define REL_TIMEOUT	1
#define REL_MAX_RC	4

enum dhcp6_message_type {
	DHCP6_MESSAGE_TYPE_SOLICIT = 1,
	DHCP6_MESSAGE_TYPE_ADVERTISE = 2,
	DHCP6_MESSAGE_TYPE_REQUEST = 3,
	DHCP6_MESSAGE_TYPE_CONFIRM = 4,
	DHCP6_MESSAGE_TYPE_RENEW = 5,
	DHCP6_MESSAGE_TYPE_REBIND = 6,
	DHCP6_MESSAGE_TYPE_REPLY = 7,
	DHCP6_MESSAGE_TYPE_RELEASE = 8,
	DHCP6_MESSAGE_TYPE_DECLINE = 9,
	DHCP6_MESSAGE_TYPE_RECONFIGURE = 10,
	DHCP6_MESSAGE_TYPE_INFORMATION_REQUEST = 11,
	DHCP6_MESSAGE_TYPE_RELAY_FORW = 12,
	DHCP6_MESSAGE_TYPE_RELAY_REPL = 13,
};

struct dhcp6_message_builder {
	uint16_t options_capacity;
	uint16_t options_pos;
	uint16_t option_start;
	struct dhcp6_message *message;
};

static inline size_t next_size(size_t s)
{
	static const size_t mask = (size_t) (-1LL) << 8;
	return (s & mask) + 256;
}

static uint8_t *option_reserve(struct dhcp6_message_builder *builder,
								size_t len)
{
	uint8_t *p;
	size_t options_end;

	options_end = builder->options_pos + len;

	if (options_end > builder->options_capacity) {
		builder->options_capacity =
			next_size(sizeof(struct dhcp6_message) + options_end);
		builder->message =
			l_realloc(builder->message, builder->options_capacity);
	}

	p = builder->message->options + builder->options_pos;
	builder->options_pos = options_end;

	return p;
}

static bool option_start(struct dhcp6_message_builder *builder,
						enum l_dhcp6_option type)
{
	static const size_t option_header_len = 4;

	if (builder->option_start)
		return false;

	builder->option_start = builder->options_pos;
	l_put_be16(type, option_reserve(builder, option_header_len));
	return true;
}

static bool option_finalize(struct dhcp6_message_builder *builder)
{
	uint8_t *p;
	uint16_t len;

	if (!builder->option_start)
		return false;

	len = builder->options_pos - builder->option_start - 4;
	p = builder->message->options + builder->option_start;
	l_put_be16(len, p + 2);
	builder->option_start = 0;

	return true;
}

static struct dhcp6_message_builder *dhcp6_message_builder_new(
						enum dhcp6_message_type type,
						uint32_t transaction_id,
						uint16_t options_capacity)
{
	struct dhcp6_message_builder *builder;

	builder = l_new(struct dhcp6_message_builder, 1);

	builder->message =
		(struct dhcp6_message *) l_new(uint8_t,
						sizeof(struct dhcp6_message) +
						options_capacity);
	builder->message->transaction_id = L_CPU_TO_BE32(transaction_id);
	builder->message->msg_type = type;
	builder->options_capacity = options_capacity;

	return builder;
}

static struct dhcp6_message *dhcp6_message_builder_free(
					struct dhcp6_message_builder *builder,
					bool free_message, size_t *out_size)
{
	struct dhcp6_message *ret;

	if (free_message) {
		memset(builder->message, 0,
			sizeof(struct dhcp6_message) + builder->options_pos);
		l_free(builder->message);
		builder->message = NULL;
	}

	ret = builder->message;

	if (out_size)
		*out_size = sizeof(struct dhcp6_message) + builder->options_pos;

	l_free(builder);

	return ret;
}

static void option_append_client_id(struct dhcp6_message_builder *builder,
					const struct duid *duid,
					uint16_t duid_len)
{
	option_start(builder, L_DHCP6_OPTION_CLIENT_ID);
	memcpy(option_reserve(builder, duid_len), duid, duid_len);
	option_finalize(builder);
}

static void option_append_server_id(struct dhcp6_message_builder *builder,
					const uint8_t *duid,
					uint16_t duid_len)
{
	option_start(builder, L_DHCP6_OPTION_SERVER_ID);
	memcpy(option_reserve(builder, duid_len), duid, duid_len);
	option_finalize(builder);
}

static void option_append_elapsed_time(struct dhcp6_message_builder *builder,
					uint64_t transaction_start_t)
{
	uint16_t elapsed_time;
	uint64_t time_diff;

	if (!transaction_start_t) {
		/*
		 * Field is set to 0 in the first message in the message
		 * exchange.
		 */
		elapsed_time = 0;
		goto done;
	}

	time_diff = l_time_now() - transaction_start_t;

	if (time_diff < UINT16_MAX * L_USEC_PER_MSEC * 10)
		elapsed_time = l_time_to_msecs(time_diff) / 10;
	else
		elapsed_time = UINT16_MAX;

done:
	option_start(builder, L_DHCP6_OPTION_ELAPSED_TIME);
	l_put_be16(elapsed_time, option_reserve(builder, 2));
	option_finalize(builder);
}

static void option_append_ia_na(struct dhcp6_message_builder *builder)
{
	option_start(builder, L_DHCP6_OPTION_IA_NA);

	l_put_be32(0, option_reserve(builder, 4));
	l_put_be32(0, option_reserve(builder, 4));
	l_put_be32(0, option_reserve(builder, 4));

	option_finalize(builder);
}

static void option_append_ia_pd(struct dhcp6_message_builder *builder)
{
	option_start(builder, L_DHCP6_OPTION_IA_PD);

	l_put_be32(0, option_reserve(builder, 4));
	l_put_be32(0, option_reserve(builder, 4));
	l_put_be32(0, option_reserve(builder, 4));

	option_finalize(builder);
}

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

	uint32_t transaction_id;
	uint64_t transaction_start_t;

	struct duid *duid;
	uint16_t duid_len;

	struct l_uintset *request_options;

	uint32_t ifindex;

	struct dhcp6_transport *transport;

	uint64_t attempt_delay;
	uint8_t attempt;

	struct l_timeout *timeout_send;
	struct l_dhcp6_lease *lease;

	l_dhcp6_client_event_cb_t event_handler;
	void *event_data;
	l_dhcp6_destroy_cb_t event_destroy;

	uint8_t addr[6];
	uint8_t addr_len;
	uint8_t addr_type;

	l_dhcp6_debug_cb_t debug_handler;
	l_dhcp6_destroy_cb_t debug_destroy;
	void *debug_data;

	bool stateless : 1;

	uint8_t ia_to_request;
};

static void request_options_foreach(uint32_t opt, void *user_data)
{
	struct dhcp6_message_builder *builder = user_data;

	l_put_be16(opt, option_reserve(builder, 2));
}

static void option_append_option_request(struct dhcp6_message_builder *builder,
					const struct l_uintset *request_options,
					enum dhcp6_state state)
{
	option_start(builder, L_DHCP6_OPTION_REQUEST_OPTION);

	switch (state) {
	case DHCP6_STATE_SOLICITING:
		l_put_be16(L_DHCP6_OPTION_SOL_MAX_RT,
						option_reserve(builder, 2));
		break;
	case DHCP6_STATE_REQUESTING_INFORMATION:
		l_put_be16(L_DHCP6_OPTION_INF_RT, option_reserve(builder, 2));
		l_put_be16(L_DHCP6_OPTION_INF_MAX_RT,
						option_reserve(builder, 2));
		break;
	case DHCP6_STATE_INIT:
	case DHCP6_STATE_REQUESTING:
	case DHCP6_STATE_RENEWING:
	case DHCP6_STATE_RELEASING:
		break;
	}

	l_uintset_foreach((void *) request_options, request_options_foreach,
								builder);
	option_finalize(builder);
}

static void option_append_reconfigure_accept(
					struct dhcp6_message_builder *builder)
{
	option_start(builder, L_DHCP6_OPTION_RECONF_ACCEPT);
	option_finalize(builder);
}

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

static int dhcp6_client_send_solicit(struct l_dhcp6_client *client)
{
	static const struct in6_addr all_nodes = DHCP6_ADDR_LINKLOCAL_ALL_NODES;
	struct dhcp6_message_builder *builder;
	L_AUTO_FREE_VAR(struct dhcp6_message *, solicit);
	size_t solicit_len;
	int error;

	CLIENT_DEBUG("");

	builder = dhcp6_message_builder_new(DHCP6_MESSAGE_TYPE_SOLICIT,
						client->transaction_id, 128);

	option_append_client_id(builder, client->duid, client->duid_len);
	option_append_elapsed_time(builder, client->transaction_start_t);

	if (client->ia_to_request & DHCP6_LEASE_TYPE_IA_NA)
		option_append_ia_na(builder);

	if (client->ia_to_request & DHCP6_LEASE_TYPE_IA_PD)
		option_append_ia_pd(builder);

	option_append_option_request(builder, client->request_options,
						DHCP6_STATE_SOLICITING);

	solicit = dhcp6_message_builder_free(builder, false, &solicit_len);

	error = client->transport->send(client->transport, &all_nodes,
							solicit, solicit_len);
	return error;
}

static int dhcp6_client_send_request(struct l_dhcp6_client *client)
{
	static const struct in6_addr all_nodes = DHCP6_ADDR_LINKLOCAL_ALL_NODES;
	struct dhcp6_message_builder *builder;
	L_AUTO_FREE_VAR(struct dhcp6_message *, request);
	size_t request_len;
	int error;

	CLIENT_DEBUG("");

	builder = dhcp6_message_builder_new(DHCP6_MESSAGE_TYPE_REQUEST,
						client->transaction_id, 128);

	option_append_server_id(builder, client->lease->server_id,
						client->lease->server_id_len);
	option_append_client_id(builder, client->duid, client->duid_len);
	option_append_elapsed_time(builder, client->transaction_start_t);

	/* Request the SOL_MAX_RT option and other options. */
	option_append_option_request(builder, client->request_options,
						DHCP6_STATE_SOLICITING);

	request = dhcp6_message_builder_free(builder, false, &request_len);

	error = client->transport->send(client->transport, &all_nodes,
							request, request_len);

	return error;
}

static int dhcp6_client_send_information_request(struct l_dhcp6_client *client)
{
	static const struct in6_addr all_nodes = DHCP6_ADDR_LINKLOCAL_ALL_NODES;
	struct dhcp6_message_builder *builder;
	L_AUTO_FREE_VAR(struct dhcp6_message *, information_request);
	size_t information_request_len;
	int error;

	CLIENT_DEBUG("");

	builder = dhcp6_message_builder_new(
					DHCP6_MESSAGE_TYPE_INFORMATION_REQUEST,
					client->transaction_id, 128);

	option_append_elapsed_time(builder, client->transaction_start_t);
	option_append_option_request(builder, client->request_options,
					DHCP6_STATE_REQUESTING_INFORMATION);
	option_append_reconfigure_accept(builder);

	information_request = dhcp6_message_builder_free(builder, false,
						&information_request_len);

	error = client->transport->send(client->transport, &all_nodes,
						information_request,
						information_request_len);
	return error;
}

static int dhcp6_client_send_renew(struct l_dhcp6_client *client)
{
	return 0;
}

static int dhcp6_client_send_release(struct l_dhcp6_client *client)
{
	return 0;
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

static inline bool verify_duid(struct l_dhcp6_client *client,
				const uint8_t *duid, uint16_t duid_len)
{
	if ((client->duid_len != duid_len) || memcmp(client->duid, duid,
								duid_len))
		return false;

	return true;
}

static int dhcp6_client_receive_advertise(struct l_dhcp6_client *client,
					const struct dhcp6_message *advertise,
					size_t len)
{
	struct dhcp6_option_iter iter;
	uint16_t opt_type;
	uint16_t opt_len;
	const void *opt_value;
	bool duid_verified = false;

	if (!_dhcp6_option_iter_init(&iter, advertise, len))
		return -EBADMSG;

	while (_dhcp6_option_iter_next(&iter, &opt_type,
						&opt_len, &opt_value)) {
		switch (opt_type) {
		case L_DHCP6_OPTION_CLIENT_ID:
			if (duid_verified) {
				CLIENT_DEBUG("Advertise message has multiple "
						"Client Identifier options.");

				return -EINVAL;
			}

			if (!verify_duid(client, opt_value, opt_len)) {
				CLIENT_DEBUG("Advertise message has invalid "
						"Client Identifier.");
				return -EINVAL;
			}

			duid_verified = true;
			break;

		case L_DHCP6_OPTION_SERVER_ID:
			break;
		}
	}

	return 0;
}

static int dhcp6_client_receive_reply(struct l_dhcp6_client *client,
					const struct dhcp6_message *reply,
					size_t len)
{
	struct dhcp6_option_iter iter;
	uint16_t opt_type;
	uint16_t opt_len;
	const void *opt_value;
	bool duid_verified = false;

	if (!_dhcp6_option_iter_init(&iter, reply, len))
		return -EBADMSG;

	while (_dhcp6_option_iter_next(&iter, &opt_type,
						&opt_len, &opt_value)) {
		switch (opt_type) {
		case L_DHCP6_OPTION_CLIENT_ID:
			if (duid_verified) {
				CLIENT_DEBUG("Reply message has multiple "
						"Client Identifier options.");
				return -EINVAL;
			}

			if (!verify_duid(client, opt_value, opt_len)) {
				CLIENT_DEBUG("Reply message has an invalid "
						"Client Identifier option.");
				return -EINVAL;
			}

			duid_verified = true;
			break;

		case L_DHCP6_OPTION_SERVER_ID:
			break;
		}
	}

	return 0;
}

static void dhcp6_client_rx_message(const void *data, size_t len,
								void *userdata)
{
	struct l_dhcp6_client *client = userdata;
	const struct dhcp6_message *message = data;

	CLIENT_DEBUG("");

	if (len < sizeof(struct dhcp6_message))
		return;

	switch (message->msg_type) {
        case DHCP6_MESSAGE_TYPE_ADVERTISE:
        case DHCP6_MESSAGE_TYPE_REPLY:
        case DHCP6_MESSAGE_TYPE_RECONFIGURE:
                break;
	default:
		/* Discard invalid message types */
		return;
	}

	if ((message->transaction_id & L_CPU_TO_BE32(0x00FFFFFFU)) !=
					L_CPU_TO_BE32(client->transaction_id))
		return;

	switch (client->state) {
	case DHCP6_STATE_INIT:
		return;
	case DHCP6_STATE_SOLICITING:
		if (message->msg_type != DHCP6_MESSAGE_TYPE_ADVERTISE)
			return;
	
		if (dhcp6_client_receive_advertise(client, message, len) < 0)
			return;

		/*
		 * Continue collecting advertisements for the duration
		 * of RT
		 */
		return;

	case DHCP6_STATE_REQUESTING_INFORMATION:
		if (message->msg_type != DHCP6_MESSAGE_TYPE_REPLY)
			return;

		if (dhcp6_client_receive_reply(client, message, len) < 0)
			return;

		break;
	case DHCP6_STATE_REQUESTING:
		if (message->msg_type != DHCP6_MESSAGE_TYPE_REPLY)
			return;

		if (dhcp6_client_receive_reply(client, message, len) < 0)
			return;

		client->attempt = 0;
		break;
	case DHCP6_STATE_RENEWING:
		if (message->msg_type != DHCP6_MESSAGE_TYPE_REPLY)
			return;

		break;
	case DHCP6_STATE_RELEASING:
		if (message->msg_type != DHCP6_MESSAGE_TYPE_REPLY)
			return;

		client->attempt = 0;
		break;
	}

	client->transaction_id = l_getrandom_uint32() & 0x00FFFFFFU;
}

static uint64_t fuzz_msecs(uint64_t ms)
{
        return ms - ms / 10 +
			(l_getrandom_uint32() % (2 * L_MSEC_PER_SEC)) *
						ms / 10 / L_MSEC_PER_SEC;
}

static void set_retransmission_delay(struct l_dhcp6_client *client,
					uint32_t irt_sec, uint32_t mrt_sec,
					uint8_t mrc)
{
	uint64_t irt_ms;
	uint64_t mrt_ms;

	if (mrc && mrc < client->attempt)
		return;

	/* TODO add check for duration */

	irt_ms = irt_sec * L_MSEC_PER_SEC;
	mrt_ms = mrt_sec * L_MSEC_PER_SEC;

	if (!client->attempt_delay) {
		client->attempt_delay = fuzz_msecs(irt_ms);

		if (client->state == DHCP6_STATE_SOLICITING)
			client->attempt_delay += irt_ms / 10;
	} else {
		if (mrt_ms && client->attempt_delay > mrt_ms)
			client->attempt_delay = fuzz_msecs(mrt_ms);
		else
			client->attempt_delay +=
					fuzz_msecs(client->attempt_delay);
	}

	l_timeout_modify_ms(client->timeout_send, client->attempt_delay);
}

static void dhcp6_client_timeout_send(struct l_timeout *timeout,
								void *user_data)
{
	struct l_dhcp6_client *client = user_data;

	CLIENT_DEBUG("");

	switch (client->state) {
	case DHCP6_STATE_INIT:
		return;
	case DHCP6_STATE_SOLICITING:
		if (dhcp6_client_send_solicit(client) < 0)
			goto error;

		set_retransmission_delay(client, SOL_TIMEOUT, SOL_MAX_RT, 0);
		break;
	case DHCP6_STATE_REQUESTING_INFORMATION:
		if (dhcp6_client_send_information_request(client) < 0)
			goto error;

		set_retransmission_delay(client, INF_TIMEOUT, INF_MAX_RT, 0);
		break;
	case DHCP6_STATE_REQUESTING:
		if (dhcp6_client_send_request(client) < 0)
			goto error;

		set_retransmission_delay(client, REQ_TIMEOUT, REQ_MAX_RT,
								REQ_MAX_RC);
		client->attempt += 1;

		break;
	case DHCP6_STATE_RENEWING:
		if (dhcp6_client_send_renew(client) < 0)
			goto error;

		set_retransmission_delay(client, REN_TIMEOUT, REN_MAX_RT, 0);
		break;
	case DHCP6_STATE_RELEASING:
		if (dhcp6_client_send_release(client) < 0)
			goto error;

		set_retransmission_delay(client, REL_TIMEOUT, 0, REL_MAX_RC);
		client->attempt += 1;

		break;
	}

	if (!client->transaction_start_t)
		/* Set after the first successfully sent message. */
		client->transaction_start_t = l_time_now();

	return;

error:
	l_dhcp6_client_stop(client);
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

	if (client->event_destroy)
		client->event_destroy(client->event_data);

	_dhcp6_transport_free(client->transport);
	l_uintset_free(client->request_options);
	l_free(client->duid);
	l_timeout_remove(client->timeout_send);

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

LIB_EXPORT bool l_dhcp6_client_set_event_handler(struct l_dhcp6_client *client,
					l_dhcp6_client_event_cb_t handler,
					void *userdata,
					l_dhcp6_destroy_cb_t destroy)
{
	if (unlikely(!client))
		return false;

	if (client->event_destroy)
		client->event_destroy(client->event_data);

	client->event_handler = handler;
	client->event_data = userdata;
	client->event_destroy = destroy;

	return true;
}

LIB_EXPORT bool l_dhcp6_client_set_stateless(struct l_dhcp6_client *client,
								bool stateless)
{
	if (unlikely(!client))
		return false;

	if (unlikely(client->state != DHCP6_STATE_INIT))
		return false;

	client->stateless = stateless;

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

static uint64_t pick_delay_interval(uint32_t min_secs, uint32_t max_secs)
{
	uint64_t min_ms = min_secs * 1000ULL;
	uint64_t max_ms = max_secs * 1000ULL;

	return l_getrandom_uint32() % (max_ms + 1 - min_ms) + min_ms;
}

LIB_EXPORT bool l_dhcp6_client_start(struct l_dhcp6_client *client)
{
	uint32_t delay;

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

	if (!client->transport) {
		client->transport =
			_dhcp6_default_transport_new(client->ifindex,
							DHCP6_PORT_CLIENT);

		if (!client->transport)
			return false;
	}

	if (client->transport->open)
		if (client->transport->open(client->transport) < 0)
			return false;

	_dhcp6_transport_set_rx_callback(client->transport,
						dhcp6_client_rx_message,
						client);

	client->transaction_id = l_getrandom_uint32() & 0x00FFFFFFU;

	if (client->stateless) {
		CLIENT_ENTER_STATE(DHCP6_STATE_REQUESTING_INFORMATION);
		delay = pick_delay_interval(0, INF_MAX_DELAY);
	} else {
		CLIENT_ENTER_STATE(DHCP6_STATE_SOLICITING);
		delay = pick_delay_interval(0, SOL_MAX_DELAY);

		client->ia_to_request = DHCP6_LEASE_TYPE_IA_NA |
							DHCP6_LEASE_TYPE_IA_PD;
	}

	client->timeout_send = l_timeout_create_ms(delay,
						dhcp6_client_timeout_send,
						client, NULL);

	return true;
}

LIB_EXPORT bool l_dhcp6_client_stop(struct l_dhcp6_client *client)
{
	if (unlikely(!client))
		return false;

	l_timeout_remove(client->timeout_send);
	client->timeout_send = NULL;

	if (client->transport && client->transport->close)
		client->transport->close(client->transport);

	client->transaction_start_t = 0;
	CLIENT_ENTER_STATE(DHCP6_STATE_INIT);

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
