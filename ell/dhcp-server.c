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

#include <linux/types.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <limits.h>

#include "private.h"
#include "time.h"
#include "net.h"
#include "dhcp.h"
#include "dhcp-private.h"
#include "queue.h"
#include "useful.h"
#include "strv.h"
#include "timeout.h"
#include "acd.h"
#include "log.h"
#include "util.h"

/* 8 hours */
#define DEFAULT_DHCP_LEASE_SEC (8*60*60)

/* 5 minutes  */
#define OFFER_TIME (5*60)

#define MAX_EXPIRED_LEASES 50

static const uint8_t MAC_BCAST_ADDR[ETH_ALEN] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

struct l_dhcp_server {
	bool started;
	int ifindex;
	char *ifname;
	uint32_t start_ip;
	uint32_t end_ip;
	uint32_t address;
	uint32_t netmask;
	uint32_t gateway;
	uint32_t *dns_list;
	uint32_t lease_seconds;
	unsigned int max_expired;

	struct l_queue *lease_list;
	struct l_queue *expired_list;

	/* Next lease expiring */
	struct l_timeout *next_expire;

	l_dhcp_debug_cb_t debug_handler;
	void *debug_data;
	l_dhcp_destroy_cb_t debug_destroy;

	l_dhcp_server_event_cb_t event_handler;
	void *user_data;
	l_dhcp_destroy_cb_t event_destroy;

	struct dhcp_transport *transport;

	struct l_acd *acd;

	bool authoritative : 1;
	bool rapid_commit : 1;
};

#define MAC "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_STR(a) a[0], a[1], a[2], a[3], a[4], a[5]

#define NIPQUAD_FMT "%u.%u.%u.%u"
#define NIPQUAD(u32_ip)	((unsigned char *) &u32_ip)[0], \
			((unsigned char *) &u32_ip)[1], \
			((unsigned char *) &u32_ip)[2], \
			((unsigned char *) &u32_ip)[3]

#define SERVER_DEBUG(fmt, args...)					\
	l_util_debug(server->debug_handler, server->debug_data,		\
			"%s:%i " fmt, __func__, __LINE__, ## args)

static uint64_t get_lease_expiry_time(const struct l_dhcp_lease *lease)
{
	return lease->bound_time + lease->lifetime * L_USEC_PER_SEC;
}

static bool is_expired_lease(const struct l_dhcp_lease *lease)
{
	return !l_time_after(get_lease_expiry_time(lease), l_time_now());
}

static bool match_lease_client_id(const void *data, const void *user_data)
{
	const struct l_dhcp_lease *lease = data;
	const uint8_t *client_id = user_data;

	return lease->client_id &&
		!memcmp(lease->client_id, client_id, client_id[0] + 1);
}

static bool match_lease_mac(const void *data, const void *user_data)
{
	const struct l_dhcp_lease *lease = data;
	const uint8_t *mac = user_data;

	return !memcmp(lease->mac, mac, 6);
}

static bool match_lease_ip(const void *data, const void *user_data)
{
	const struct l_dhcp_lease *lease = data;

	return lease->address == L_PTR_TO_UINT(user_data);
}

static struct l_dhcp_lease *find_lease_by_ip(struct l_queue *lease_list,
						uint32_t nip)
{
	return l_queue_find(lease_list, match_lease_ip, L_UINT_TO_PTR(nip));
}

static struct l_dhcp_lease *find_lease_by_id(struct l_queue *lease_list,
						const uint8_t *client_id,
						const uint8_t *mac)
{
	if (client_id)
		return l_queue_find(lease_list, match_lease_client_id,
					client_id);

	return l_queue_find(lease_list, match_lease_mac, mac);
}

static struct l_dhcp_lease *find_lease_by_id_and_ip(struct l_queue *lease_list,
						const uint8_t *client_id,
						const uint8_t *mac,
						uint32_t ip)
{
	struct l_dhcp_lease *lease = find_lease_by_ip(lease_list, ip);

	if (!lease)
		return NULL;

	if (client_id) {
		if (!match_lease_client_id(lease, client_id))
			return NULL;
	} else {
		if (!match_lease_mac(lease, mac))
			return NULL;
	}

	return lease;
}

/* Clear the old lease and create the new one */
static int get_lease(struct l_dhcp_server *server, uint32_t yiaddr,
			const uint8_t *client_id, const uint8_t *mac,
			struct l_dhcp_lease **lease_out)
{
	struct l_dhcp_lease *lease;

	if (yiaddr == 0)
		return -ENXIO;

	if (ntohl(yiaddr) < server->start_ip)
		return -ENXIO;

	if (ntohl(yiaddr) > server->end_ip)
		return -ENXIO;

	if (l_memeq(mac, ETH_ALEN, 0xff))
		return -ENXIO;

	if (l_memeqzero(mac, ETH_ALEN))
		return -ENXIO;

	lease = find_lease_by_ip(server->lease_list, yiaddr);
	if (lease) {
		l_queue_remove(server->lease_list, lease);
		*lease_out = lease;
		return 0;
	}

	lease = find_lease_by_ip(server->expired_list, yiaddr);
	if (lease && lease->address == yiaddr) {
		l_queue_remove(server->expired_list, lease);
		*lease_out = lease;
		return 0;
	}

	*lease_out = l_new(struct l_dhcp_lease, 1);

	return 0;
}

static int compare_expiry_or_offering(const void *a, const void *b,
					void *user_data)
{
	const struct l_dhcp_lease *lease1 = a;
	const struct l_dhcp_lease *lease2 = b;
	int64_t diff;

	/*
	 * Ensures offered but not active leases stay at the head of the queue.
	 * This lets us peek at the tail to find the next expiring (active)
	 */
	if (lease1->offering)
		return 1;

	diff = (int64_t) lease2->bound_time - lease1->bound_time +
		((int64_t) lease2->lifetime - lease1->lifetime) * L_USEC_PER_SEC;
	return diff >= 0 ? diff > 0 ? 1 : 0 : -1;
}

static void lease_expired_cb(struct l_timeout *timeout, void *user_data);

static void set_next_expire_timer(struct l_dhcp_server *server,
					struct l_dhcp_lease *expired)
{
	struct l_dhcp_lease *next;
	uint64_t expiry;
	uint64_t now;
	uint64_t next_timeout;

	/*
	 * If this is an expiring lease put it into the expired queue, removing
	 * a lease if we have reached the max
	 */
	if (expired) {
		l_queue_remove(server->lease_list, expired);

		if (!expired->offering) {
			if (l_queue_length(server->expired_list) >
					server->max_expired)
				_dhcp_lease_free(l_queue_pop_head(
							server->expired_list));

			l_queue_push_tail(server->expired_list, expired);
		} else
			_dhcp_lease_free(expired);
	}

	next = l_queue_peek_tail(server->lease_list);
	if (!next) {
		l_timeout_remove(server->next_expire);
		server->next_expire = NULL;
		return;
	}

	expiry = get_lease_expiry_time(next);
	now = l_time_now();
	next_timeout = l_time_after(expiry, now) ?
		l_time_to_msecs(expiry - now) : 0;

	if (server->next_expire)
		l_timeout_modify_ms(server->next_expire, next_timeout ?: 1);
	else
		server->next_expire = l_timeout_create(next_timeout ?: 1,
							lease_expired_cb,
							server, NULL);
}

static void lease_expired_cb(struct l_timeout *timeout, void *user_data)
{
	struct l_dhcp_server *server = user_data;
	struct l_dhcp_lease *lease = l_queue_peek_tail(server->lease_list);

	if (!lease->offering && server->event_handler)
		server->event_handler(server, L_DHCP_SERVER_EVENT_LEASE_EXPIRED,
					server->user_data, lease);

	set_next_expire_timer(server, lease);
}

static struct l_dhcp_lease *add_lease(struct l_dhcp_server *server,
					bool offering, const uint8_t *client_id,
					const uint8_t *chaddr, uint32_t yiaddr,
					uint64_t timestamp)
{
	struct l_dhcp_lease *lease = NULL;
	int ret;

	ret = get_lease(server, yiaddr, client_id, chaddr, &lease);
	if (ret != 0)
		return NULL;

	l_free(lease->dns);
	l_free(lease->client_id);
	memset(lease, 0, sizeof(*lease));

	memcpy(lease->mac, chaddr, ETH_ALEN);
	lease->address = yiaddr;
	lease->subnet_mask = server->netmask;
	lease->router = server->gateway;

	if (server->dns_list) {
		unsigned int i;

		for (i = 0; server->dns_list[i]; i++);
		lease->dns = l_memdup(server->dns_list, (i + 1) * 4);
	}

	if (client_id)
		lease->client_id = l_memdup(client_id, client_id[0] + 1);

	lease->offering = offering;
	lease->bound_time = timestamp;

	if (!offering) {
		lease->lifetime = server->lease_seconds;

		/*
		 * Insert into queue by lifetime (skipping any offered leases
		 * at the head)
		 */
		l_queue_insert(server->lease_list, lease,
					compare_expiry_or_offering, NULL);
	} else {
		lease->lifetime = OFFER_TIME;
		/* Push offered leases to head, active leases after those */
		l_queue_push_head(server->lease_list, lease);
	}

	/*
	 * This is a new (or renewed) lease so pass NULL for expired so the
	 * queues are not modified, only the next_expire timer.
	 */
	set_next_expire_timer(server, NULL);

	SERVER_DEBUG("added lease IP "NIPQUAD_FMT " for "MAC " lifetime=%u",
			NIPQUAD(yiaddr), MAC_STR(chaddr),
			server->lease_seconds);

	return lease;
}

static bool remove_lease(struct l_dhcp_server *server,
				struct l_dhcp_lease *lease)
{
	if (!l_queue_remove(server->lease_list, lease))
		return false;

	_dhcp_lease_free(lease);
	set_next_expire_timer(server, NULL);
	return true;
}

static void lease_release(struct l_dhcp_server *server,
			struct l_dhcp_lease *lease)
{
	if (server->event_handler)
		server->event_handler(server, L_DHCP_SERVER_EVENT_LEASE_EXPIRED,
					server->user_data, lease);

	set_next_expire_timer(server, lease);
}

static bool check_requested_ip(struct l_dhcp_server *server,
				uint32_t requested_nip)
{
	struct l_dhcp_lease *lease;

	if (requested_nip == 0)
		return false;

	if (ntohl(requested_nip) < server->start_ip)
		return false;

	if (ntohl(requested_nip) > server->end_ip)
		return false;

	if (requested_nip == server->address)
		return false;

	lease = find_lease_by_ip(server->lease_list, requested_nip);
	if (!lease)
		return true;

	if (!is_expired_lease(lease))
		return false;

	return true;
}

/* Check if the IP is taken; if it is, add it to the lease table */
static bool arp_check(uint32_t ip, const uint8_t *safe_mac)
{
	/* TODO: Add ARP checking */
	return true;
}

static uint32_t find_free_or_expired_ip(struct l_dhcp_server *server,
						const uint8_t *safe_mac)
{
	uint32_t ip_addr;
	struct l_dhcp_lease *lease;

	for (ip_addr = server->start_ip; ip_addr <= server->end_ip; ip_addr++) {
		/* Get IP in network order to return/check for matches */
		uint32_t ip_nl = htonl(ip_addr);

		/* e.g. 192.168.55.0 */
		if ((ip_addr & 0xff) == 0)
			continue;

		/* e.g. 192.168.55.255 */
		if ((ip_addr & 0xff) == 0xff)
			continue;

		if (ip_nl == server->address)
			continue;

		/*
		 * Search both active and expired leases. If this exausts all
		 * IP's in the range pop the expired list (oldest expired lease)
		 * and use that IP. If the expired list is empty we have reached
		 * our maximum number of clients.
		 */
		lease = find_lease_by_ip(server->lease_list, ip_nl);
		if (lease)
			continue;

		lease = find_lease_by_ip(server->expired_list, ip_nl);
		if (lease && memcmp(lease->mac, safe_mac, ETH_ALEN))
			continue;

		if (arp_check(ip_nl, safe_mac))
			return ip_nl;
	}

	lease = l_queue_pop_head(server->expired_list);
	if (!lease)
		return 0;

	ip_addr = lease->address;
	_dhcp_lease_free(lease);
	return ip_addr;
}

static void server_message_init(struct l_dhcp_server *server,
				const struct dhcp_message *client_msg,
				struct dhcp_message *reply)
{
	reply->xid = client_msg->xid;
	memcpy(reply->chaddr, client_msg->chaddr, sizeof(client_msg->chaddr));
	reply->flags = client_msg->flags;
	reply->giaddr = client_msg->giaddr;
	reply->ciaddr = client_msg->ciaddr;
}

static bool server_message_send(struct l_dhcp_server *server,
				struct dhcp_message *reply, size_t len,
				uint8_t type)
{
	uint32_t daddr;
	uint16_t dport;
	const uint8_t *dest_mac;

	/*
	 * RFC2131 Section 4.1: "If the 'giaddr' field in a DHCP message from
	 * a client is non-zero, the server sends any return messages to the
	 * 'DHCP server' port on the BOOTP relay agent whose address appears
	 * in 'giaddr'. If the 'giaddr' field is zero and the 'ciaddr' field
	 * is nonzero, then the server unicasts DHCPOFFER and DHCPACK messages
	 * to the address in 'ciaddr'.  If 'giaddr' is zero and 'ciaddr' is
	 * zero, and the broadcast bit is set, then the server broadcasts
	 * DHCPOFFER and DHCPACK messages to 0xffffffff. If the broadcast bit
	 * is not set and 'giaddr' is zero and 'ciaddr' is zero, then the
	 * server unicasts DHCPOFFER and DHCPACK messages to the client's
	 * hardware address and 'yiaddr' address.  In all cases, when 'giaddr'
	 * is zero, the server broadcasts any DHCPNAK messages to 0xffffffff."
	 *
	 * 4.3.2: "If 'giaddr' is set in the DHCPREQUEST message, the client
	 * is on a different subnet.  The server MUST set the broadcast bit in
	 * the DHCPNAK, so that the relay agent will broadcast the DHCPNAK to
	 * the client, because the client may not have a correct network
	 * address or subnet mask, and the client may not be answering ARP
	 * requests."
	 */
	if (reply->giaddr) {
		dport = DHCP_PORT_SERVER;
		daddr = reply->giaddr;
		dest_mac = reply->chaddr;

		if (type == DHCP_MESSAGE_TYPE_NAK)
			reply->flags |= L_CPU_TO_BE16(DHCP_FLAG_BROADCAST);
	} else {
		dport = DHCP_PORT_CLIENT;

		if (type == DHCP_MESSAGE_TYPE_NAK) {
			daddr = 0xffffffff;
			dest_mac = MAC_BCAST_ADDR;
		} else if (reply->ciaddr) {
			daddr = reply->ciaddr;
			dest_mac = reply->chaddr;
		} else if (L_BE16_TO_CPU(reply->flags) & DHCP_FLAG_BROADCAST) {
			daddr = 0xffffffff;
			dest_mac = MAC_BCAST_ADDR;
		} else {
			daddr = reply->yiaddr;
			dest_mac = reply->chaddr;
		}
	}

	if (server->transport->l2_send(server->transport, server->address,
					DHCP_PORT_SERVER, daddr, dport,
					dest_mac, reply, len) < 0) {
		SERVER_DEBUG("Failed to send %s",
				_dhcp_message_type_to_string(type));
		return false;
	}

	return true;
}

static void add_server_options(struct l_dhcp_server *server,
				struct dhcp_message_builder *builder)
{
	int i;

	if (server->netmask)
		_dhcp_message_builder_append(builder, L_DHCP_OPTION_SUBNET_MASK,
						4, &server->netmask);

	if (server->gateway)
		_dhcp_message_builder_append(builder, L_DHCP_OPTION_ROUTER,
						4, &server->gateway);

	if (server->dns_list) {
		for (i = 0; server->dns_list[i]; i++);

		_dhcp_message_builder_append(builder,
					L_DHCP_OPTION_DOMAIN_NAME_SERVER,
					i * 4, server->dns_list);
	}
}

/* Copy the client identifier option from the client message per RFC6842 */
static void copy_client_id(struct dhcp_message_builder *builder,
				const uint8_t *client_id)
{
	if (client_id)
		_dhcp_message_builder_append(builder,
						DHCP_OPTION_CLIENT_IDENTIFIER,
						client_id[0], client_id + 1);
}

static void send_offer(struct l_dhcp_server *server,
			const struct dhcp_message *client_msg,
			struct l_dhcp_lease *lease, uint32_t requested_ip,
			const uint8_t *client_id, uint64_t timestamp)
{
	struct dhcp_message_builder builder;
	size_t len = sizeof(struct dhcp_message) + DHCP_MIN_OPTIONS_SIZE;
	L_AUTO_FREE_VAR(struct dhcp_message *, reply);
	uint32_t lease_time = L_CPU_TO_BE32(server->lease_seconds);

	reply = (struct dhcp_message *) l_new(uint8_t, len);

	if (lease)
		reply->yiaddr = lease->address;
	else if (check_requested_ip(server, requested_ip))
		reply->yiaddr = requested_ip;
	else
		reply->yiaddr = find_free_or_expired_ip(server,
							client_msg->chaddr);

	if (!reply->yiaddr) {
		SERVER_DEBUG("No free IP addresses, OFFER abandoned");
		return;
	}

	lease = add_lease(server, true, client_id, client_msg->chaddr,
				reply->yiaddr, timestamp);
	if (!lease) {
		SERVER_DEBUG("add_lease() failed");
		return;
	}

	server_message_init(server, client_msg, reply);

	_dhcp_message_builder_init(&builder, reply, len,
					DHCP_MESSAGE_TYPE_OFFER);

	_dhcp_message_builder_append(&builder,
					L_DHCP_OPTION_IP_ADDRESS_LEASE_TIME,
					4, &lease_time);

	_dhcp_message_builder_append(&builder, L_DHCP_OPTION_SERVER_IDENTIFIER,
					4, &server->address);

	add_server_options(server, &builder);
	copy_client_id(&builder, client_id);

	_dhcp_message_builder_finalize(&builder, &len);

	SERVER_DEBUG("Sending OFFER of "NIPQUAD_FMT " to "MAC,
			NIPQUAD(reply->yiaddr),	MAC_STR(reply->chaddr));

	server_message_send(server, reply, len, DHCP_MESSAGE_TYPE_OFFER);
}

static void send_inform(struct l_dhcp_server *server,
				const struct dhcp_message *client_msg,
				const uint8_t *client_id)
{
	struct dhcp_message_builder builder;
	size_t len = sizeof(struct dhcp_message) + DHCP_MIN_OPTIONS_SIZE;
	L_AUTO_FREE_VAR(struct dhcp_message *, reply);

	reply = (struct dhcp_message *) l_new(uint8_t, len);

	server_message_init(server, client_msg, reply);

	_dhcp_message_builder_init(&builder, reply, len, DHCP_MESSAGE_TYPE_ACK);

	add_server_options(server, &builder);
	copy_client_id(&builder, client_id);

	_dhcp_message_builder_finalize(&builder, &len);

	server_message_send(server, reply, len, DHCP_MESSAGE_TYPE_INFORM);
}

static void send_nak(struct l_dhcp_server *server,
			const struct dhcp_message *client_msg,
			const uint8_t *client_id)
{
	struct dhcp_message_builder builder;
	size_t len = sizeof(struct dhcp_message) + DHCP_MIN_OPTIONS_SIZE;
	L_AUTO_FREE_VAR(struct dhcp_message *, reply);

	reply = (struct dhcp_message *) l_new(uint8_t, len);

	server_message_init(server, client_msg, reply);

	_dhcp_message_builder_init(&builder, reply, len, DHCP_MESSAGE_TYPE_NAK);
	copy_client_id(&builder, client_id);
	_dhcp_message_builder_finalize(&builder, &len);

	server_message_send(server, reply, len, DHCP_MESSAGE_TYPE_NAK);
}

static void send_ack(struct l_dhcp_server *server,
			const struct dhcp_message *client_msg,
			struct l_dhcp_lease *lease,
			bool rapid_commit,
			uint64_t timestamp)
{
	struct dhcp_message_builder builder;
	size_t len = sizeof(struct dhcp_message) + DHCP_MIN_OPTIONS_SIZE;
	L_AUTO_FREE_VAR(struct dhcp_message *, reply);
	uint32_t lease_time = L_CPU_TO_BE32(server->lease_seconds);
	L_AUTO_FREE_VAR(uint8_t *, client_id) = l_steal_ptr(lease->client_id);

	reply = (struct dhcp_message *) l_new(uint8_t, len);

	server_message_init(server, client_msg, reply);

	_dhcp_message_builder_init(&builder, reply, len, DHCP_MESSAGE_TYPE_ACK);

	reply->yiaddr = lease->address;

	_dhcp_message_builder_append(&builder,
					L_DHCP_OPTION_IP_ADDRESS_LEASE_TIME,
					4, &lease_time);

	add_server_options(server, &builder);
	copy_client_id(&builder, client_id);

	_dhcp_message_builder_append(&builder, L_DHCP_OPTION_SERVER_IDENTIFIER,
					4, &server->address);

	if (rapid_commit)
		_dhcp_message_builder_append(&builder, DHCP_OPTION_RAPID_COMMIT,
						0, "");

	_dhcp_message_builder_finalize(&builder, &len);

	SERVER_DEBUG("Sending ACK to "NIPQUAD_FMT, NIPQUAD(reply->yiaddr));

	if (!server_message_send(server, reply, len, DHCP_MESSAGE_TYPE_ACK))
		return;

	lease = add_lease(server, false, client_id, reply->chaddr,
				reply->yiaddr, timestamp);

	if (server->event_handler)
		server->event_handler(server, L_DHCP_SERVER_EVENT_NEW_LEASE,
					server->user_data, lease);
}

static void listener_event(const void *data, size_t len, void *user_data,
				const uint8_t *saddr, uint64_t timestamp)
{
	struct l_dhcp_server *server = user_data;
	const struct dhcp_message *message = data;
	struct dhcp_message_iter iter;
	uint8_t t, l;
	const void *v;
	struct l_dhcp_lease *lease;
	uint8_t type = 0;
	bool server_id_opt = false;
	bool server_id_match = true;
	uint32_t requested_ip_opt = 0;
	L_AUTO_FREE_VAR(uint8_t *, client_id_opt) = NULL;
	bool rapid_commit_opt = false;

	SERVER_DEBUG("");

	if (saddr && memcmp(saddr, message->chaddr, ETH_ALEN))
		return;

	if (!_dhcp_message_iter_init(&iter, message, len))
		return;

	while (_dhcp_message_iter_next(&iter, &t, &l, &v)) {
		switch (t) {
		case DHCP_OPTION_MESSAGE_TYPE:
			if (l == 1)
				type = l_get_u8(v);

			break;
		case L_DHCP_OPTION_SERVER_IDENTIFIER:
			if (l != 4)
				break;

			server_id_opt = true;
			server_id_match = (l_get_u32(v) == server->address);
			break;
		case L_DHCP_OPTION_REQUESTED_IP_ADDRESS:
			if (l == 4)
				requested_ip_opt = l_get_u32(v);

			break;
		case DHCP_OPTION_CLIENT_IDENTIFIER:
			if (l < 1 || l > 253 || client_id_opt)
				break;

			client_id_opt = l_malloc(l + 1);
			client_id_opt[0] = l;
			memcpy(client_id_opt + 1, v, l);
			break;
		case DHCP_OPTION_RAPID_COMMIT:
			rapid_commit_opt = true;
			break;
		}
	}

	if (type == 0)
		return;

	if (requested_ip_opt)
		lease = find_lease_by_id_and_ip(server->lease_list,
						client_id_opt, message->chaddr,
						requested_ip_opt);

	if (!requested_ip_opt || !lease)
		lease = find_lease_by_id(server->lease_list, client_id_opt,
						message->chaddr);

	if (!lease)
		SERVER_DEBUG("No lease found for "MAC,
					MAC_STR(message->chaddr));

	switch (type) {
	case DHCP_MESSAGE_TYPE_DISCOVER:
		SERVER_DEBUG("Received DISCOVER, requested IP "NIPQUAD_FMT,
					NIPQUAD(requested_ip_opt));

		if (!server_id_match)
			break;

		if (rapid_commit_opt && server->rapid_commit) {
			lease = l_dhcp_server_discover(server, requested_ip_opt,
							client_id_opt,
							message->chaddr);
			if (!lease) {
				send_nak(server, message, client_id_opt);
				break;
			}

			send_ack(server, message, lease, rapid_commit_opt,
					timestamp);
			break;
		}

		send_offer(server, message, lease, requested_ip_opt,
				client_id_opt, timestamp);
		break;
	case DHCP_MESSAGE_TYPE_REQUEST:
		SERVER_DEBUG("Received REQUEST, requested IP "NIPQUAD_FMT,
				NIPQUAD(requested_ip_opt));

		/*
		 * RFC2131 Section 3.5: "Those servers not selected by the
		 * DHCPREQUEST message use the message as notification that
		 * the client has declined that server's offer."
		 */
		if (!server_id_match) {
			if (server->authoritative) {
				send_nak(server, message, client_id_opt);
				break;
			}

			if (!lease || !lease->offering)
				break;

			remove_lease(server, lease);
			break;
		}

		/*
		 * As an extension, check if we have an expired lease matching
		 * the requested IP and the client ID/mac and if so, allow the
		 * lease to be re-activated.
		 */
		if (!lease && requested_ip_opt)
			lease = find_lease_by_id_and_ip(server->expired_list,
							client_id_opt,
							message->chaddr,
							requested_ip_opt);

		/*
		 * RFC2131 Section 3.5: "If the selected server is unable to
		 * satisfy the DHCPREQUEST message (...), the server SHOULD
		 * respond with a DHCPNAK message."
		 *
		 * But:
		 * 4.3.2: "If the DHCP server has no record of this client,
		 * then it MUST remain silent (...)"
		 */
		if (!lease) {
			if (server_id_opt || server->authoritative)
				send_nak(server, message, client_id_opt);

			break;
		}

		/*
		 * 4.3.2: "If the DHCPREQUEST message contains a 'server
		 * identifier' option, the message is in response to a
		 * DHCPOFFER message.  Otherwise, the message is a request
		 * to verify or extend an existing lease."
		 */
		if (server_id_opt && server_id_match) {
			/*
			 * Allow either no 'requested IP address' option or
			 * a value identical with the one we offered because
			 * the spec is unclear on whether it is to be
			 * included:
			 *
			 * Section 4.3.2: "DHCPREQUEST generated during
			 * SELECTING state: (...) 'requested IP address' MUST
			 * be filled in with the yiaddr value from the chosen
			 * DHCPOFFER."
			 *
			 * but section 3.5 suggests only in the INIT-REBOOT
			 * state: "The 'requested IP address' option is to be
			 * filled in only in a DHCPREQUEST message when the
			 * client is verifying network parameters obtained
			 * previously."
			 */
			if (!lease->offering ||
					(requested_ip_opt &&
					 requested_ip_opt != lease->address)) {
				send_nak(server, message, client_id_opt);
				break;
			}
		} else {
			/*
			 * 3.5: "If a server receives a DHCPREQUEST message
			 * with an invalid 'requested IP address', the server
			 * SHOULD respond to the client with a DHCPNAK message"
			 */
			if (lease->offering ||
					(requested_ip_opt &&
					 requested_ip_opt != lease->address)) {
				send_nak(server, message, client_id_opt);
				break;
			}
		}

		send_ack(server, message, lease, false, timestamp);
		break;
	case DHCP_MESSAGE_TYPE_DECLINE:
		SERVER_DEBUG("Received DECLINE");

		if (!server_id_opt || !server_id_match || !requested_ip_opt ||
				!lease)
			break;

		if (requested_ip_opt == lease->address)
			remove_lease(server, lease);

		break;
	case DHCP_MESSAGE_TYPE_RELEASE:
		SERVER_DEBUG("Received RELEASE");

		if (!server_id_opt || !server_id_match || !lease ||
				lease->offering)
			break;

		if (message->ciaddr == lease->address)
			lease_release(server, lease);

		break;
	case DHCP_MESSAGE_TYPE_INFORM:
		SERVER_DEBUG("Received INFORM");

		if (!server_id_match)
			break;

		send_inform(server, message, client_id_opt);
		break;
	}
}

bool _dhcp_server_set_max_expired_clients(struct l_dhcp_server *server,
						unsigned int max_expired)
{
	if (unlikely(!server))
		return false;

	server->max_expired = max_expired;

	return true;
}

bool _dhcp_server_set_transport(struct l_dhcp_server *server,
					struct dhcp_transport *transport)
{
	if (unlikely(!server))
		return false;

	if (server->transport)
		_dhcp_transport_free(server->transport);

	server->transport = transport;
	return true;
}

struct dhcp_transport *_dhcp_server_get_transport(struct l_dhcp_server *server)
{
	if (unlikely(!server))
		return NULL;

	return server->transport;
}

LIB_EXPORT struct l_dhcp_server *l_dhcp_server_new(int ifindex)
{
	struct l_dhcp_server *server = l_new(struct l_dhcp_server, 1);

	server->lease_list = l_queue_new();
	server->expired_list = l_queue_new();

	server->started = false;
	server->authoritative = true;
	server->rapid_commit = true;

	server->lease_seconds = DEFAULT_DHCP_LEASE_SEC;
	server->max_expired = MAX_EXPIRED_LEASES;

	server->ifindex = ifindex;
	server->debug_handler = NULL;
	server->debug_data = NULL;

	return server;
}

LIB_EXPORT void l_dhcp_server_destroy(struct l_dhcp_server *server)
{
	if (unlikely(!server))
		return;

	l_dhcp_server_stop(server);

	if (server->event_destroy)
		server->event_destroy(server->user_data);

	_dhcp_transport_free(server->transport);
	l_free(server->ifname);

	l_queue_destroy(server->lease_list,
				(l_queue_destroy_func_t) _dhcp_lease_free);
	l_queue_destroy(server->expired_list,
				(l_queue_destroy_func_t) _dhcp_lease_free);

	if (server->dns_list)
		l_free(server->dns_list);

	l_free(server);
}

LIB_EXPORT bool l_dhcp_server_start(struct l_dhcp_server *server)
{
	char buf[INET_ADDRSTRLEN];
	struct in_addr ia;

	if (unlikely(!server))
		return false;

	if (server->started)
		return false;

	if (!server->address) {
		if (!l_net_get_address(server->ifindex, &ia))
			return false;

		server->address = ia.s_addr;
	}

	/* Assign a default netmask if not already */
	if (!server->netmask) {
		if (inet_pton(AF_INET,"255.255.255.0", &ia) != 1)
			return false;

		server->netmask = ia.s_addr;
	}

	/*
	 * Assign a default ip range if not already. This will default to
	 * server->address + 1 ... subnet end address - 1
	 */
	if (!server->start_ip) {
		server->start_ip = ntohl(server->address) + 1;
		server->end_ip = (ntohl(server->address) |
			(~ntohl(server->netmask))) - 1;
	} else {
		if ((server->start_ip ^ ntohl(server->address)) &
				ntohl(server->netmask))
			return false;

		if ((server->end_ip ^ ntohl(server->address)) &
				ntohl(server->netmask))
			return false;

		/*
		 * Directly ensure the [start_ip, end_ip] range doesn't
		 * include the subnet address or the broadcast address so that
		 * we have fewer checks to make when selecting a free address
		 * from that range.  Additionally this ensures end_ip is not
		 * 0xffffffff so we can use the condition "<= server->end_ip"
		 * safely on uint32_t values.
		 * In find_free_or_expired_ip we skip over IPs ending in .0 or
		 * .255 even for netmasks other than 24-bit just to avoid
		 * generating addresses that could look suspicious even if
		 * they're legal.  We don't exclude these addresses when
		 * explicitly requested by the client, i.e. in
		 * check_requested_ip.
		 */
		if ((server->start_ip & (~ntohl(server->netmask))) == 0)
			server->start_ip++;

		if ((server->end_ip | ntohl(server->netmask)) == 0xffffffff)
			server->end_ip--;
	}

	if (server->start_ip >= server->end_ip)
		return false;

	if (!server->ifname) {
		server->ifname = l_net_get_name(server->ifindex);

		if (!server->ifname)
			return false;
	}

	if (!server->transport) {
		server->transport = _dhcp_default_transport_new(server->ifindex,
					server->ifname, DHCP_PORT_SERVER);
		if (!server->transport)
			return false;
	}

	SERVER_DEBUG("Starting DHCP server on %s", server->ifname);

	if (server->transport->open)
		if (server->transport->open(server->transport, 0) < 0)
			return false;

	_dhcp_transport_set_rx_callback(server->transport, listener_event,
						server);

	server->started = true;

	server->acd = l_acd_new(server->ifindex);
	l_acd_set_skip_probes(server->acd, true);
	l_acd_set_defend_policy(server->acd, L_ACD_DEFEND_POLICY_INFINITE);

	ia.s_addr = server->address;
	inet_ntop(AF_INET, &ia, buf, INET_ADDRSTRLEN);

	/* In case of unit testing we don't want this to be a fatal error */
	if (!l_acd_start(server->acd, buf)) {
		SERVER_DEBUG("Failed to start ACD on %s, continuing without",
				buf);

		l_acd_destroy(server->acd);
		server->acd = NULL;
	}

	return true;
}

LIB_EXPORT bool l_dhcp_server_stop(struct l_dhcp_server *server)
{
	if (unlikely(!server))
		return false;

	if (!server->started)
		return true;

	if (server->transport->close)
		server->transport->close(server->transport);

	server->started = false;

	if (server->next_expire) {
		l_timeout_remove(server->next_expire);
		server->next_expire = NULL;
	}

	if (server->acd) {
		l_acd_destroy(server->acd);
		server->acd = NULL;
	}

	/* TODO: Add ability to save leases */

	return true;
}

LIB_EXPORT bool l_dhcp_server_set_ip_range(struct l_dhcp_server *server,
				const char *start_ip,
				const char *end_ip)
{
	struct in_addr _host_addr;
	uint32_t start;

	if (unlikely(!server || !start_ip || !end_ip))
		return false;

	if (inet_pton(AF_INET, start_ip, &_host_addr) != 1)
		return false;

	start = ntohl(_host_addr.s_addr);

	if (inet_pton(AF_INET, (const char *) end_ip, &_host_addr) != 1)
		return false;

	server->start_ip = start;
	server->end_ip = ntohl(_host_addr.s_addr);

	return true;
}

LIB_EXPORT bool l_dhcp_server_set_debug(struct l_dhcp_server *server,
				l_dhcp_debug_cb_t function,
				void *user_data, l_dhcp_destroy_cb_t destory)
{
	if (unlikely(!server))
		return false;

	server->debug_handler = function;
	server->debug_data = user_data;
	server->debug_destroy = destory;

	return true;
}

LIB_EXPORT bool l_dhcp_server_set_lease_time(struct l_dhcp_server *server,
					unsigned int lease_time)
{
	if (unlikely(!server))
		return false;

	server->lease_seconds = lease_time;

	return true;
}

LIB_EXPORT bool l_dhcp_server_set_event_handler(struct l_dhcp_server *server,
					l_dhcp_server_event_cb_t handler,
					void *user_data,
					l_dhcp_destroy_cb_t destroy)
{
	if (unlikely(!server))
		return false;

	server->event_handler = handler;
	server->user_data = user_data;
	server->event_destroy = destroy;

	return true;
}

LIB_EXPORT bool l_dhcp_server_set_ip_address(struct l_dhcp_server *server,
						const char *ip)
{
	struct in_addr ia;

	if (unlikely(!server))
		return false;

	if (inet_pton(AF_INET, ip, &ia) != 1)
		return false;

	server->address = ia.s_addr;

	return true;
}

LIB_EXPORT bool l_dhcp_server_set_interface_name(struct l_dhcp_server *server,
							const char *ifname)
{
	if (unlikely(!server || !ifname))
		return false;

	l_free(server->ifname);
	server->ifname = l_strdup(ifname);

	return true;
}

LIB_EXPORT bool l_dhcp_server_set_netmask(struct l_dhcp_server *server,
						const char *mask)
{
	struct in_addr ia;

	if (unlikely(!server || !mask))
		return false;

	if (inet_pton(AF_INET, mask, &ia) != 1)
		return false;

	server->netmask = ia.s_addr;

	return true;
}

LIB_EXPORT bool l_dhcp_server_set_gateway(struct l_dhcp_server *server,
						const char *ip)
{
	struct in_addr ia;

	if (unlikely(!server || !ip))
		return false;

	if (inet_pton(AF_INET, ip, &ia) != 1)
		return false;

	server->gateway = ia.s_addr;

	return true;
}

LIB_EXPORT bool l_dhcp_server_set_dns(struct l_dhcp_server *server, char **dns)
{
	unsigned int i;
	uint32_t *dns_list;

	if (unlikely(!server || !dns))
		return false;

	dns_list = l_new(uint32_t, l_strv_length(dns) + 1);

	for (i = 0; dns[i]; i++) {
		struct in_addr ia;

		if (inet_pton(AF_INET, dns[i], &ia) != 1)
			goto failed;

		dns_list[i] = ia.s_addr;
	}

	if (server->dns_list)
		l_free(server->dns_list);

	server->dns_list = dns_list;

	return true;

failed:
	l_free(dns_list);
	return false;
}

LIB_EXPORT void l_dhcp_server_set_authoritative(struct l_dhcp_server *server,
						bool authoritative)
{
	if (unlikely(!server))
		return;

	server->authoritative = authoritative;
}

LIB_EXPORT void l_dhcp_server_set_enable_rapid_commit(
						struct l_dhcp_server *server,
						bool enable)
{
	if (unlikely(!server))
		return;

	server->rapid_commit = enable;
}

LIB_EXPORT struct l_dhcp_lease *l_dhcp_server_discover(
						struct l_dhcp_server *server,
						uint32_t requested_ip_opt,
						const uint8_t *client_id,
						const uint8_t *mac)
{
	struct l_dhcp_lease *lease;

	SERVER_DEBUG("Requested IP " NIPQUAD_FMT " for " MAC,
			NIPQUAD(requested_ip_opt), MAC_STR(mac));

	if ((lease = find_lease_by_id(server->lease_list, client_id, mac)))
		requested_ip_opt = lease->address;
	else if (!check_requested_ip(server, requested_ip_opt)) {
		requested_ip_opt = find_free_or_expired_ip(server, mac);

		if (unlikely(!requested_ip_opt)) {
			SERVER_DEBUG("Could not find any free addresses");
			return NULL;
		}
	}

	lease = add_lease(server, true, client_id, mac, requested_ip_opt,
				l_time_now());
	if (unlikely(!lease)) {
		SERVER_DEBUG("add_lease() failed");
		return NULL;
	}

	SERVER_DEBUG("Offering " NIPQUAD_FMT " to " MAC,
			NIPQUAD(requested_ip_opt), MAC_STR(mac));
	return lease;
}

LIB_EXPORT bool l_dhcp_server_request(struct l_dhcp_server *server,
					struct l_dhcp_lease *lease)
{
	uint8_t mac[ETH_ALEN];

	if (unlikely(!lease))
		return false;

	SERVER_DEBUG("Requested IP " NIPQUAD_FMT " for " MAC,
			NIPQUAD(lease->address), MAC_STR(lease->mac));

	memcpy(mac, lease->mac, ETH_ALEN);
	lease = add_lease(server, false, NULL, mac, lease->address,
				lease->bound_time);

	if (server->event_handler)
		server->event_handler(server, L_DHCP_SERVER_EVENT_NEW_LEASE,
					server->user_data, lease);

	return true;
}

LIB_EXPORT bool l_dhcp_server_decline(struct l_dhcp_server *server,
					struct l_dhcp_lease *lease)
{
	if (unlikely(!lease || !lease->offering))
		return false;

	SERVER_DEBUG("Declined IP " NIPQUAD_FMT " for " MAC,
			NIPQUAD(lease->address), MAC_STR(lease->mac));

	return remove_lease(server, lease);
}

LIB_EXPORT bool l_dhcp_server_release(struct l_dhcp_server *server,
					struct l_dhcp_lease *lease)
{
	if (unlikely(!lease || lease->offering))
		return false;

	SERVER_DEBUG("Released IP " NIPQUAD_FMT " for " MAC,
			NIPQUAD(lease->address), MAC_STR(lease->mac));

	lease_release(server, lease);
	return true;
}

/* Drop an offered, active or expired lease without moving it to expired_list */
LIB_EXPORT bool l_dhcp_server_lease_remove(struct l_dhcp_server *server,
						struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return false;

	if (unlikely(!l_queue_remove(server->lease_list, lease) &&
			!l_queue_remove(server->expired_list, lease)))
		return false;

	_dhcp_lease_free(lease);
	set_next_expire_timer(server, NULL);
	return true;
}

struct dhcp_expire_by_mac_data {
	struct l_dhcp_server *server;
	const uint8_t *mac;
	unsigned int expired_cnt;
};

static bool dhcp_expire_by_mac(void *data, void *user_data)
{
	struct l_dhcp_lease *lease = data;
	struct dhcp_expire_by_mac_data *expire_data = user_data;
	struct l_dhcp_server *server = expire_data->server;

	if (!match_lease_mac(lease, expire_data->mac))
		return false;

	if (server->event_handler)
		server->event_handler(server, L_DHCP_SERVER_EVENT_LEASE_EXPIRED,
					server->user_data, lease);

	if (!lease->offering) {
		if (l_queue_length(server->expired_list) > server->max_expired)
			_dhcp_lease_free(l_queue_pop_head(server->expired_list));

		l_queue_push_tail(server->expired_list, lease);
	} else
		_dhcp_lease_free(lease);

	expire_data->expired_cnt++;
	return true;
}

LIB_EXPORT void l_dhcp_server_expire_by_mac(struct l_dhcp_server *server,
						const uint8_t *mac)
{
	struct dhcp_expire_by_mac_data expire_data = { server, mac, 0 };

	l_queue_foreach_remove(server->lease_list, dhcp_expire_by_mac,
				&expire_data);

	if (expire_data.expired_cnt)
		set_next_expire_timer(server, NULL);
}
