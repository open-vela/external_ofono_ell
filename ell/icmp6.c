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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <linux/ipv6.h>
#include <linux/rtnetlink.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <stddef.h>

#include "private.h"
#include "useful.h"
#include "timeout.h"
#include "time.h"
#include "io.h"
#include "time-private.h"
#include "queue.h"
#include "net.h"
#include "net-private.h"
#include "netlink.h"
#include "rtnl.h"
#include "missing.h"
#include "utf8.h"
#include "icmp6.h"
#include "icmp6-private.h"

/* RFC4191 */
#ifndef ND_OPT_ROUTE_INFORMATION
#define ND_OPT_ROUTE_INFORMATION	24
#endif

/* RFC8106 */
#ifndef ND_OPT_RECURSIVE_DNS_SERVER
#define ND_OPT_RECURSIVE_DNS_SERVER	25
#endif
#ifndef ND_OPT_DNS_SEARCH_LIST
#define ND_OPT_DNS_SEARCH_LIST		31
#endif

#define CLIENT_DEBUG(fmt, args...)					\
	l_util_debug(client->debug_handler, client->debug_data,		\
			"%s:%i " fmt, __func__, __LINE__, ## args)

#define IN6ADDR_LINKLOCAL_ALLNODES_INIT	\
			{ { { 0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }
#define IN6ADDR_LINKLOCAL_ALLROUTERS_INIT \
			{ { { 0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,2 } } }
#define LLADDR_LINKLOCAL_ALLNODES_INIT	\
			{ 0x33,0x33,0,0,0,1 }
#define LLADDR_LINKLOCAL_ALLROUTERS_INIT \
			{ 0x33,0x33,0,0,0,2 }

static int icmp6_open_router_solicitation(int ifindex)
{
	int s;
	struct sockaddr_ll addr;
	struct sock_filter filter[] = {
		/* A <- packet length */
		BPF_STMT(BPF_LD | BPF_W | BPF_LEN, 0),
		/* A >= sizeof(nd_router_advert) ? */
		BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, sizeof(struct ip6_hdr) +
				sizeof(struct nd_router_advert), 1, 0),
		/* ignore */
		BPF_STMT(BPF_RET | BPF_K, 0),
		/* A <- IP version + Traffic class */
		BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0),
		/* A <- A & 0xf0 (Mask off version) */
		BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf0),
		/* A == IPv6 ? */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 6 << 4, 1, 0),
		/* ignore */
		BPF_STMT(BPF_RET | BPF_K, 0),
		/* A <- Next Header */
		BPF_STMT(BPF_LD | BPF_B | BPF_ABS,
				offsetof(struct ip6_hdr, ip6_nxt)),
		/* A == ICMPv6 ? */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMPV6, 1, 0),
		/* ignore */
		BPF_STMT(BPF_RET | BPF_K, 0),
		/* A <- ICMPv6 Type */
		BPF_STMT(BPF_LD | BPF_B | BPF_ABS, sizeof(struct ip6_hdr) +
				offsetof(struct icmp6_hdr, icmp6_type)),
		/* A == Router Advertisement ? */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ND_ROUTER_ADVERT, 1, 0),
		/* ignore */
		BPF_STMT(BPF_RET | BPF_K, 0),
		/* A <- Payload Length */
		BPF_STMT(BPF_LD | BPF_H | BPF_ABS,
				offsetof(struct ip6_hdr, ip6_plen)),
		/* A >= sizeof(nd_router_advert) ? */
		BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K,
				sizeof(struct nd_router_advert), 1, 0),
		/* ignore */
		BPF_STMT(BPF_RET | BPF_K, 0),
		/* return all */
		BPF_STMT(BPF_RET | BPF_K, 65535),
	};
	const struct sock_fprog fprog = {
		.len = L_ARRAY_SIZE(filter),
		.filter = filter
	};
	int one = 1;

	s = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_IPV6));
	if (s < 0)
		return -errno;

	if (setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER,
						&fprog, sizeof(fprog)) < 0)
		goto error;

	if (setsockopt(s, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof(one)) < 0)
		goto error;

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_IPV6);
	addr.sll_ifindex = ifindex;

	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		goto error;

	return s;

error:
	L_TFR(close(s));
	return -errno;
}

static uint16_t icmp6_checksum(const struct iovec *iov, unsigned int iov_len)
{
	const struct ip6_hdr *ip_hdr = iov[0].iov_base;
	uint32_t sum = 0;
	const uint16_t *ptr;
	const uint16_t *buf_end;
	/* Skip the real IPv6 header */
	unsigned int buf_offset = sizeof(struct ip6_hdr);

	/*
	 * ICMPv6 checksum according to RFC 4443 Section 2.3, this includes
	 * the IPv6 payload + the IPv6 pseudo-header according to RFC 2460
	 * Section 8.1, i.e. the two IPv6 addresses + the payload length +
	 * the header type.  The caller must ensure that the IPv6 header is
	 * all in one buffer and that all buffer starts and lengths are
	 * 16-bit-aligned.
	 *
	 * We can skip all zero words such as the upper 16 bits of the
	 * payload length.  No need to byteswap as the carry bits from
	 * either byte (high or low) accumulate in the other byte in
	 * exactly the same way.
	 */
	buf_end = (void *) &ip_hdr->ip6_src + 32;
	for (ptr = (void *) &ip_hdr->ip6_src; ptr < buf_end; )
		sum += *ptr++;

	sum += ip_hdr->ip6_plen + htons(ip_hdr->ip6_nxt);

	for (; iov_len; iov++, iov_len--) {
		buf_end = iov->iov_base + iov->iov_len;
		for (ptr = iov->iov_base + buf_offset; ptr < buf_end; )
			sum += *ptr++;

		buf_offset = 0;
	}

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

static int icmp6_send_router_solicitation(int s, int ifindex,
					const uint8_t src_mac[static 6],
					const struct in6_addr *src_ip,
					bool src_ip_optimistic)
{
	struct nd_router_solicit rs = {
		.nd_rs_type = ND_ROUTER_SOLICIT,
		.nd_rs_code = 0,
	};
	struct nd_opt_hdr rs_sllao = {
		.nd_opt_type = ND_OPT_SOURCE_LINKADDR,
		.nd_opt_len = 1,
	};
	const size_t rs_sllao_size = sizeof(rs_sllao) + 6;
	struct ip6_hdr ip_hdr = {
		.ip6_flow = htonl(6 << 28),
		.ip6_hops = 255,
		.ip6_nxt = IPPROTO_ICMPV6,
		.ip6_plen = htons(sizeof(rs) + rs_sllao_size),
		.ip6_dst = IN6ADDR_LINKLOCAL_ALLROUTERS_INIT,
	};
	struct iovec iov[4] = {
		{ .iov_base = &ip_hdr, .iov_len = sizeof(ip_hdr) },
		{ .iov_base = &rs, .iov_len = sizeof(rs) },
		{ .iov_base = &rs_sllao, .iov_len = sizeof(rs_sllao) },
		{ .iov_base = (void *) src_mac, .iov_len = 6 } };

	struct sockaddr_ll dst = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_IPV6),
		.sll_ifindex = ifindex,
		.sll_addr = LLADDR_LINKLOCAL_ALLROUTERS_INIT,
		.sll_halen = 6,
	};
	struct msghdr msg = {
		.msg_name = &dst,
		.msg_namelen = sizeof(dst),
		.msg_iov = iov,
		.msg_iovlen = L_ARRAY_SIZE(iov),
	};
	int r;

	memcpy(&ip_hdr.ip6_src, src_ip, 16);

	if (l_memeqzero(src_ip, 16) || src_ip_optimistic) {
		/*
		 * RFC 4429 Section 3.2: "A node MUST NOT send a Router
		 * Solicitation with a SLLAO from an Optimistic Address.
		 * Router Solicitations SHOULD be sent from a non-Optimistic
		 * or the Unspecified Address; however, they MAY be sent from
		 * an Optimistic Address as long as the SLLAO is not included."
		 *
		 * Additionally radvd will also discard and warn about RSs
		 * from the unspecified address with the SLLAO.  Omit that
		 * option by dropping the last two iov buffers.
		 */
		msg.msg_iovlen -= 2;
		ip_hdr.ip6_plen = htons(ntohs(ip_hdr.ip6_plen) - rs_sllao_size);
	}

	/* Don't byteswap the checksum */
	rs.nd_rs_cksum = icmp6_checksum(msg.msg_iov, msg.msg_iovlen);

	r = sendmsg(s, &msg, 0);
	if (r < 0)
		return -errno;

	return 0;
}

static int icmp6_receive(int s, void *buf, ssize_t *buf_len,
				struct in6_addr *src, uint64_t *out_timestamp)
{
	char c_msg_buf[CMSG_SPACE(sizeof(int)) +
			CMSG_SPACE(sizeof(struct timeval))];
	struct ip6_hdr ip_hdr;
	struct iovec iov[2] = {
		{ .iov_base = &ip_hdr, .iov_len = sizeof(ip_hdr) },
		{ .iov_base = buf, .iov_len = *buf_len - sizeof(ip_hdr) },
	};
	struct sockaddr_ll saddr;
	struct msghdr msg = {
		.msg_name = (void *)&saddr,
		.msg_namelen = sizeof(struct sockaddr_ll),
		.msg_flags = 0,
		.msg_iov = iov,
		.msg_iovlen = L_ARRAY_SIZE(iov),
		.msg_control = c_msg_buf,
		.msg_controllen = sizeof(c_msg_buf),
	};
	struct cmsghdr *cmsg;
	ssize_t l;
	uint64_t timestamp = 0;

	l = recvmsg(s, &msg, MSG_DONTWAIT);
	if (l < 0)
		return -errno;

	if (l != *buf_len)
		return -EINVAL;

	if (ntohs(ip_hdr.ip6_plen) > iov[1].iov_len)
		return -EMSGSIZE;

	iov[1].iov_len = ntohs(ip_hdr.ip6_plen);

	/*
	 * Unlikely but align length for icmp6_checksum().  We know we have
	 * at least sizeof(struct ip6_hdr) extra bytes in buf so we can
	 * append this 0 byte no problem.
	 */
	if (iov[1].iov_len & 1)
		((uint8_t *) buf)[iov[1].iov_len++] = 0x00;

	if (icmp6_checksum(iov, L_ARRAY_SIZE(iov)))
		return -EBADMSG;

	if (ip_hdr.ip6_hops != 255)
		return -EMULTIHOP;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
				cmsg->cmsg_type == SCM_TIMESTAMP &&
				cmsg->cmsg_len ==
				CMSG_LEN(sizeof(struct timeval))) {
			const struct timeval *tv = (void *) CMSG_DATA(cmsg);

			timestamp = _time_realtime_to_boottime(tv);
		}
	}

	*buf_len = ntohs(ip_hdr.ip6_plen);
	memcpy(src, &ip_hdr.ip6_src, 16);
	*out_timestamp = timestamp ?: l_time_now();
	return 0;
}

struct icmp6_event_handler_entry {
	l_icmp6_client_event_cb_t handle;
	void *user_data;
	l_icmp6_destroy_cb_t destroy;
};

struct l_icmp6_client {
	uint32_t ifindex;
	uint8_t mac[6];
	struct l_timeout *timeout_send;
	uint64_t retransmit_time;
	struct l_io *io;
	struct in6_addr src_ip;
	bool src_ip_optimistic;

	struct l_icmp6_router *ra;
	struct l_netlink *rtnl;
	uint32_t route_priority;
	struct l_queue *routes;

	struct l_queue *event_handlers;

	l_icmp6_debug_cb_t debug_handler;
	l_icmp6_destroy_cb_t debug_destroy;
	void *debug_data;

	bool nodelay : 1;
	bool have_mac : 1;
};

static inline void icmp6_client_event_notify(struct l_icmp6_client *client,
					enum l_icmp6_client_event event,
					void *event_data)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(client->event_handlers); entry;
			entry = entry->next) {
		struct icmp6_event_handler_entry *handler = entry->data;

		handler->handle(client, event, event_data, handler->user_data);
	}
}

static bool icmp6_client_remove_route(void *data, void *user_data)
{
	struct l_icmp6_client *client = user_data;
	struct l_rtnl_route *r = data;

	if (client->rtnl)
		l_rtnl_route_delete(client->rtnl, client->ifindex, r,
					NULL, NULL, NULL);

	l_free(r);
	return true;
}

static void icmp6_client_setup_routes(struct l_icmp6_client *client)
{
	struct l_icmp6_router *ra = client->ra;
	struct l_rtnl_route *rt;
	char buf[INET6_ADDRSTRLEN];
	unsigned int i;

	rt = l_rtnl_route_new_gateway(inet_ntop(AF_INET6, ra->address,
							buf, sizeof(buf)));
	if (!rt) {
		CLIENT_DEBUG("Unable to parse RA 'from' address");
		return;
	}

	l_rtnl_route_set_preference(rt, ra->pref);
	l_rtnl_route_set_protocol(rt, RTPROT_RA);
	l_rtnl_route_set_mtu(rt, ra->mtu);
	l_rtnl_route_set_priority(rt, client->route_priority);
	l_queue_push_tail(client->routes, rt);

	if (client->rtnl)
		l_rtnl_route_add(client->rtnl, client->ifindex, rt,
					NULL, NULL, NULL);

	for (i = 0; i < ra->n_routes; i++) {
		char prefix_buf[INET6_ADDRSTRLEN];
		struct route_info *info = &ra->routes[i];

		if (info->valid_lifetime == 0)
			continue;

		if (!inet_ntop(AF_INET6, info->address, prefix_buf,
				sizeof(prefix_buf)))
			continue;

		if (info->onlink)
			rt = l_rtnl_route_new_prefix(prefix_buf,
							info->prefix_len);
		else
			rt = l_rtnl_route_new_static(buf, prefix_buf,
							info->prefix_len);

		if (!rt)
			continue;

		l_rtnl_route_set_preference(rt, info->preference);
		l_rtnl_route_set_protocol(rt, RTPROT_RA);
		l_rtnl_route_set_mtu(rt, ra->mtu);
		l_rtnl_route_set_priority(rt, client->route_priority);
		l_queue_push_tail(client->routes, rt);

		if (client->rtnl)
			l_rtnl_route_add(client->rtnl, client->ifindex, rt,
						NULL, NULL, NULL);
	}
}

static int icmp6_client_handle_message(struct l_icmp6_client *client,
						struct nd_router_advert *ra,
						size_t len,
						const struct in6_addr *src,
						uint64_t timestamp)
{
	struct l_icmp6_router *r =
		_icmp6_router_parse(ra, len, src->s6_addr, timestamp);

	if (!r)
		return -EBADMSG;

	icmp6_client_event_notify(client,
					L_ICMP6_CLIENT_EVENT_ROUTER_FOUND,
					r);

	/* DHCP6 client may have stopped us */
	if (!client->io)
		return -ECANCELED;

	if (!client->ra) {
		client->ra = r;
		icmp6_client_setup_routes(client);
		return 0;
	}

	/*
	 * TODO: Figure out if the RA has updated info and update routes
	 * accordingly.
	 */
	_icmp6_router_free(r);
	return 0;
}

static bool icmp6_client_read_handler(struct l_io *io, void *userdata)
{
	struct l_icmp6_client *client = userdata;
	int s = l_io_get_fd(io);
	struct nd_router_advert *ra;
	ssize_t l;
	struct in6_addr src;
	int r;
	uint64_t timestamp = 0;

	/* Poke to see how many bytes we need to read / alloc */
	l = recv(s, NULL, 0, MSG_PEEK|MSG_TRUNC);
	if (l < 0) {
		CLIENT_DEBUG("Unable to read len info from socket: %s",
				strerror(-errno));
		return false;
	}

	if ((size_t) l < sizeof(struct ip6_hdr) +
			sizeof(struct nd_router_advert)) {
		CLIENT_DEBUG("Message too small - ignore");
		return true;
	}

	ra = l_malloc(l);
	r = icmp6_receive(s, ra, &l, &src, &timestamp);
	if (r < 0) {
		CLIENT_DEBUG("icmp6_receive(): %s (%i)", strerror(-r), -r);
		goto done;
	}

	r = icmp6_client_handle_message(client, ra, l, &src, timestamp);
	if (r < 0)
		goto done;

	/* Stop solicitations */
	client->retransmit_time = 0;
	l_timeout_remove(client->timeout_send);
	client->timeout_send = NULL;

done:
	l_free(ra);
	return true;
}

static void icmp6_client_timeout_send(struct l_timeout *timeout,
							void *user_data)
{
	static const uint64_t MAX_SOLICITATION_INTERVAL =
							3600 * L_MSEC_PER_SEC;
	static const uint64_t SOLICITATION_INTERVAL = 4 * L_MSEC_PER_SEC;
	struct l_icmp6_client *client = user_data;
	int r;

	CLIENT_DEBUG("");

	if (client->retransmit_time > MAX_SOLICITATION_INTERVAL / 2)
		client->retransmit_time =
				_time_fuzz_msecs(MAX_SOLICITATION_INTERVAL);
	else
		client->retransmit_time +=
			_time_fuzz_msecs(client->retransmit_time ?:
						SOLICITATION_INTERVAL);

	r = icmp6_send_router_solicitation(l_io_get_fd(client->io),
						client->ifindex, client->mac,
						&client->src_ip,
						client->src_ip_optimistic);
	if (r < 0) {
		CLIENT_DEBUG("Error sending Router Solicitation: %s",
				strerror(-r));
		l_icmp6_client_stop(client);
		return;
	}

	CLIENT_DEBUG("Sent router solicitation, next attempt in %"PRIu64" ms",
			client->retransmit_time);
	l_timeout_modify_ms(timeout, client->retransmit_time);
}

LIB_EXPORT struct l_icmp6_client *l_icmp6_client_new(uint32_t ifindex)
{
	struct l_icmp6_client *client = l_new(struct l_icmp6_client, 1);

	client->ifindex = ifindex;
	client->routes = l_queue_new();

	return client;
}

static void icmp6_event_handler_destroy(void *data)
{
	struct icmp6_event_handler_entry *handler = data;

	if (handler->destroy)
		handler->destroy(handler->user_data);

	l_free(handler);
}

LIB_EXPORT void l_icmp6_client_free(struct l_icmp6_client *client)
{
	if (unlikely(!client))
		return;

	l_icmp6_client_stop(client);
	l_queue_destroy(client->routes, NULL);
	l_icmp6_client_set_debug(client, NULL, NULL, NULL);
	l_queue_destroy(client->event_handlers, icmp6_event_handler_destroy);
	l_free(client);
}

LIB_EXPORT bool l_icmp6_client_start(struct l_icmp6_client *client)
{
	uint64_t delay = 0;
	int s;

	if (unlikely(!client))
		return false;

	if (client->io)
		return false;

	CLIENT_DEBUG("Starting ICMPv6 Client");

	s = icmp6_open_router_solicitation(client->ifindex);
	if (s < 0)
		return false;

	if (!client->have_mac) {
		if (!l_net_get_mac_address(client->ifindex, client->mac))
			goto err;

		client->have_mac = true;
	}

	client->io = l_io_new(s);
	if (!client->io)
		goto err;

	l_io_set_close_on_destroy(client->io, true);
	l_io_set_read_handler(client->io, icmp6_client_read_handler,
					client, NULL);

	if (!client->nodelay)
		delay = _time_pick_interval_secs(0, 1);

	client->timeout_send = l_timeout_create_ms(delay,
						icmp6_client_timeout_send,
						client, NULL);

	if (client->nodelay)
		icmp6_client_timeout_send(client->timeout_send, client);

	return true;

err:
	close(s);
	return false;
}

LIB_EXPORT bool l_icmp6_client_stop(struct l_icmp6_client *client)
{
	if (unlikely(!client))
		return false;

	if (!client->io)
		return false;

	CLIENT_DEBUG("Stopping...");

	l_io_destroy(client->io);
	client->io = NULL;

	l_queue_foreach_remove(client->routes,
					icmp6_client_remove_route, client);

	client->retransmit_time = 0;
	l_timeout_remove(client->timeout_send);
	client->timeout_send = NULL;

	if (client->ra) {
		_icmp6_router_free(client->ra);
		client->ra = NULL;
	}

	return true;
}

LIB_EXPORT const struct l_icmp6_router *l_icmp6_client_get_router(
						struct l_icmp6_client *client)
{
	if (unlikely(!client))
		return NULL;

	return client->ra;
}

LIB_EXPORT bool l_icmp6_client_add_event_handler(struct l_icmp6_client *client,
					l_icmp6_client_event_cb_t handler,
					void *user_data,
					l_icmp6_destroy_cb_t destroy)
{
	struct icmp6_event_handler_entry *handler_entry;

	if (unlikely(!client))
		return false;

	if (!client->event_handlers)
		client->event_handlers = l_queue_new();

	handler_entry = l_new(struct icmp6_event_handler_entry, 1);
	handler_entry->handle = handler;
	handler_entry->user_data = user_data;
	handler_entry->destroy = destroy;
	l_queue_push_head(client->event_handlers, handler_entry);

	return true;
}

LIB_EXPORT bool l_icmp6_client_set_debug(struct l_icmp6_client *client,
				l_icmp6_debug_cb_t function,
				void *user_data, l_icmp6_destroy_cb_t destroy)
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

LIB_EXPORT bool l_icmp6_client_set_address(struct l_icmp6_client *client,
						const uint8_t addr[static 6])
{
	if (unlikely(!client))
		return false;

	if (client->io)
		return false;

	memcpy(client->mac, addr, 6);
	client->have_mac = true;

	return true;
}

LIB_EXPORT bool l_icmp6_client_set_nodelay(struct l_icmp6_client *client,
						bool nodelay)
{
	if (unlikely(!client))
		return false;

	client->nodelay = nodelay;

	return true;
}

LIB_EXPORT bool l_icmp6_client_set_rtnl(struct l_icmp6_client *client,
						struct l_netlink *rtnl)
{
	if (unlikely(!client))
		return false;

	client->rtnl = rtnl;
	return true;
}

LIB_EXPORT bool l_icmp6_client_set_route_priority(
						struct l_icmp6_client *client,
						uint32_t priority)
{
	if (unlikely(!client))
		return false;

	client->route_priority = priority;
	return true;
}

LIB_EXPORT bool l_icmp6_client_set_link_local_address(
						struct l_icmp6_client *client,
						const char *ll, bool optimistic)
{
	if (unlikely(!client))
		return false;

	/*
	 * client->src_ip is all 0s initially which results in our Router
	 * Solicitations being sent from the IPv6 Unspecified Address, which
	 * is fine.  Once we have a confirmed link-local address we use that
	 * as the source address.
	 */
	if (inet_pton(AF_INET6, ll, &client->src_ip) != 1)
		return false;

	client->src_ip_optimistic = optimistic;
	return true;
}

struct l_icmp6_router *_icmp6_router_new()
{
	struct l_icmp6_router *r = l_new(struct l_icmp6_router, 1);

	return r;
}

void _icmp6_router_free(struct l_icmp6_router *r)
{
	l_free(r->routes);
	l_free(r->ac_prefixes);
	l_free(r);
}

/* Note: the following two write to @out even when they return false */
static bool icmp6_prefix_parse_rt_info(const uint8_t *data,
					struct route_info *out)
{
	out->prefix_len = data[2];
	out->onlink = true;
	out->preference = 0;
	out->valid_lifetime = l_get_be32(data + 4);

	/*
	 * Only the initial Prefix Length bits of the prefix are valid.
	 * The remaining bits "MUST" be ignored by the receiver.
	 */
	memcpy(out->address, net_prefix_from_ipv6(data + 16, out->prefix_len),
		16);

	if (out->prefix_len >= 10 && IN6_IS_ADDR_LINKLOCAL(out->address))
		return false;

	return true;
}

static bool icmp6_prefix_parse_ac_info(const uint8_t *data,
					struct autoconf_prefix_info *out)
{
	/*
	 * Per RFC4862 we need to silently ignore prefixes with a
	 * preferred lifetime longer than valid lifetime, those with
	 * 0 valid lifetime and those with link-local prefixes.
	 * Prefix Length must be 8 bytes (IPv6 address - Interface ID).
	 */
	if (data[2] != 64)
		return false;

	if (IN6_IS_ADDR_LINKLOCAL(data + 16))
		return false;

	out->valid_lifetime = l_get_be32(data + 4);
	out->preferred_lifetime = l_get_be32(data + 8);

	if (out->valid_lifetime == 0 ||
			out->preferred_lifetime > out->valid_lifetime)
		return false;

	memcpy(out->prefix, data + 16, 8);
	return true;
}

struct l_icmp6_router *_icmp6_router_parse(const struct nd_router_advert *ra,
						size_t len,
						const uint8_t src[static 16],
						uint64_t timestamp)
{
	struct l_icmp6_router *r;
	const uint8_t *opts;
	uint32_t opts_len;
	uint32_t n_routes = 0;
	uint32_t n_ac_prefixes = 0;
	uint32_t n_dns = 0;
	uint32_t n_domains = 0;

	if (ra->nd_ra_type != ND_ROUTER_ADVERT)
		return NULL;

	if (ra->nd_ra_code != 0)
		return NULL;

	opts = (uint8_t *) (ra + 1);
	opts_len = len - sizeof(struct nd_router_advert);

	while (opts_len) {
		uint8_t t;
		uint32_t l;

		if (opts_len < 2)
			return NULL;

		l = opts[1] * 8;
		if (!l || opts_len < l)
			return NULL;

		t = opts[0];

		switch (t) {
		case ND_OPT_MTU:
			if (l != 8)
				return NULL;
			break;
		case ND_OPT_PREFIX_INFORMATION:
			if (l != 32)
				return NULL;

			if (opts[2] > 128)
				return NULL;

			if (opts[3] & ND_OPT_PI_FLAG_ONLINK)
				n_routes += 1;

			if (opts[3] & ND_OPT_PI_FLAG_AUTO)
				n_ac_prefixes += 1;

			break;
		case ND_OPT_ROUTE_INFORMATION:
			if (l < 8)
				return NULL;

			if (opts[2] > 128 || opts[2] > (l - 8) * 8)
				return NULL;

			/*
			 * RFC 4191 Section 2.3:
			 * "If the Reserved (10) value is received, the Route
			 * Information Option MUST be ignored."
			 */
			if (bit_field(opts[3], 3, 2) == 2)
				break;

			/*
			 * RFC 4191 Section 3.1:
			 * "The Router Preference and Lifetime values in a ::/0
			 * Route Information Option override the preference and
			 * lifetime values in the Router Advertisement header."
			 *
			 * Don't count ::/0 routes.
			 */
			if (opts[2] == 0)
				break;

			n_routes += 1;
			break;
		case ND_OPT_RECURSIVE_DNS_SERVER:
			if (l < 24 || (l & 15) != 8)
				return NULL;

			n_dns += (l - 8) / 16;
			break;
		case ND_OPT_DNS_SEARCH_LIST:
		{
			unsigned int n_labels;
			unsigned int pos = 8;

			if (l < 16)
				return NULL;

			/* Count domains according to RFC1035 Section 3.1 */
			do {
				unsigned int label_len;

				n_labels = 0;

				do {
					label_len = opts[pos];
					pos += 1 + label_len;
					n_labels += label_len ? 1 : 0;
				} while (label_len && pos < l);

				/*
				 * Check if the root label was missing, or
				 * a label didn't fit in the option bytes, or
				 * the first domain had 0 labels, i.e. there
				 * were no domains.
				 */
				if (label_len || pos > l || pos == 9)
					return NULL;

				n_domains += n_labels ? 1 : 0;
			} while (n_labels && pos < l);

			break;
		}
		}

		opts += l;
		opts_len -= l;
	}

	r = _icmp6_router_new();
	memcpy(r->address, src, sizeof(r->address));
	r->routes = l_new(struct route_info, n_routes);
	r->ac_prefixes = l_new(struct autoconf_prefix_info, n_ac_prefixes);
	r->dns_list = l_new(struct dns_info, n_dns);
	r->domains = l_new(struct domain_info, n_domains);

	if (ra->nd_ra_flags_reserved & ND_RA_FLAG_MANAGED)
		r->managed = true;

	if (ra->nd_ra_flags_reserved & ND_RA_FLAG_OTHER)
		r->other = true;

	r->pref = (ra->nd_ra_flags_reserved >> 3) & 0x3;
	if (r->pref == 0x2) /* If invalid, reset to medium */
		r->pref = 0;

	r->start_time = timestamp;
	r->lifetime = L_BE16_TO_CPU(ra->nd_ra_router_lifetime);

	opts = (uint8_t *) (ra + 1);
	opts_len = len - sizeof(struct nd_router_advert);
	n_routes = 0;
	n_ac_prefixes = 0;
	n_dns = 0;
	n_domains = 0;

	while (opts_len) {
		uint8_t t = opts[0];
		uint32_t l = opts[1] * 8;

		switch (t) {
		case ND_OPT_MTU:
			if (r->mtu)
				break;

			r->mtu = l_get_be32(opts + 4);
			if (r->mtu < IPV6_MIN_MTU)
				r->mtu = 0;

			break;
		case ND_OPT_PREFIX_INFORMATION:
			if (opts[3] & ND_OPT_PI_FLAG_ONLINK) {
				struct route_info *i = &r->routes[n_routes];

				if (icmp6_prefix_parse_rt_info(opts, i))
					n_routes++;
			}

			if (opts[3] & ND_OPT_PI_FLAG_AUTO) {
				struct autoconf_prefix_info *i =
					&r->ac_prefixes[n_ac_prefixes];

				if (icmp6_prefix_parse_ac_info(opts, i))
					n_ac_prefixes++;
			}

			break;
		case ND_OPT_RTR_ADV_INTERVAL:
			if (l < 8)
				break;

			r->max_rtr_adv_interval_ms = l_get_be32(opts + 4);
			break;
		case ND_OPT_ROUTE_INFORMATION:
		{
			struct route_info *i = &r->routes[n_routes];
			uint8_t preference = bit_field(opts[3], 3, 2);

			if (preference == 2)
				break;

			/*
			 * RFC 4191 Section 3.1:
			 * "The Router Preference and Lifetime values in a ::/0
			 * Route Information Option override the preference and
			 * lifetime values in the Router Advertisement header."
			 */
			if (opts[2] == 0) {
				if (r->lifetime == 0 && l_get_be32(opts + 4)) {
					/*
					 * A ::/0 route received from a
					 * non-default router?  Should issue
					 * a warning?
					 */
					break;
				}

				r->pref = preference;
				r->lifetime = l_get_be16(opts + 4) ? 0xffff :
					l_get_be16(opts + 6);
				break;
			}

			/*
			 * Don't check or warn if the route lifetime is longer
			 * than the router lifetime because that refers to its
			 * time as the default router.  It may be configured to
			 * route packets for us for specific prefixes without
			 * being a default router.
			 */
			i->prefix_len = opts[2];
			i->onlink = false;
			i->preference = preference;
			i->valid_lifetime = l_get_be32(opts + 4);

			/*
			 * Only the initial Prefix Length bits of the prefix
			 * are valid.  The remaining bits "MUST" be ignored
			 * by the receiver.
			 */
			memcpy(i->address, net_prefix_from_ipv6(opts + 8,
							i->prefix_len), 16);

			n_routes += 1;
			break;
		}
		case ND_OPT_RECURSIVE_DNS_SERVER:
		{
			unsigned int pos;

			for (pos = 8; pos < l; pos += 16) {
				struct dns_info *i = &r->dns_list[n_dns++];

				i->lifetime = l_get_be32(opts + 4);
				memcpy(i->address, opts + pos, 16);
			}

			break;
		}
		case ND_OPT_DNS_SEARCH_LIST:
		{
			struct domain_info *info = &r->domains[n_domains];
			_auto_(l_free) char **domain_list =
				net_domain_list_parse(opts + 8, l - 8, true);
			char **i;

			/* Ignore malformed option */
			if (!domain_list || !domain_list[0])
				break;

			for (i = domain_list; *i; i++) {
				info->lifetime = l_get_be32(opts + 4);
				info->domain = *i;
				info++;
				n_domains++;
			}

			break;
		}
		}

		opts += l;
		opts_len -= l;
	}

	r->n_routes = n_routes;
	r->n_ac_prefixes = n_ac_prefixes;
	r->n_dns = n_dns;
	r->n_domains = n_domains;
	return r;
}

LIB_EXPORT char *l_icmp6_router_get_address(const struct l_icmp6_router *r)
{
	char buf[INET6_ADDRSTRLEN];

	if (unlikely(!r))
		return NULL;

	if (!inet_ntop(AF_INET6, r->address, buf, sizeof(buf)))
		return NULL;

	return l_strdup(buf);
}

LIB_EXPORT bool l_icmp6_router_get_managed(const struct l_icmp6_router *r)
{
	if (unlikely(!r))
		return false;

	return r->managed;
}

LIB_EXPORT bool l_icmp6_router_get_other(const struct l_icmp6_router *r)
{
	if (unlikely(!r))
		return false;

	return r->other;
}

LIB_EXPORT uint16_t l_icmp6_router_get_lifetime(const struct l_icmp6_router *r)
{
	if (unlikely(!r))
		return false;

	return r->lifetime;
}

/* Get the reception timestamp, i.e. when lifetime is counted from */
LIB_EXPORT uint64_t l_icmp6_router_get_start_time(const struct l_icmp6_router *r)
{
	if (unlikely(!r))
		return false;

	return r->start_time;
}
