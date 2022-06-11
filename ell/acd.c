/*
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <errno.h>

#include "private.h"
#include "useful.h"
#include "acd.h"
#include "util.h"
#include "io.h"
#include "net.h"
#include "timeout.h"
#include "random.h"
#include "time-private.h"

/* IPv4 Address Conflict Detection (RFC 5227) */
#define PROBE_WAIT		1
#define PROBE_NUM		3
#define PROBE_MIN		1
#define PROBE_MAX		2

#define ANNOUNCE_WAIT		2
#define ANNOUNCE_NUM		2
#define ANNOUNCE_INTERVAL	2

#define DEFEND_INTERVAL		10

#define MAC "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_STR(a) a[0], a[1], a[2], a[3], a[4], a[5]

#define NIPQUAD_FMT "%u.%u.%u.%u"
#define NIPQUAD(u32_ip)	((unsigned char *) &u32_ip)[0], \
			((unsigned char *) &u32_ip)[1], \
			((unsigned char *) &u32_ip)[2], \
			((unsigned char *) &u32_ip)[3]

#define ACD_DEBUG(fmt, args...)					\
	l_util_debug(acd->debug_handler, acd->debug_data,		\
			"%s:%i " fmt, __func__, __LINE__, ## args)

enum acd_state {
	ACD_STATE_PROBE,
	ACD_STATE_ANNOUNCED,
	ACD_STATE_DEFEND,
};

struct l_acd {
	int ifindex;

	uint32_t ip;
	uint8_t mac[ETH_ALEN];

	enum acd_state state;
	enum l_acd_defend_policy policy;

	struct l_io *io;
	struct l_timeout *timeout;
	unsigned int retries;

	l_acd_event_func_t event_func;
	l_acd_destroy_func_t destroy;
	void *user_data;

	l_acd_debug_cb_t debug_handler;
	l_acd_destroy_func_t debug_destroy;
	void *debug_data;

	bool skip_probes : 1;
};

static int acd_open_socket(int ifindex)
{
	struct sockaddr_ll dest;
	int fd;

	fd = socket(PF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	memset(&dest, 0, sizeof(dest));

	dest.sll_family = AF_PACKET;
	dest.sll_protocol = htons(ETH_P_ARP);
	dest.sll_ifindex = ifindex;
	dest.sll_halen = ETH_ALEN;
	memset(dest.sll_addr, 0xFF, ETH_ALEN);

	if (bind(fd, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
		int err = errno;
		close(fd);
		return -err;
	}

	return fd;
}

static int acd_send_packet(struct l_acd *acd, uint32_t source_ip)
{
	struct sockaddr_ll dest;
	struct ether_arp p;
	int n;
	int fd = l_io_get_fd(acd->io);

	memset(&dest, 0, sizeof(dest));
	memset(&p, 0, sizeof(p));

	dest.sll_family = AF_PACKET;
	dest.sll_protocol = htons(ETH_P_ARP);
	dest.sll_ifindex = acd->ifindex;
	dest.sll_halen = ETH_ALEN;
	memset(dest.sll_addr, 0xFF, ETH_ALEN);

	p.arp_hrd = htons(ARPHRD_ETHER);
	p.arp_pro = htons(ETHERTYPE_IP);
	p.arp_hln = ETH_ALEN;
	p.arp_pln = 4;
	p.arp_op = htons(ARPOP_REQUEST);

	ACD_DEBUG("sending packet with target IP "NIPQUAD_FMT,
			NIPQUAD(acd->ip));

	memcpy(&p.arp_sha, acd->mac, ETH_ALEN);
	memcpy(&p.arp_spa, &source_ip, sizeof(p.arp_spa));
	memcpy(&p.arp_tpa, &acd->ip, sizeof(p.arp_tpa));

	n = sendto(fd, &p, sizeof(p), 0,
			(struct sockaddr*) &dest, sizeof(dest));
	if (n < 0)
		n = -errno;

	return n;
}

static void announce_wait_timeout(struct l_timeout *timeout, void *user_data)
{
	struct l_acd *acd = user_data;

	if (acd->state == ACD_STATE_PROBE) {
		ACD_DEBUG("No conflicts found for "NIPQUAD_FMT ", announcing address",
				NIPQUAD(acd->ip));

		acd->state = ACD_STATE_ANNOUNCED;

		/*
		 * RFC 5227 - Section 2.3
		 *
		 * "The host may begin legitimately using the IP address
		 *  immediately after sending the first of the two ARP
		 *  Announcements"
		 */

		if (acd->event_func)
			acd->event_func(L_ACD_EVENT_AVAILABLE, acd->user_data);
	}

	if (acd->retries != ANNOUNCE_NUM) {
		int err = acd_send_packet(acd, acd->ip);

		acd->retries++;

		if (err < 0) {
			ACD_DEBUG("Failed to send ACD announcement: %s",
					strerror(-err));
			return;
		}

		l_timeout_modify(acd->timeout, ANNOUNCE_INTERVAL);

		return;
	}

	l_timeout_remove(acd->timeout);
	acd->timeout = NULL;

	ACD_DEBUG("Done announcing");
}

static void probe_wait_timeout(struct l_timeout *timeout, void *user_data)
{
	struct l_acd *acd = user_data;
	int err;
	uint32_t delay;

	ACD_DEBUG("Sending ACD Probe");

	if ((err = acd_send_packet(acd, 0)) < 0) {
		ACD_DEBUG("Failed to send ACD probe: %s", strerror(-err));
		return;
	}

	acd->retries++;

	if (acd->retries < PROBE_NUM) {
		/*
		 * RFC 5227 - Section 2.1.1
		 *
		 * "... and should then send PROBE_NUM probe packets, each of
		 * these probe packets spaced randomly and uniformly, PROBE_MIN
		 * to PROBE_MAX seconds apart."
		 */
		delay = _time_pick_interval_secs(PROBE_MIN, PROBE_MAX);
		l_timeout_modify_ms(acd->timeout, delay);
	} else {
		/*
		 * Wait for ANNOUNCE_WAIT seconds after probe period before
		 * announcing address.
		 */
		ACD_DEBUG("Done probing");

		l_timeout_remove(acd->timeout);
		acd->timeout = NULL;

		acd->retries = 1;

		acd->timeout = l_timeout_create(ANNOUNCE_WAIT,
							announce_wait_timeout,
							acd, NULL);
	}
}

static void defend_wait_timeout(struct l_timeout *timeout, void *user_data)
{
	struct l_acd *acd = user_data;

	l_timeout_remove(acd->timeout);
	acd->timeout = NULL;

	/* Successfully defended address */
	acd->state = ACD_STATE_ANNOUNCED;
}

static bool acd_read_handler(struct l_io *io, void *user_data)
{
	struct l_acd *acd = user_data;
	struct ether_arp arp;
	ssize_t len;
	int source_conflict;
	int target_conflict;
	bool probe;
	int err;

	memset(&arp, 0, sizeof(arp));
	len = read(l_io_get_fd(acd->io), &arp, sizeof(arp));
	if (len < 0)
		return false;

	if (len != sizeof(arp))
		return true;

	if (arp.arp_op != htons(ARPOP_REPLY) &&
			arp.arp_op != htons(ARPOP_REQUEST))
		return true;

	if (memcmp(arp.arp_sha, acd->mac, ETH_ALEN) == 0)
		return true;

	source_conflict = !memcmp(arp.arp_spa, &acd->ip, sizeof(uint32_t));
	probe = l_memeqzero(arp.arp_spa, sizeof(uint32_t));
	target_conflict = probe &&
		!memcmp(arp.arp_tpa, &acd->ip, sizeof(uint32_t));

	if (!source_conflict && !target_conflict)
		return true;

	switch (acd->state) {
	case ACD_STATE_PROBE:
		/* No reason to continue probing */
		ACD_DEBUG("%s conflict detected for "NIPQUAD_FMT,
				target_conflict ? "Target" : "Source",
				NIPQUAD(acd->ip));

		if (acd->event_func)
			acd->event_func(L_ACD_EVENT_CONFLICT, acd->user_data);

		l_acd_stop(acd);

		break;
	case ACD_STATE_ANNOUNCED:
		/* Only defend packets with a source conflict */
		if (!source_conflict)
			return true;

		/*
		 * RFC 5227 - Section 2.4 (a)
		 *
		 * "Upon receiving a conflicting ARP packet, a host MAY elect to
		 * immediately cease using the address, and signal an error to
		 * the configuring agent as described above."
		 */
		if (acd->policy == L_ACD_DEFEND_POLICY_NONE) {
			ACD_DEBUG("Conflict detected, giving up address");

			l_acd_stop(acd);

			if (acd->event_func)
				acd->event_func(L_ACD_EVENT_LOST,
							acd->user_data);

			break;
		}

		/*
		 * RFC 5227 - Section 2.4 (b)
		 * [If the host] "has not seen any other conflicting ARP packets
		 * within the last DEFEND_INTERVAL seconds, MAY elect to attempt
		 * to defend its address by recording the time that the
		 * conflicting ARP packet was received, and then broadcasting
		 * one single ARP Announcement"
		 */
		acd->state = ACD_STATE_DEFEND;

		/*
		 * We still have an initial announcement to send, but rather
		 * than wait for that (potentially 2 seconds) we can remove
		 * the timeout, send annouce now, and still transition to the
		 * defending state.
		 */
		if (acd->timeout)
			l_timeout_remove(acd->timeout);

		err = acd_send_packet(acd, acd->ip);
		if (err < 0)
			ACD_DEBUG("Failed to send initial announcement: %s",
					strerror(-err));

		ACD_DEBUG("Defending address");

		acd->timeout = l_timeout_create(DEFEND_INTERVAL,
						defend_wait_timeout, acd, NULL);

		break;
	case ACD_STATE_DEFEND:
		if (!source_conflict)
			return true;

		/*
		 * RFC 5227 Section 2.4 (c)
		 * "If a host has been configured such that it should not give
		 * up its address under any circumstances ... then it MAY elect
		 * to defend its address indefinitely."
		 */
		if (acd->policy == L_ACD_DEFEND_POLICY_INFINITE) {
			ACD_DEBUG("Conflict "MAC" found with infinite policy",
					MAC_STR(arp.arp_sha));

			/*
			 * Nothing to do at this point. We are in the DEFEND
			 * state meaning there is a defend wait timeout pending.
			 * Once that fires it will transition back into
			 * ANNOUNCED. Once in ANNOUNCED and another conflict is
			 * received, a single announcement will be sent. This
			 * ensures a maximum of only 1 announcement every
			 * DEFEND_INTERVAL seconds as long as conflicting
			 * packets are being received.
			 */
			break;
		}

		l_timeout_remove(acd->timeout);
		acd->timeout = NULL;

		ACD_DEBUG("Lost address");
		l_acd_stop(acd);

		/*
		* RFC 5227 Section 2.4(b)
		* "if this is not the first conflicting ARP packet the host has seen,
		* and the time recorded for the previous conflicting ARP packet is
		* recent, within DEFEND_INTERVAL seconds, then the host MUST
		* immediately cease using this address and signal an error to the
		* configuring agent"
		*/
		if (acd->event_func)
			acd->event_func(L_ACD_EVENT_LOST, acd->user_data);

		break;
	}

	return true;
}

LIB_EXPORT struct l_acd *l_acd_new(int ifindex)
{
	struct l_acd *acd = l_new(struct l_acd, 1);

	acd->ifindex = ifindex;
	acd->policy = L_ACD_DEFEND_POLICY_DEFEND;

	return acd;
}

LIB_EXPORT bool l_acd_start(struct l_acd *acd, const char *ip)
{
	struct in_addr ia;
	int fd;
	uint32_t delay;

	if (unlikely(!acd || !ip))
		return false;

	if (inet_pton(AF_INET, ip, &ia) != 1)
		return false;

	fd = acd_open_socket(acd->ifindex);
	if (fd < 0)
		return false;

	if (l_memeqzero(acd->mac, ETH_ALEN) &&
			!l_net_get_mac_address(acd->ifindex, acd->mac))
		goto err;

	acd->io = l_io_new(fd);
	if (!acd->io)
		goto err;

	l_io_set_close_on_destroy(acd->io, true);
	l_io_set_read_handler(acd->io, acd_read_handler, acd, NULL);

	acd->ip = ia.s_addr;

	/*
	 * Optimization to allows skipping the probe stage. The RFC does not
	 * mention allowing this, but probes take an eternity and would
	 * drastically increase connection times for wifi/eth. It is still
	 * recommended that probes be used for statically configured IP's where
	 * no DHCP server is involved.
	 */
	if (acd->skip_probes) {
		ACD_DEBUG("Skipping probes and sending announcements");

		acd->retries = 1;

		announce_wait_timeout(NULL, acd);

		return true;
	} else
		acd->state = ACD_STATE_PROBE;

	delay = _time_pick_interval_secs(0, PROBE_WAIT);

	ACD_DEBUG("Waiting %ums to send probe", delay);

	/*
	 * RFC 5227 - Section 2.1.1
	 * "When ready to begin probing, the host should then wait for a random
	 *  time interval selected uniformly in the range zero to PROBE_WAIT
	 *  seconds..."
	 */
	acd->timeout = l_timeout_create_ms(delay, probe_wait_timeout,
							acd, NULL);

	return true;

err:
	close(fd);
	return false;
}

LIB_EXPORT bool l_acd_set_event_handler(struct l_acd *acd,
					l_acd_event_func_t cb,
					void *user_data,
					l_acd_destroy_func_t destroy)
{
	if (unlikely(!acd))
		return false;

	acd->event_func = cb;
	acd->destroy = destroy;
	acd->user_data = user_data;

	return true;
}

LIB_EXPORT bool l_acd_stop(struct l_acd *acd)
{
	if (unlikely(!acd))
		return false;

	if (acd->timeout) {
		l_timeout_remove(acd->timeout);
		acd->timeout = NULL;
	}

	if (acd->io) {
		l_io_destroy(acd->io);
		acd->io = NULL;
	}

	return true;
}

LIB_EXPORT void l_acd_destroy(struct l_acd *acd)
{
	if (unlikely(!acd))
		return;

	l_acd_stop(acd);

	if (acd->destroy)
		acd->destroy(acd->user_data);

	l_free(acd);
}

LIB_EXPORT bool l_acd_set_debug(struct l_acd *acd,
				l_acd_debug_cb_t function,
				void *user_data, l_acd_destroy_func_t destory)
{
	if (unlikely(!acd))
		return false;

	acd->debug_handler = function;
	acd->debug_data = user_data;
	acd->debug_destroy = destory;

	return true;
}

LIB_EXPORT bool l_acd_set_skip_probes(struct l_acd *acd, bool skip)
{
	if (unlikely(!acd))
		return false;

	/* ACD has already been started */
	if (acd->io)
		return false;

	acd->skip_probes = skip;

	return true;
}

LIB_EXPORT bool l_acd_set_defend_policy(struct l_acd *acd,
				enum l_acd_defend_policy policy)
{
	if (unlikely(!acd))
		return false;

	/* ACD has already been started */
	if (acd->io)
		return false;

	acd->policy = policy;

	return true;
}
