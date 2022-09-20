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
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>

#include "strv.h"
#include "private.h"
#include "useful.h"
#include "dhcp6-private.h"
#include "dhcp6.h"
#include "net-private.h"

static inline char *get_ip(const uint8_t a[static 16])
{
	struct in6_addr addr;
	char buf[INET6_ADDRSTRLEN];

	memcpy(addr.s6_addr, a, 16);
	return l_strdup(inet_ntop(AF_INET6, &addr, buf, sizeof(buf)));
}

struct l_dhcp6_lease *_dhcp6_lease_new(void)
{
	struct l_dhcp6_lease *ret = l_new(struct l_dhcp6_lease, 1);

	return ret;
}

void _dhcp6_lease_free(struct l_dhcp6_lease *lease)
{
	if (!lease)
		return;

	l_free(lease->server_id);
	l_free(lease->dns);
	l_strfreev(lease->domain_list);

	l_free(lease);
}

static char **convert_ipv6_addresses(const void *a, uint16_t l)
{
	uint16_t i = 0;
	char **r;

	l >>= 4;
	r = l_new(char *, l + 1);

	while (i < l) {
		r[i++] = get_ip(a);
		a += 16;
	}

	return r;
}

static int parse_ia_address(const void *ia_addr, uint16_t ia_addr_len,
				struct dhcp6_address_info *out)
{
	struct dhcp6_option_iter iter;
	uint16_t t;
	uint16_t l;
	const void *v;
	uint32_t preferred_lifetime;
	uint32_t valid_lifetime;

	if (ia_addr_len < 24)
		return -EBADMSG;

	preferred_lifetime = l_get_be32(ia_addr + 16);
	valid_lifetime = l_get_be32(ia_addr + 20);

	/*
	 * TODO: The RFC allows valid_lifetime to be 0 in the case that the
	 * DHCP server might want to invalidate or take back an address.
	 * However, since the address space is so large, the use case for doing
	 * so is a bit unclear.  For now we do not treat this as a possibility
	 * that can happen and simply reject the option
	 */
	if (preferred_lifetime > valid_lifetime || !valid_lifetime)
		return -EINVAL;

	__dhcp6_option_iter_init(&iter, ia_addr + 24, ia_addr_len - 24);

	while (_dhcp6_option_iter_next(&iter, &t, &l, &v)) {
		uint16_t status;

		switch (t) {
		case DHCP6_OPTION_STATUS_CODE:
			if (l < 2)
				return -EBADMSG;

			status = l_get_be16(v);
			if (status != 0)
				return -EINVAL;

			break;
		}
	}

	memset(out, 0, sizeof(*out));
	memcpy(out->addr, ia_addr, sizeof(out->addr));
	out->preferred_lifetime = preferred_lifetime;
	out->valid_lifetime = valid_lifetime;

	return 0;
}

static int parse_ia_prefix(const void *ia_prefix, uint16_t ia_prefix_len,
				struct dhcp6_address_info *out)
{
	struct dhcp6_option_iter iter;
	uint16_t t;
	uint16_t l;
	const void *v;
	uint32_t preferred_lifetime;
	uint32_t valid_lifetime;

	if (ia_prefix_len < 25)
		return -EBADMSG;

	preferred_lifetime = l_get_be32(ia_prefix);
	valid_lifetime = l_get_be32(ia_prefix + 4);

	if (preferred_lifetime > valid_lifetime || !valid_lifetime)
		return -EINVAL;

	__dhcp6_option_iter_init(&iter, ia_prefix + 25, ia_prefix_len - 25);

	while (_dhcp6_option_iter_next(&iter, &t, &l, &v)) {
		uint16_t status;

		switch (t) {
		case DHCP6_OPTION_STATUS_CODE:
			if (l < 2)
				return -EBADMSG;

			status = l_get_be16(v);
			if (status != 0)
				return -EINVAL;

			break;
		}
	}

	memset(out, 0, sizeof(*out));
	out->prefix_len = l_get_u8(ia_prefix + 8);
	memcpy(out->addr, ia_prefix + 9, sizeof(out->addr));
	out->preferred_lifetime = preferred_lifetime;
	out->valid_lifetime = valid_lifetime;

	return 0;
}

static int parse_ia(const void *ia, uint16_t ia_len, uint16_t tag,
			const uint8_t expected_iaid[static 4],
			struct dhcp6_ia *out)
{
	struct dhcp6_option_iter iter;
	uint16_t t;
	uint16_t l;
	const void *v;
	uint32_t t1;
	uint32_t t2;
	struct dhcp6_address_info info;
	bool have_info = false;

	if (ia_len < 12)
		return -EBADMSG;

	if (memcmp(ia, expected_iaid, 4))
		return -EINVAL;

	t1 = l_get_be32(ia + 4);
	t2 = l_get_be32(ia + 8);

	/*
	 * RFC 8415, Section 21.4:
	 * "If a client receives an IA_NA with T1 greater than T2 and both T1
	 * and T2 are greater than 0, the client discards the IA_NA option and
	 * processes the remainder of the message as though the server had not
	 * included the invalid IA_NA option."
	 */
	if (t1 > t2 && t2)
		return -EINVAL;

	__dhcp6_option_iter_init(&iter, ia + 12, ia_len - 12);

	while (_dhcp6_option_iter_next(&iter, &t, &l, &v)) {
		uint16_t status;

		switch (t) {
		case DHCP6_OPTION_STATUS_CODE:
			if (l < 2)
				return -EBADMSG;

			status = l_get_be16(v);
			if (status != 0)
				return -EINVAL;

			break;
		case DHCP6_OPTION_IA_ADDR:
			if (tag != DHCP6_OPTION_IA_NA)
				return -EBADMSG;

			if (have_info || parse_ia_address(v, l, &info) < 0)
				continue;

			have_info = true;
			break;
		case DHCP6_OPTION_IA_PREFIX:
			if (tag != DHCP6_OPTION_IA_PD)
				return -EBADMSG;

			if (have_info || parse_ia_prefix(v, l, &info) < 0)
				continue;

			have_info = true;
			break;
		default:
			break;
		}
	}

	if (!have_info)
		return -EINVAL;

	memcpy(out->iaid, expected_iaid, 4);
	out->t1 = t1;
	out->t2 = t2;
	memcpy(&out->info, &info, sizeof(info));

	return 0;
}

struct l_dhcp6_lease *_dhcp6_lease_parse_options(
					struct dhcp6_option_iter *iter,
					const uint8_t expected_iaid[static 4])
{
	struct l_dhcp6_lease *lease = _dhcp6_lease_new();
	uint16_t t;
	uint16_t l;
	const void *v;

	while (_dhcp6_option_iter_next(iter, &t, &l, &v)) {
		switch (t) {
		case DHCP6_OPTION_SERVER_ID:
			lease->server_id = l_memdup(v, l);
			lease->server_id_len = l;
			break;
		case DHCP6_OPTION_PREFERENCE:
			if (l != 1)
				goto error;

			lease->preference = l_get_u8(v);
			break;
		case DHCP6_OPTION_IA_NA:
			if (lease->have_na ||
					parse_ia(v, l, t, expected_iaid,
							&lease->ia_na) < 0)
				continue;

			lease->have_na = true;
			break;
		case DHCP6_OPTION_IA_PD:
			if (lease->have_pd ||
					parse_ia(v, l, t, expected_iaid,
							&lease->ia_pd) < 0)
				continue;

			lease->have_pd = true;
			break;
		case L_DHCP6_OPTION_DNS_SERVERS:
			if (!l || l % sizeof(struct in6_addr))
				goto error;

			lease->dns = l_memdup(v, l);
			lease->dns_len = l;
			break;
		case DHCP6_OPTION_RAPID_COMMIT:
			if (l != 0)
				goto error;

			lease->rapid_commit = true;
			break;
		case L_DHCP6_OPTION_DOMAIN_LIST:
			lease->domain_list = net_domain_list_parse(v, l, false);
			if (!lease->domain_list)
				goto error;

			break;
		}
	}

	return lease;

error:
	_dhcp6_lease_free(lease);
	return NULL;
}

LIB_EXPORT char *l_dhcp6_lease_get_address(const struct l_dhcp6_lease *lease)
{
	if (unlikely(!lease))
		return NULL;

	if (!lease->have_na)
		return NULL;

	return get_ip(lease->ia_na.info.addr);
}

LIB_EXPORT char **l_dhcp6_lease_get_dns(const struct l_dhcp6_lease *lease)
{
	if (unlikely(!lease))
		return NULL;

	if (!lease->dns)
		return NULL;

	return convert_ipv6_addresses(lease->dns, lease->dns_len);
}

LIB_EXPORT char **l_dhcp6_lease_get_domains(const struct l_dhcp6_lease *lease)
{
	if (unlikely(!lease))
		return NULL;

	return l_strv_copy(lease->domain_list);
}

LIB_EXPORT uint8_t l_dhcp6_lease_get_prefix_length(
					const struct l_dhcp6_lease *lease)
{
	if (unlikely(!lease))
		return 0;

	if (lease->have_na)
		return 128;

	if (lease->have_pd)
		return lease->ia_pd.info.prefix_len;

	return 0;
}

#define PICK_IA() \
	const struct dhcp6_ia *ia;	\
					\
	if (lease->have_na)		\
		ia = &lease->ia_na;	\
	else if (lease->have_pd)	\
		ia = &lease->ia_pd;	\
	else				\
		return 0		\

uint32_t _dhcp6_lease_get_t1(const struct l_dhcp6_lease *lease)
{
	PICK_IA();

	if (ia->t1)
		return ia->t1;

	if (ia->info.valid_lifetime == 0xffffffffu)
		return ia->info.valid_lifetime;

	return ia->info.valid_lifetime / 2;
}

uint32_t _dhcp6_lease_get_t2(const struct l_dhcp6_lease *lease)
{
	PICK_IA();

	if (ia->t2)
		return ia->t2;

	if (ia->info.valid_lifetime == 0xffffffffu)
		return ia->info.valid_lifetime;

	return ia->info.valid_lifetime /  10 * 8;
}

LIB_EXPORT uint32_t l_dhcp6_lease_get_valid_lifetime(
					const struct l_dhcp6_lease *lease)
{
	if (unlikely(!lease))
		return 0;

	{
		PICK_IA();
		return ia->info.valid_lifetime;
	}
}

LIB_EXPORT uint32_t l_dhcp6_lease_get_preferred_lifetime(
					const struct l_dhcp6_lease *lease)
{
	if (unlikely(!lease))
		return 0;

	{
		PICK_IA();
		return ia->info.preferred_lifetime;
	}
}

/* Get the reception timestamp, i.e. when lifetimes are counted from */
LIB_EXPORT uint64_t l_dhcp6_lease_get_start_time(
					const struct l_dhcp6_lease *lease)
{
	if (unlikely(!lease))
		return 0;

	return lease->start_time;
}
