/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "private.h"
#include "useful.h"
#include "dhcp.h"
#include "dhcp-private.h"
#include "utf8.h"
#include "net.h"

struct l_dhcp_lease *_dhcp_lease_new(void)
{
	struct l_dhcp_lease *ret = l_new(struct l_dhcp_lease, 1);

	return ret;
}

void _dhcp_lease_free(struct l_dhcp_lease *lease)
{
	if (!lease)
		return;

	l_free(lease->dns);
	l_free(lease->domain_name);
	l_free(lease->client_id);

	l_free(lease);
}

struct l_dhcp_lease *_dhcp_lease_parse_options(struct dhcp_message_iter *iter)
{
	struct l_dhcp_lease *lease = _dhcp_lease_new();
	uint8_t t, l;
	const void *v;

	while (_dhcp_message_iter_next(iter, &t, &l, &v)) {
		switch (t) {
		case L_DHCP_OPTION_IP_ADDRESS_LEASE_TIME:
			if (l == 4)
				lease->lifetime = l_get_be32(v);
			break;
		case L_DHCP_OPTION_SERVER_IDENTIFIER:
			if (l == 4)
				lease->server_address = l_get_u32(v);
			break;
		case L_DHCP_OPTION_SUBNET_MASK:
			if (l == 4)
				lease->subnet_mask = l_get_u32(v);
			break;
		case L_DHCP_OPTION_ROUTER:
			if (l == 4)
				lease->router = l_get_u32(v);
			break;
		case L_DHCP_OPTION_RENEWAL_T1_TIME:
			if (l == 4)
				lease->t1 = l_get_be32(v);
			break;
		case L_DHCP_OPTION_REBINDING_T2_TIME:
			if (l == 4)
				lease->t2 = l_get_be32(v);
			break;
		case L_DHCP_OPTION_BROADCAST_ADDRESS:
			if (l == 4)
				lease->broadcast = l_get_u32(v);
			break;
		case L_DHCP_OPTION_DOMAIN_NAME_SERVER:
			if (lease->dns)
				goto error;

			if (l >= 4 && !(l % 4)) {
				unsigned i = 0;

				lease->dns = l_new(uint32_t, l / 4 + 1);

				while (l >= 4) {
					lease->dns[i] = l_get_u32(v + i * 4);
					l -= 4;

					if (lease->dns[i])
						i++;
				}
			}
			break;
		case L_DHCP_OPTION_DOMAIN_NAME:
			if (l < 1 || l > 253 || lease->domain_name)
				goto error;

			/* Disallow embedded NUL bytes. */
			if (memchr(v, 0, l - 1))
				goto error;

			/*
			 * RFC2132 doesn't say whether ending NULLs are present
			 * or not.  However, section 2 recommends that trailing
			 * NULLs should not be used but must not be treated
			 * as an error
			 */
			if (l_get_u8(v + l - 1) == 0)
				l -= 1;

			if (!l_utf8_validate(v, l, NULL))
				goto error;

			lease->domain_name = l_new(char, l + 1);

			memcpy(lease->domain_name, v, l);

			if (l_net_hostname_is_root(lease->domain_name))
				goto error;

			if (l_net_hostname_is_localhost(lease->domain_name))
				goto error;

			break;
		case DHCP_OPTION_CLIENT_IDENTIFIER:
			if (l < 1 || l > 253 || lease->client_id)
				goto error;

			lease->client_id = l_malloc(l + 1);
			lease->client_id[0] = l;
			memcpy(lease->client_id + 1, v, l);
			break;
		default:
			break;
		}
	}

	if (!lease->server_address || !lease->lifetime)
		goto error;

	if (lease->lifetime < 10)
		goto error;

	/*
	 * RFC2131, Section 3.3:
	 * "Throughout the protocol, times are to be represented in units of
	 * seconds.  The time value of 0xffffffff is reserved to represent
	 * "infinity"."
	 *
	 * Don't bother checking t1/t2 for infinite leases
	 */
	if (lease->lifetime == 0xffffffffu)
		return lease;

	if (!lease->t1)
		lease->t1 = lease->lifetime / 2;

	if (!lease->t2)
		lease->t2 = lease->lifetime / 8 * 7;

	if (lease->t1 > lease->t2)
		goto error;

	if (lease->t2 > lease->lifetime)
		goto error;

	return lease;
error:
	_dhcp_lease_free(lease);
	return NULL;
}

static inline char *get_ip(uint32_t ip)
{
	struct in_addr addr;
	char buf[INET_ADDRSTRLEN];

	if (ip == 0)
		return NULL;

	addr.s_addr = ip;
	return l_strdup(inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN));
}

LIB_EXPORT char *l_dhcp_lease_get_address(const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return NULL;

	return get_ip(lease->address);
}

LIB_EXPORT uint32_t l_dhcp_lease_get_address_u32(
					const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return 0;

	return lease->address;
}

LIB_EXPORT char *l_dhcp_lease_get_gateway(const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return NULL;

	return get_ip(lease->router);
}

LIB_EXPORT uint32_t l_dhcp_lease_get_gateway_u32(
					const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return 0;

	return lease->router;
}

LIB_EXPORT char *l_dhcp_lease_get_netmask(const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return NULL;

	return get_ip(lease->subnet_mask);
}

LIB_EXPORT uint32_t l_dhcp_lease_get_netmask_u32(
					const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return 0;

	return lease->subnet_mask;
}

LIB_EXPORT uint32_t l_dhcp_lease_get_prefix_length(
					const struct l_dhcp_lease *lease)
{
	int pl;

	if (unlikely(!lease))
		return 0;

	if (!lease->subnet_mask)
		return 0;

	pl = __builtin_popcount(lease->subnet_mask);

	if (__builtin_ctz(L_BE32_TO_CPU(lease->subnet_mask)) != 32 - pl)
		return 0;

	return pl;
}

LIB_EXPORT char *l_dhcp_lease_get_broadcast(const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return NULL;

	return get_ip(lease->broadcast);
}

LIB_EXPORT char *l_dhcp_lease_get_server_id(const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return NULL;

	return get_ip(lease->server_address);
}

LIB_EXPORT const uint8_t *l_dhcp_lease_get_server_mac(
					const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return NULL;

	if (l_memeqzero(lease->server_mac, sizeof(lease->server_mac)))
		return NULL;

	return lease->server_mac;
}

LIB_EXPORT char **l_dhcp_lease_get_dns(const struct l_dhcp_lease *lease)
{
	unsigned i;
	char **dns_list;

	if (unlikely(!lease))
		return NULL;

	if (!lease->dns)
		return NULL;

	for (i = 0; lease->dns[i]; i++)
		;

	dns_list = l_new(char *, i + 1);

	for (i = 0; lease->dns[i]; i++)
		dns_list[i] = get_ip(lease->dns[i]);

	return dns_list;
}

LIB_EXPORT char *l_dhcp_lease_get_domain_name(const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return NULL;

	return l_strdup(lease->domain_name);
}

LIB_EXPORT uint32_t l_dhcp_lease_get_t1(const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return 0;

	return lease->t1;
}

LIB_EXPORT uint32_t l_dhcp_lease_get_t2(const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return 0;

	return lease->t2;
}

LIB_EXPORT uint32_t l_dhcp_lease_get_lifetime(const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return 0;

	return lease->lifetime;
}

LIB_EXPORT uint64_t l_dhcp_lease_get_start_time(
					const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return 0;

	return lease->bound_time;
}

LIB_EXPORT const uint8_t *l_dhcp_lease_get_mac(const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return NULL;

	return lease->mac;
}
