/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
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
#include <linux/if.h>
#include <linux/icmpv6.h>
#include <linux/neighbour.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#include "useful.h"
#include "netlink.h"
#include "log.h"
#include "util.h"
#include "time.h"
#include "rtnl-private.h"
#include "rtnl.h"
#include "private.h"

static struct l_netlink *rtnl;

struct l_rtnl_address {
	uint8_t family;
	uint8_t prefix_len;
	uint8_t scope;
	union {
		struct in6_addr in6_addr;
		struct in_addr in_addr;
	};
	struct in_addr broadcast;
	char label[IFNAMSIZ];
	uint32_t preferred_lifetime;
	uint32_t valid_lifetime;
	uint64_t preferred_expiry_time;
	uint64_t valid_expiry_time;
	uint32_t flags;
};

static inline int address_to_string(int family, const struct in_addr *v4,
					const struct in6_addr *v6,
					char *out_address)
{
	switch (family) {
	case AF_INET:
		if (!inet_ntop(family, v4, out_address, INET_ADDRSTRLEN))
			return -errno;
		break;
	case AF_INET6:
		if (!inet_ntop(family, v6, out_address, INET6_ADDRSTRLEN))
			return -errno;
		break;
	default:
		return -EAFNOSUPPORT;
	}

	return 0;
}

static int address_get(const char *ip, struct in_addr *out_v4,
				struct in6_addr *out_v6)
{
	if (inet_pton(AF_INET, ip, out_v4) == 1)
		return AF_INET;

	if (inet_pton(AF_INET6, ip, out_v6) == 1)
		return AF_INET6;

	return -EINVAL;
}

static int address_is_null(int family, const struct in_addr *v4,
						const struct in6_addr *v6)
{
	switch (family) {
	case AF_INET:
		return v4->s_addr == 0;
	case AF_INET6:
		return IN6_IS_ADDR_UNSPECIFIED(v6);
	}

	return -EAFNOSUPPORT;
}

static inline void _rtnl_address_init(struct l_rtnl_address *addr,
					uint8_t prefix_len)
{
	addr->prefix_len = prefix_len;
	addr->scope = RT_SCOPE_UNIVERSE;
	addr->flags = IFA_F_PERMANENT;
	memset(addr->label, 0, sizeof(addr->label));
	addr->preferred_lifetime = 0;
	addr->valid_lifetime = 0;
	addr->preferred_expiry_time = 0;
	addr->valid_expiry_time = 0;

	l_rtnl_address_set_broadcast(addr, NULL);
}

static bool rtnl_address_init(struct l_rtnl_address *addr,
				const char *ip, uint8_t prefix_len)
{
	int family;

	if ((family = address_get(ip, &addr->in_addr, &addr->in6_addr)) < 0)
		return false;

	addr->family = family;
	_rtnl_address_init(addr, prefix_len);
	return true;
}

LIB_EXPORT struct l_rtnl_address *l_rtnl_address_new(const char *ip,
							uint8_t prefix_len)
{
	struct in_addr in_addr;
	struct in6_addr in6_addr;
	int family;
	struct l_rtnl_address *addr;

	if ((family = address_get(ip, &in_addr, &in6_addr)) < 0)
		return NULL;

	addr = l_new(struct l_rtnl_address, 1);
	_rtnl_address_init(addr, prefix_len);
	addr->family = family;

	if (family == AF_INET6)
		memcpy(&addr->in6_addr, &in6_addr, sizeof(in6_addr));
	else
		memcpy(&addr->in_addr, &in_addr, sizeof(in_addr));

	return addr;
}

LIB_EXPORT struct l_rtnl_address *l_rtnl_address_clone(
					const struct l_rtnl_address *orig)
{
	return l_memdup(orig, sizeof(struct l_rtnl_address));
}

LIB_EXPORT void l_rtnl_address_free(struct l_rtnl_address *addr)
{
	l_free(addr);
}

LIB_EXPORT bool l_rtnl_address_get_address(const struct l_rtnl_address *addr,
						char *out_buf)
{
	if (unlikely(!addr))
		return false;

	return !address_to_string(addr->family, &addr->in_addr,
						&addr->in6_addr,
						out_buf);
}

LIB_EXPORT const void *l_rtnl_address_get_in_addr(
					const struct l_rtnl_address *addr)
{
	if (unlikely(!addr))
		return NULL;

	return addr->family == AF_INET ? (void *) &addr->in_addr : &addr->in6_addr;
}

LIB_EXPORT uint8_t l_rtnl_address_get_family(const struct l_rtnl_address *addr)
{
	if (unlikely(!addr))
		return 0;

	return addr->family;
}

LIB_EXPORT uint8_t l_rtnl_address_get_prefix_length(
					const struct l_rtnl_address *addr)
{
	if (unlikely(!addr))
		return 0;

	return addr->prefix_len;
}

LIB_EXPORT bool l_rtnl_address_get_broadcast(const struct l_rtnl_address *addr,
						char *out_buf)
{
	if (unlikely(!addr))
		return false;

	inet_ntop(AF_INET, &addr->broadcast, out_buf, INET_ADDRSTRLEN);
	return true;
}

LIB_EXPORT bool l_rtnl_address_set_broadcast(struct l_rtnl_address *addr,
						const char *broadcast)
{
	if (unlikely(!addr))
		return false;

	if (unlikely(addr->family != AF_INET))
		return false;

	if (broadcast) {
		if (inet_pton(AF_INET, broadcast, &addr->broadcast) != 1)
			return false;
	} else
		addr->broadcast.s_addr = addr->in_addr.s_addr |
					htonl(0xFFFFFFFFLU >> addr->prefix_len);

	return true;
}

LIB_EXPORT const char *l_rtnl_address_get_label(
					const struct l_rtnl_address *addr)
{
	if (unlikely(!addr))
		return NULL;

	return addr->label;
}

LIB_EXPORT bool l_rtnl_address_set_label(struct l_rtnl_address *addr,
						const char *label)
{
	if (unlikely(!addr))
		return false;

	if (strlen(label) > IFNAMSIZ - 1)
		return false;

	l_strlcpy(addr->label, label, IFNAMSIZ);
	return true;
}

LIB_EXPORT bool l_rtnl_address_set_noprefixroute(struct l_rtnl_address *addr,
							bool noprefixroute)
{
	if (unlikely(!addr))
		return false;

	if (noprefixroute)
		addr->flags |= IFA_F_NOPREFIXROUTE;
	else
		addr->flags &= ~IFA_F_NOPREFIXROUTE;

	return true;
}

LIB_EXPORT uint32_t l_rtnl_address_get_valid_lifetime(
					const struct l_rtnl_address *addr)
{
	if (unlikely(!addr))
		return false;

	return addr->valid_lifetime;
}

LIB_EXPORT uint32_t l_rtnl_address_get_preferred_lifetime(
					const struct l_rtnl_address *addr)
{
	if (unlikely(!addr))
		return false;

	return addr->preferred_lifetime;
}

LIB_EXPORT bool l_rtnl_address_set_lifetimes(struct l_rtnl_address *addr,
						uint32_t preferred_lifetime,
						uint32_t valid_lifetime)
{
	uint64_t now = l_time_now();

	if (unlikely(!addr))
		return false;

	addr->preferred_lifetime = preferred_lifetime;
	addr->valid_lifetime = valid_lifetime;
	addr->preferred_expiry_time = preferred_lifetime ?
		now + preferred_lifetime * L_USEC_PER_SEC : 0;
	addr->valid_expiry_time = valid_lifetime ?
		now + valid_lifetime * L_USEC_PER_SEC : 0;
	return true;
}

LIB_EXPORT bool l_rtnl_address_get_expiry(const struct l_rtnl_address *addr,
						uint64_t *preferred_expiry_time,
						uint64_t *valid_expiry_time)
{
	if (unlikely(!addr))
		return false;

	if (preferred_expiry_time)
		*preferred_expiry_time = addr->preferred_expiry_time;

	if (valid_expiry_time)
		*valid_expiry_time = addr->valid_expiry_time;

	return true;
}

LIB_EXPORT bool l_rtnl_address_set_expiry(struct l_rtnl_address *addr,
						uint64_t preferred_expiry_time,
						uint64_t valid_expiry_time)
{
	if (unlikely(!addr))
		return false;

	addr->preferred_expiry_time = preferred_expiry_time;
	addr->valid_expiry_time = valid_expiry_time;
	return true;
}

LIB_EXPORT bool l_rtnl_address_set_scope(struct l_rtnl_address *addr,
								uint8_t scope)
{
	if (unlikely(!addr))
		return false;

	addr->scope = scope;
	return true;
}

LIB_EXPORT struct l_rtnl_route *l_rtnl_route_new_gateway(const char *gw)
{
	struct in_addr in_addr;
	struct in6_addr in6_addr;
	int family;
	struct l_rtnl_route *rt;

	if ((family = address_get(gw, &in_addr, &in6_addr)) < 0)
		return NULL;

	rt = l_new(struct l_rtnl_route, 1);
	rt->family = family;
	rt->scope = RT_SCOPE_UNIVERSE;
	rt->protocol = RTPROT_UNSPEC;
	rt->lifetime = 0xffffffff;

	if (family == AF_INET6)
		memcpy(&rt->gw.in6_addr, &in6_addr, sizeof(in6_addr));
	else
		memcpy(&rt->gw.in_addr, &in_addr, sizeof(in_addr));

	return rt;
}

LIB_EXPORT struct l_rtnl_route *l_rtnl_route_new_prefix(const char *ip,
							uint8_t prefix_len)
{
	struct in_addr in_addr;
	struct in6_addr in6_addr;
	int family;
	struct l_rtnl_route *rt;

	if ((family = address_get(ip, &in_addr, &in6_addr)) < 0)
		return NULL;

	if (!prefix_len)
		return NULL;

	if (family == AF_INET && prefix_len > 32)
		return NULL;

	if (family == AF_INET6 && prefix_len > 128)
		return NULL;

	rt = l_new(struct l_rtnl_route, 1);
	rt->family = family;
	rt->protocol = RTPROT_UNSPEC;
	rt->lifetime = 0xffffffff;
	rt->dst_prefix_len = prefix_len;

	/* IPV6 prefix routes are usually global, IPV4 are link-local */
	if (family == AF_INET6) {
		memcpy(&rt->dst.in6_addr, &in6_addr, sizeof(in6_addr));
		rt->scope = RT_SCOPE_UNIVERSE;
	} else {
		memcpy(&rt->dst.in_addr, &in_addr, sizeof(in_addr));
		rt->scope = RT_SCOPE_LINK;
	}

	return rt;
}

LIB_EXPORT struct l_rtnl_route *l_rtnl_route_new_static(const char *gw,
							const char *ip,
							uint8_t prefix_len)
{
	struct in_addr gw_addr4;
	struct in6_addr gw_addr6;
	struct in_addr dst_addr4;
	struct in6_addr dst_addr6;
	int family;
	struct l_rtnl_route *rt;

	if ((family = address_get(gw, &gw_addr4, &gw_addr6)) < 0)
		return NULL;

	if (address_get(ip, &dst_addr4, &dst_addr6) != family)
		return NULL;

	if (prefix_len == 0 || prefix_len > (family == AF_INET ? 32 : 128))
		return NULL;

	rt = l_rtnl_route_new_gateway(gw);
	if (!rt)
		return rt;

	rt->dst_prefix_len = prefix_len;

	if (family == AF_INET6)
		memcpy(&rt->dst.in6_addr, &dst_addr6, sizeof(dst_addr6));
	else
		memcpy(&rt->dst.in_addr, &dst_addr4, sizeof(dst_addr4));

	return rt;
}

LIB_EXPORT void l_rtnl_route_free(struct l_rtnl_route *rt)
{
	l_free(rt);
}

LIB_EXPORT uint8_t l_rtnl_route_get_family(const struct l_rtnl_route *rt)
{
	if (unlikely(!rt))
		return 0;

	return rt->family;
}

LIB_EXPORT bool l_rtnl_route_get_gateway(const struct l_rtnl_route *rt,
						char *out_buf)
{
	if (unlikely(!rt))
		return false;

	if (address_is_null(rt->family, &rt->gw.in_addr, &rt->gw.in6_addr))
		return false;

	return !address_to_string(rt->family, &rt->gw.in_addr, &rt->gw.in6_addr,
					out_buf);
}

LIB_EXPORT const void *l_rtnl_route_get_gateway_in_addr(
						const struct l_rtnl_route *rt)
{
	if (unlikely(!rt))
		return NULL;

	if (address_is_null(rt->family, &rt->gw.in_addr, &rt->gw.in6_addr))
		return NULL;

	if (rt->family == AF_INET)
		return &rt->gw.in_addr;
	else
		return &rt->gw.in6_addr;
}

LIB_EXPORT bool l_rtnl_route_get_dst(const struct l_rtnl_route *rt,
						char *out_buf,
						uint8_t *out_prefix_len)
{
	if (unlikely(!rt))
		return false;

	if (address_to_string(rt->family, &rt->dst.in_addr, &rt->dst.in6_addr,
					out_buf) != 0)
		return false;

	*out_prefix_len = rt->dst_prefix_len;
	return true;
}

LIB_EXPORT const void *l_rtnl_route_get_dst_in_addr(
						const struct l_rtnl_route *rt,
						uint8_t *out_prefix_len)
{
	if (unlikely(!rt))
		return NULL;

	*out_prefix_len = rt->dst_prefix_len;

	if (rt->family == AF_INET)
		return &rt->dst.in_addr;
	else
		return &rt->dst.in6_addr;
}

LIB_EXPORT uint32_t l_rtnl_route_get_lifetime(const struct l_rtnl_route *rt)
{
	if (unlikely(!rt))
		return 0;

	return rt->lifetime;
}

LIB_EXPORT bool l_rtnl_route_set_lifetime(struct l_rtnl_route *rt, uint32_t lt)
{
	if (unlikely(!rt))
		return false;

	rt->lifetime = lt;
	rt->expiry_time = lt ? l_time_now() + lt * L_USEC_PER_SEC : 0;

	return true;
}

LIB_EXPORT uint64_t l_rtnl_route_get_expiry(const struct l_rtnl_route *rt)
{
	return rt->expiry_time;
}

LIB_EXPORT bool l_rtnl_route_set_expiry(struct l_rtnl_route *rt,
					uint64_t expiry_time)
{
	if (unlikely(!rt))
		return false;

	rt->expiry_time = expiry_time;
	return true;
}

LIB_EXPORT uint32_t l_rtnl_route_get_mtu(const struct l_rtnl_route *rt)
{
	if (unlikely(!rt))
		return 0;

	return rt->mtu;
}

LIB_EXPORT bool l_rtnl_route_set_mtu(struct l_rtnl_route *rt, uint32_t mtu)
{
	if (unlikely(!rt))
		return false;

	rt->mtu = mtu;
	return true;
}

LIB_EXPORT uint8_t l_rtnl_route_get_preference(const struct l_rtnl_route *rt)
{
	if (unlikely(!rt))
		return ICMPV6_ROUTER_PREF_INVALID;

	return rt->preference;
}

LIB_EXPORT bool l_rtnl_route_set_preference(struct l_rtnl_route *rt,
							uint8_t preference)
{
	if (unlikely(!rt))
		return false;

	if (!L_IN_SET(preference, ICMPV6_ROUTER_PREF_LOW,
			ICMPV6_ROUTER_PREF_HIGH, ICMPV6_ROUTER_PREF_MEDIUM))
		return false;

	rt->preference = preference;
	return true;
}

LIB_EXPORT bool l_rtnl_route_get_prefsrc(const struct l_rtnl_route *rt,
						char *out_address)
{
	if (unlikely(!rt))
		return false;

	if (address_is_null(rt->family, &rt->prefsrc.in_addr,
					&rt->prefsrc.in6_addr))
		return false;

	return !address_to_string(rt->family, &rt->prefsrc.in_addr,
						&rt->prefsrc.in6_addr,
						out_address);
}

LIB_EXPORT bool l_rtnl_route_set_prefsrc(struct l_rtnl_route *rt,
							const char *address)
{
	if (unlikely(!rt))
		return false;

	switch(rt->family) {
	case AF_INET:
		return inet_pton(AF_INET, address, &rt->prefsrc.in_addr) == 1;
	case AF_INET6:
		return inet_pton(AF_INET6, address, &rt->prefsrc.in6_addr) == 1;
	default:
		return  false;
	}
}

LIB_EXPORT uint32_t l_rtnl_route_get_priority(const struct l_rtnl_route *rt)
{
	if (unlikely(!rt))
		return 0;

	return rt->priority;
}

LIB_EXPORT bool l_rtnl_route_set_priority(struct l_rtnl_route *rt,
							uint32_t priority)
{
	if (unlikely(!rt))
		return false;

	rt->priority = priority;
	return true;
}

LIB_EXPORT uint8_t l_rtnl_route_get_protocol(const struct l_rtnl_route *rt)
{
	if (unlikely(!rt))
		return RTPROT_UNSPEC;

	return rt->protocol;
}

LIB_EXPORT bool l_rtnl_route_set_protocol(struct l_rtnl_route *rt,
							uint8_t protocol)
{
	if (unlikely(!rt))
		return false;

	rt->protocol = protocol;
	return true;
}

LIB_EXPORT uint8_t l_rtnl_route_get_scope(const struct l_rtnl_route *rt)
{
	if (unlikely(!rt))
		return RT_SCOPE_NOWHERE;

	return rt->scope;
}

LIB_EXPORT bool l_rtnl_route_set_scope(struct l_rtnl_route *rt, uint8_t scope)
{
	if (unlikely(!rt))
		return false;

	rt->scope = scope;
	return true;
}

static size_t rta_add_u8(void *rta_buf, unsigned short type, uint8_t value)
{
	struct rtattr *rta = rta_buf;

	rta->rta_len = RTA_LENGTH(sizeof(uint8_t));
	rta->rta_type = type;
	*((uint8_t *) RTA_DATA(rta)) = value;

	return RTA_SPACE(sizeof(uint8_t));
}

static size_t rta_add_u32(void *rta_buf, unsigned short type, uint32_t value)
{
	struct rtattr *rta = rta_buf;

	rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
	rta->rta_type = type;
	*((uint32_t *) RTA_DATA(rta)) = value;

	return RTA_SPACE(sizeof(uint32_t));
}

static size_t rta_add_data(void *rta_buf, unsigned short type, const void *data,
								size_t data_len)
{
	struct rtattr *rta = rta_buf;

	rta->rta_len = RTA_LENGTH(data_len);
	rta->rta_type = type;
	memcpy(RTA_DATA(rta), data, data_len);

	return RTA_SPACE(data_len);
}

static size_t rta_add_address(void *rta_buf, unsigned short type,
				uint8_t family,
				const struct in6_addr *v6,
				const struct in_addr *v4)
{
	struct rtattr *rta = rta_buf;

	rta->rta_type = type;

	switch (family) {
	case AF_INET6:
		rta->rta_len = RTA_LENGTH(sizeof(struct in6_addr));
		memcpy(RTA_DATA(rta), v6, sizeof(struct in6_addr));
		return RTA_SPACE(sizeof(struct in6_addr));
	case AF_INET:
		rta->rta_len = RTA_LENGTH(sizeof(struct in_addr));
		memcpy(RTA_DATA(rta), v4, sizeof(struct in_addr));
		return RTA_SPACE(sizeof(struct in_addr));
	}

	return 0;
}

static void l_rtnl_route_extract(const struct rtmsg *rtmsg, uint32_t len,
				int family, uint32_t *table, uint32_t *ifindex,
				uint32_t *priority, uint8_t *pref,
				char **dst, char **gateway, char **src)
{
	struct rtattr *attr;
	char buf[INET6_ADDRSTRLEN];

	/* Not extracted at the moment: RTA_CACHEINFO for IPv6 */
	for (attr = RTM_RTA(rtmsg); RTA_OK(attr, len);
						attr = RTA_NEXT(attr, len)) {
		switch (attr->rta_type) {
		case RTA_DST:
			if (!dst)
				break;

			inet_ntop(family, RTA_DATA(attr), buf, sizeof(buf));
			*dst = l_strdup(buf);

			break;
		case RTA_GATEWAY:
			if (!gateway)
				break;

			inet_ntop(family, RTA_DATA(attr), buf, sizeof(buf));
			*gateway = l_strdup(buf);

			break;
		case RTA_PREFSRC:
			if (!src)
				break;

			inet_ntop(family, RTA_DATA(attr), buf, sizeof(buf));
			*src = l_strdup(buf);

			break;
		case RTA_TABLE:
			if (!table)
				break;

			*table = *((uint32_t *) RTA_DATA(attr));
			break;
		case RTA_PRIORITY:
			if (!priority)
				break;

			*priority = *((uint32_t *) RTA_DATA(attr));
			break;
		case RTA_PREF:
			if (!pref)
				break;

			*pref = *((uint8_t *) RTA_DATA(attr));
			break;
		case RTA_OIF:
			if (!ifindex)
				break;

			*ifindex = *((uint32_t *) RTA_DATA(attr));
			break;
		}
	}
}

LIB_EXPORT uint32_t l_rtnl_set_linkmode_and_operstate(struct l_netlink *rtnl,
					int ifindex,
					uint8_t linkmode, uint8_t operstate,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct ifinfomsg *rtmmsg;
	void *rta_buf;
	size_t bufsize;
	uint32_t id;

	bufsize = NLMSG_ALIGN(sizeof(struct ifinfomsg)) +
		RTA_SPACE(sizeof(uint8_t)) + RTA_SPACE(sizeof(uint8_t));

	rtmmsg = l_malloc(bufsize);
	memset(rtmmsg, 0, bufsize);

	rtmmsg->ifi_family = AF_UNSPEC;
	rtmmsg->ifi_index = ifindex;

	rta_buf = (void *) rtmmsg + NLMSG_ALIGN(sizeof(struct ifinfomsg));

	rta_buf += rta_add_u8(rta_buf, IFLA_LINKMODE, linkmode);
	rta_buf += rta_add_u8(rta_buf, IFLA_OPERSTATE, operstate);

	id = l_netlink_send(rtnl, RTM_SETLINK, 0, rtmmsg,
					rta_buf - (void *) rtmmsg,
					cb, user_data, destroy);
	l_free(rtmmsg);

	return id;
}

LIB_EXPORT uint32_t l_rtnl_set_mac(struct l_netlink *rtnl, int ifindex,
					const uint8_t addr[static 6],
					bool power_up,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct ifinfomsg *rtmmsg;
	void *rta_buf;
	size_t bufsize;
	uint32_t id;

	bufsize = NLMSG_ALIGN(sizeof(struct ifinfomsg)) + RTA_SPACE(6);

	rtmmsg = l_malloc(bufsize);
	memset(rtmmsg, 0, bufsize);

	rtmmsg->ifi_family = AF_UNSPEC;
	rtmmsg->ifi_index = ifindex;

	if (power_up) {
		rtmmsg->ifi_change = IFF_UP;
		rtmmsg->ifi_flags = IFF_UP;
	}

	rta_buf = (void *) rtmmsg + NLMSG_ALIGN(sizeof(struct ifinfomsg));

	rta_buf += rta_add_data(rta_buf, IFLA_ADDRESS, (void *) addr, 6);

	id = l_netlink_send(rtnl, RTM_SETLINK, 0, rtmmsg,
					rta_buf - (void *) rtmmsg,
					cb, user_data, destroy);
	l_free(rtmmsg);

	return id;
}

LIB_EXPORT uint32_t l_rtnl_set_powered(struct l_netlink *rtnl, int ifindex,
				bool powered,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy)
{
	struct ifinfomsg *rtmmsg;
	size_t bufsize;
	uint32_t id;

	bufsize = NLMSG_ALIGN(sizeof(struct ifinfomsg));

	rtmmsg = l_malloc(bufsize);
	memset(rtmmsg, 0, bufsize);

	rtmmsg->ifi_family = AF_UNSPEC;
	rtmmsg->ifi_index = ifindex;
	rtmmsg->ifi_change = IFF_UP;
	rtmmsg->ifi_flags = powered ? IFF_UP : 0;

	id = l_netlink_send(rtnl, RTM_SETLINK, 0, rtmmsg, bufsize,
					cb, user_data, destroy);
	l_free(rtmmsg);

	return id;
}

LIB_EXPORT void l_rtnl_ifaddr4_extract(const struct ifaddrmsg *ifa, int bytes,
				char **label, char **ip, char **broadcast)
{
	char buf[INET_ADDRSTRLEN];
	struct in_addr in_addr;
	struct rtattr *attr;

	for (attr = IFA_RTA(ifa); RTA_OK(attr, bytes);
						attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case IFA_LOCAL:
			if (!ip)
				break;

			in_addr = *((struct in_addr *) RTA_DATA(attr));
			*ip = l_strdup(inet_ntop(AF_INET, &in_addr, buf,
							INET_ADDRSTRLEN));

			break;
		case IFA_BROADCAST:
			if (!broadcast)
				break;

			in_addr = *((struct in_addr *) RTA_DATA(attr));
			*broadcast = l_strdup(inet_ntop(AF_INET, &in_addr, buf,
							INET_ADDRSTRLEN));

			break;
		case IFA_LABEL:
			if (!label)
				break;

			*label = l_strdup(RTA_DATA(attr));
			break;
		}
	}
}

LIB_EXPORT uint32_t l_rtnl_ifaddr4_dump(struct l_netlink *rtnl,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct ifaddrmsg *rtmmsg;
	uint32_t id;

	rtmmsg = l_malloc(sizeof(struct ifaddrmsg));
	memset(rtmmsg, 0, sizeof(struct ifaddrmsg));

	rtmmsg->ifa_family = AF_INET;

	id = l_netlink_send(rtnl, RTM_GETADDR, NLM_F_DUMP, rtmmsg,
				sizeof(struct ifaddrmsg), cb, user_data,
				destroy);

	l_free(rtmmsg);

	return id;
}

LIB_EXPORT uint32_t l_rtnl_ifaddr4_add(struct l_netlink *rtnl, int ifindex,
				uint8_t prefix_len, const char *ip,
				const char *broadcast,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy)
{
	struct l_rtnl_address a4;

	if (!rtnl_address_init(&a4, ip, prefix_len))
		return 0;

	if (broadcast)
		if (!l_rtnl_address_set_broadcast(&a4, broadcast))
			return 0;

	return l_rtnl_ifaddr_add(rtnl, ifindex, &a4, cb, user_data, destroy);
}

LIB_EXPORT uint32_t l_rtnl_ifaddr4_delete(struct l_netlink *rtnl, int ifindex,
				uint8_t prefix_len, const char *ip,
				const char *broadcast,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy)
{
	struct l_rtnl_address a4;

	if (!rtnl_address_init(&a4, ip, prefix_len))
		return 0;

	if (broadcast)
		if (!l_rtnl_address_set_broadcast(&a4, broadcast))
			return 0;

	return l_rtnl_ifaddr_delete(rtnl, ifindex, &a4, cb, user_data, destroy);
}

LIB_EXPORT void l_rtnl_route4_extract(const struct rtmsg *rtmsg, uint32_t len,
				uint32_t *table, uint32_t *ifindex,
				char **dst, char **gateway, char **src)
{
	l_rtnl_route_extract(rtmsg, len, AF_INET, table, ifindex,
				NULL, NULL, dst, gateway, src);
}

LIB_EXPORT uint32_t l_rtnl_route4_dump(struct l_netlink *rtnl,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy)
{
	struct rtmsg rtmsg;

	memset(&rtmsg, 0, sizeof(struct rtmsg));
	rtmsg.rtm_family = AF_INET;

	return l_netlink_send(rtnl, RTM_GETROUTE, NLM_F_DUMP, &rtmsg,
					sizeof(struct rtmsg), cb, user_data,
					destroy);
}

LIB_EXPORT uint32_t l_rtnl_route4_add_connected(struct l_netlink *rtnl,
					int ifindex,
					uint8_t dst_len, const char *dst,
					const char *src, uint8_t proto,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct l_rtnl_route *rt = l_rtnl_route_new_prefix(dst, dst_len);
	uint32_t r = 0;

	if (!rt)
		return 0;

	l_rtnl_route_set_protocol(rt, proto);
	if (!l_rtnl_route_set_prefsrc(rt, src))
		goto err;

	r = l_rtnl_route_add(rtnl, ifindex, rt, cb, user_data, destroy);
err:
	l_rtnl_route_free(rt);
	return r;
}

LIB_EXPORT uint32_t l_rtnl_route4_add_gateway(struct l_netlink *rtnl,
					int ifindex,
					const char *gateway, const char *src,
					uint32_t priority_offset,
					uint8_t proto,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct l_rtnl_route *rt = l_rtnl_route_new_gateway(gateway);
	uint32_t r;

	if (!rt)
		return 0;

	l_rtnl_route_set_protocol(rt, proto);
	l_rtnl_route_set_priority(rt, priority_offset);

	r = l_rtnl_route_add(rtnl, ifindex, rt, cb, user_data, destroy);
	l_rtnl_route_free(rt);
	return r;
}

LIB_EXPORT void l_rtnl_ifaddr6_extract(const struct ifaddrmsg *ifa, int len,
					char **ip)
{
	struct in6_addr in6_addr;
	struct rtattr *attr;
	char address[128];

	for (attr = IFA_RTA(ifa); RTA_OK(attr, len);
						attr = RTA_NEXT(attr, len)) {
		switch (attr->rta_type) {
		case IFA_ADDRESS:
			if (!ip)
				break;

			memcpy(&in6_addr.s6_addr, RTA_DATA(attr),
						sizeof(in6_addr.s6_addr));

			if (!inet_ntop(AF_INET6, &in6_addr, address,
							INET6_ADDRSTRLEN)) {
				l_error("rtnl: Failed to extract IPv6 address");
				break;
			}

			*ip = l_strdup(address);

			break;
		}
	}
}

LIB_EXPORT uint32_t l_rtnl_ifaddr6_dump(struct l_netlink *rtnl,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy)
{
	struct ifaddrmsg *rtmmsg;
	uint32_t id;

	rtmmsg = l_malloc(sizeof(struct ifaddrmsg));
	memset(rtmmsg, 0, sizeof(struct ifaddrmsg));

	rtmmsg->ifa_family = AF_INET6;

	id = l_netlink_send(rtnl, RTM_GETADDR, NLM_F_DUMP, rtmmsg,
				sizeof(struct ifaddrmsg), cb, user_data,
				destroy);

	l_free(rtmmsg);

	return id;
}

LIB_EXPORT uint32_t l_rtnl_ifaddr6_add(struct l_netlink *rtnl, int ifindex,
				uint8_t prefix_len, const char *ip,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy)
{
	struct l_rtnl_address a6;

	if (!rtnl_address_init(&a6, ip, prefix_len))
		return 0;

	return l_rtnl_ifaddr_add(rtnl, ifindex, &a6, cb, user_data, destroy);
}

LIB_EXPORT uint32_t l_rtnl_ifaddr6_delete(struct l_netlink *rtnl, int ifindex,
					uint8_t prefix_len, const char *ip,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct l_rtnl_address a6;

	if (!rtnl_address_init(&a6, ip, prefix_len))
		return 0;

	return l_rtnl_ifaddr_delete(rtnl, ifindex, &a6, cb, user_data, destroy);
}

LIB_EXPORT void l_rtnl_route6_extract(const struct rtmsg *rtmsg, uint32_t len,
				uint32_t *table, uint32_t *ifindex,
				char **dst, char **gateway, char **src)
{
	l_rtnl_route_extract(rtmsg, len, AF_INET6, table, ifindex,
				NULL, NULL, dst, gateway, src);
}

LIB_EXPORT uint32_t l_rtnl_route6_dump(struct l_netlink *rtnl,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy)
{
	struct rtmsg rtmsg;

	memset(&rtmsg, 0, sizeof(struct rtmsg));
	rtmsg.rtm_family = AF_INET6;

	return l_netlink_send(rtnl, RTM_GETROUTE, NLM_F_DUMP, &rtmsg,
					sizeof(struct rtmsg), cb, user_data,
					destroy);
}

LIB_EXPORT uint32_t l_rtnl_route6_add_gateway(struct l_netlink *rtnl,
					int ifindex,
					const char *gateway,
					uint32_t priority_offset,
					uint8_t proto,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct l_rtnl_route *rt = l_rtnl_route_new_gateway(gateway);
	uint32_t r;

	if (!rt)
		return 0;

	l_rtnl_route_set_protocol(rt, proto);
	l_rtnl_route_set_priority(rt, priority_offset);

	r = l_rtnl_route_add(rtnl, ifindex, rt, cb, user_data, destroy);
	l_rtnl_route_free(rt);
	return r;
}

LIB_EXPORT uint32_t l_rtnl_route6_delete_gateway(struct l_netlink *rtnl,
					int ifindex,
					const char *gateway,
					uint32_t priority_offset,
					uint8_t proto,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct l_rtnl_route *rt = l_rtnl_route_new_gateway(gateway);
	uint32_t r;

	if (!rt)
		return 0;

	l_rtnl_route_set_protocol(rt, proto);
	l_rtnl_route_set_priority(rt, priority_offset);

	r = l_rtnl_route_delete(rtnl, ifindex, rt, cb, user_data, destroy);
	l_rtnl_route_free(rt);
	return r;
}

static uint32_t _rtnl_ifaddr_change(struct l_netlink *rtnl, uint16_t nlmsg_type,
					int ifindex,
					const struct l_rtnl_address *addr,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct ifaddrmsg *ifamsg;
	void *buf;
	size_t bufsize;
	uint32_t id;
	int flags = 0;
	uint64_t now = l_time_now();

	if  (nlmsg_type == RTM_NEWADDR)
		flags = NLM_F_CREATE | NLM_F_REPLACE;

	bufsize = NLMSG_ALIGN(sizeof(struct ifaddrmsg)) +
					RTA_SPACE(sizeof(struct in6_addr)) +
					RTA_SPACE(sizeof(struct in_addr)) +
					RTA_SPACE(sizeof(uint32_t)) +
					RTA_SPACE(IFNAMSIZ) +
					RTA_SPACE(sizeof(struct ifa_cacheinfo));

	ifamsg = l_malloc(bufsize);
	memset(ifamsg, 0, bufsize);

	ifamsg->ifa_index = ifindex;
	ifamsg->ifa_family = addr->family;
	ifamsg->ifa_scope = addr->scope;
	ifamsg->ifa_prefixlen = addr->prefix_len;
	/* Kernel ignores legacy flags in IFA_FLAGS, so set them here */
	ifamsg->ifa_flags = addr->flags & 0xff;

	buf = (void *) ifamsg + NLMSG_ALIGN(sizeof(struct ifaddrmsg));

	if (addr->family == AF_INET) {
		buf += rta_add_data(buf, IFA_LOCAL, &addr->in_addr,
						sizeof(struct in_addr));
		buf += rta_add_data(buf, IFA_BROADCAST, &addr->broadcast,
						sizeof(struct in_addr));
	} else
		buf += rta_add_data(buf, IFA_LOCAL, &addr->in6_addr,
						sizeof(struct in6_addr));

	/* Address & Prefix length are enough to perform deletions */
	if (nlmsg_type == RTM_DELADDR)
		goto done;

	if (addr->flags & 0xffffff00)
		buf += rta_add_u32(buf, IFA_FLAGS, addr->flags & 0xffffff00);

	if (addr->label[0])
		buf += rta_add_data(buf, IFA_LABEL,
					addr->label, strlen(addr->label) + 1);

	if (addr->preferred_expiry_time > now ||
			addr->valid_expiry_time > now) {
		struct ifa_cacheinfo cinfo;

		memset(&cinfo, 0, sizeof(cinfo));
		cinfo.ifa_prefered = addr->preferred_expiry_time > now ?
			l_time_to_secs(addr->preferred_expiry_time - now) : 0;
		cinfo.ifa_valid =  addr->valid_expiry_time > now ?
			l_time_to_secs(addr->valid_expiry_time - now) : 0;

		buf += rta_add_data(buf, IFA_CACHEINFO, &cinfo, sizeof(cinfo));
	}

done:
	id = l_netlink_send(rtnl, nlmsg_type, flags,
				ifamsg, buf - (void *) ifamsg,
				cb, user_data, destroy);
	l_free(ifamsg);

	return id;
}

LIB_EXPORT struct l_rtnl_address *l_rtnl_ifaddr_extract(
						const struct ifaddrmsg *ifa,
						int bytes)
{
	struct rtattr *attr;
	struct ifa_cacheinfo *cinfo;
	struct l_rtnl_address *addr;

	if (unlikely(!ifa))
		return NULL;

	if (!L_IN_SET(ifa->ifa_family, AF_INET, AF_INET6))
		return NULL;

	addr = l_new(struct l_rtnl_address, 1);
	addr->prefix_len = ifa->ifa_prefixlen;
	addr->family = ifa->ifa_family;
	addr->flags = ifa->ifa_flags;
	addr->scope = ifa->ifa_scope;

	for (attr = IFA_RTA(ifa); RTA_OK(attr, bytes);
						attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case IFA_LOCAL:
			if (ifa->ifa_family == AF_INET)
				addr->in_addr =
					*((struct in_addr *) RTA_DATA(attr));

			break;
		case IFA_ADDRESS:
			if (ifa->ifa_family == AF_INET6)
				addr->in6_addr =
					*((struct in6_addr *) RTA_DATA(attr));

			break;
		case IFA_BROADCAST:
			addr->broadcast = *((struct in_addr *) RTA_DATA(attr));
			break;
		case IFA_LABEL:
			l_strlcpy(addr->label, RTA_DATA(attr),
					sizeof(addr->label));
			break;
		case IFA_CACHEINFO:
			cinfo = RTA_DATA(attr);
			l_rtnl_address_set_lifetimes(addr, cinfo->ifa_prefered,
							cinfo->ifa_valid);
			break;
		}
	}

	return addr;
}

LIB_EXPORT uint32_t l_rtnl_ifaddr_add(struct l_netlink *rtnl, int ifindex,
					const struct l_rtnl_address *addr,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	return _rtnl_ifaddr_change(rtnl, RTM_NEWADDR, ifindex, addr,
						cb, user_data, destroy);
}

LIB_EXPORT uint32_t l_rtnl_ifaddr_delete(struct l_netlink *rtnl, int ifindex,
					const struct l_rtnl_address *addr,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	return _rtnl_ifaddr_change(rtnl, RTM_DELADDR, ifindex, addr,
						cb, user_data, destroy);
}

static uint32_t _rtnl_route_change(struct l_netlink *rtnl,
					uint16_t nlmsg_type, int ifindex,
					const struct l_rtnl_route *rt,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	L_AUTO_FREE_VAR(struct rtmsg *, rtmmsg) = NULL;
	size_t bufsize;
	void *rta_buf;
	uint16_t flags;
	uint64_t now = l_time_now();

	bufsize = NLMSG_ALIGN(sizeof(struct rtmsg)) +
			RTA_SPACE(sizeof(uint32_t)) +        /* RTA_OIF */
			RTA_SPACE(sizeof(uint32_t)) +        /* RTA_PRIORITY */
			RTA_SPACE(sizeof(struct in6_addr)) + /* RTA_GATEWAY */
			RTA_SPACE(sizeof(struct in6_addr)) + /* RTA_DST */
			RTA_SPACE(sizeof(struct in6_addr)) + /* RTA_PREFSRC */
			256 +                                /* RTA_METRICS */
			RTA_SPACE(sizeof(uint8_t)) +         /* RTA_PREF */
			RTA_SPACE(sizeof(uint32_t));         /* RTA_EXPIRES */

	rtmmsg = l_malloc(bufsize);
	memset(rtmmsg, 0, bufsize);

	rtmmsg->rtm_family = rt->family;
	rtmmsg->rtm_table = RT_TABLE_MAIN;
	rtmmsg->rtm_protocol = rt->protocol;
	rtmmsg->rtm_type = RTN_UNICAST;
	rtmmsg->rtm_scope = rt->scope;

	flags = NLM_F_CREATE | NLM_F_REPLACE;

	rta_buf = (void *) rtmmsg + NLMSG_ALIGN(sizeof(struct rtmsg));
	rta_buf += rta_add_u32(rta_buf, RTA_OIF, ifindex);

	if (rt->priority)
		rta_buf += rta_add_u32(rta_buf, RTA_PRIORITY,
						rt->priority + ifindex);

	if (!address_is_null(rt->family, &rt->gw.in_addr, &rt->gw.in6_addr))
		rta_buf += rta_add_address(rta_buf, RTA_GATEWAY, rt->family,
					&rt->gw.in6_addr, &rt->gw.in_addr);

	if (rt->dst_prefix_len) {
		rtmmsg->rtm_dst_len = rt->dst_prefix_len;
		rta_buf += rta_add_address(rta_buf, RTA_DST, rt->family,
					&rt->dst.in6_addr, &rt->dst.in_addr);
	}

	if (!address_is_null(rt->family, &rt->prefsrc.in_addr,
						&rt->prefsrc.in6_addr))
		rta_buf += rta_add_address(rta_buf, RTA_PREFSRC, rt->family,
						&rt->prefsrc.in6_addr,
						&rt->prefsrc.in_addr);

	if (rt->mtu) {
		uint8_t buf[256];
		size_t written = rta_add_u32(buf, RTAX_MTU, rt->mtu);

		rta_buf += rta_add_data(rta_buf, RTA_METRICS, buf, written);
	}

	if (rt->preference)
		rta_buf += rta_add_u8(rta_buf, RTA_PREF, rt->preference);

	if (rt->expiry_time > now)
		rta_buf += rta_add_u32(rta_buf, RTA_EXPIRES,
					l_time_to_secs(rt->expiry_time - now));

	return l_netlink_send(rtnl, nlmsg_type, flags, rtmmsg,
				rta_buf - (void *) rtmmsg, cb, user_data,
								destroy);
}

LIB_EXPORT uint32_t l_rtnl_route_add(struct l_netlink *rtnl, int ifindex,
					const struct l_rtnl_route *rt,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	return _rtnl_route_change(rtnl, RTM_NEWROUTE, ifindex, rt,
						cb, user_data, destroy);
}

LIB_EXPORT uint32_t l_rtnl_route_delete(struct l_netlink *rtnl, int ifindex,
					const struct l_rtnl_route *rt,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	return _rtnl_route_change(rtnl, RTM_DELROUTE, ifindex, rt,
						cb, user_data, destroy);
}

struct rtnl_neighbor_get_data {
	l_rtnl_neighbor_get_cb_t cb;
	void *user_data;
	l_netlink_destroy_func_t destroy;
};

static void rtnl_neighbor_get_cb(int error, uint16_t type, const void *data,
					uint32_t len, void *user_data)
{
	struct rtnl_neighbor_get_data *cb_data = user_data;
	const struct ndmsg *ndmsg = data;
	struct rtattr *attr;
	const uint8_t *hwaddr = NULL;
	size_t hwaddr_len = 0;

	if (error != 0)
		goto done;

	if (type != RTM_NEWNEIGH || len < NLMSG_ALIGN(sizeof(*ndmsg))) {
		error = -EIO;
		goto done;
	}

	if (!(ndmsg->ndm_state & (NUD_PERMANENT | NUD_NOARP | NUD_REACHABLE))) {
		error = -ENOENT;
		goto done;
	}

	attr = (void *) ndmsg + NLMSG_ALIGN(sizeof(*ndmsg));
	len -= NLMSG_ALIGN(sizeof(*ndmsg));

	for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len))
		switch (attr->rta_type) {
		case NDA_LLADDR:
			hwaddr = RTA_DATA(attr);
			hwaddr_len = RTA_PAYLOAD(attr);
			break;
		}

	if (!hwaddr)
		error = -EIO;

done:
	if (cb_data->cb) {
		cb_data->cb(error, hwaddr, hwaddr_len, cb_data->user_data);
		cb_data->cb = NULL;
	}
}

static void rtnl_neighbor_get_destroy_cb(void *user_data)
{
	struct rtnl_neighbor_get_data *cb_data = user_data;

	if (cb_data->destroy)
		cb_data->destroy(cb_data->user_data);

	l_free(cb_data);
}

LIB_EXPORT uint32_t l_rtnl_neighbor_get_hwaddr(struct l_netlink *rtnl,
					int ifindex, int family,
					const void *ip,
					l_rtnl_neighbor_get_cb_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	size_t bufsize = NLMSG_ALIGN(sizeof(struct ndmsg)) +
			RTA_SPACE(16); /* NDA_DST */
	uint8_t buf[bufsize];
	struct ndmsg *ndmsg = (struct ndmsg *) buf;
	void *rta_buf = (void *) ndmsg + NLMSG_ALIGN(sizeof(struct ndmsg));
	__auto_type cb_data = struct_alloc(rtnl_neighbor_get_data,
						cb, user_data, destroy);
	uint32_t ret;

	memset(buf, 0, bufsize);
	ndmsg->ndm_family = family;
	ndmsg->ndm_ifindex = ifindex;
	ndmsg->ndm_flags = 0;

	rta_buf += rta_add_address(rta_buf, NDA_DST, family, ip, ip);

	ret = l_netlink_send(rtnl, RTM_GETNEIGH, 0, ndmsg,
				rta_buf - (void *) ndmsg,
				rtnl_neighbor_get_cb, cb_data,
				rtnl_neighbor_get_destroy_cb);
	if (ret)
		return ret;

	l_free(cb_data);
	return 0;
}

LIB_EXPORT uint32_t l_rtnl_neighbor_set_hwaddr(struct l_netlink *rtnl,
					int ifindex, int family,
					const void *ip,
					const uint8_t *hwaddr,
					size_t hwaddr_len,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	size_t bufsize = NLMSG_ALIGN(sizeof(struct ndmsg)) +
			RTA_SPACE(16) +        /* NDA_DST */
			RTA_SPACE(hwaddr_len); /* NDA_LLADDR */
	uint8_t buf[bufsize];
	struct ndmsg *ndmsg = (struct ndmsg *) buf;
	void *rta_buf = (void *) ndmsg + NLMSG_ALIGN(sizeof(struct ndmsg));

	memset(buf, 0, bufsize);
	ndmsg->ndm_family = family;
	ndmsg->ndm_ifindex = ifindex;
	ndmsg->ndm_flags = 0;
	ndmsg->ndm_state = NUD_REACHABLE;

	rta_buf += rta_add_address(rta_buf, NDA_DST, family, ip, ip);
	rta_buf += rta_add_data(rta_buf, NDA_LLADDR, hwaddr, hwaddr_len);

	return l_netlink_send(rtnl, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_REPLACE,
				ndmsg, rta_buf - (void *) ndmsg,
				cb, user_data, destroy);
}

__attribute__((destructor(32000))) static void free_rtnl()
{
	l_netlink_destroy(rtnl);
}

LIB_EXPORT struct l_netlink *l_rtnl_get()
{
	if (!rtnl)
		rtnl = l_netlink_new(NETLINK_ROUTE);

	return rtnl;
}
