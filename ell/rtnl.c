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
#include <sys/socket.h>
#include <arpa/inet.h>

#include "util.h"
#include "netlink.h"
#include "log.h"
#include "rtnl.h"
#include "private.h"

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
	uint32_t flags;
};

static int address_get(const char *ip, struct in_addr *out_v4,
				struct in6_addr *out_v6)
{
	if (inet_pton(AF_INET, ip, out_v4) == 1)
		return AF_INET;

	if (inet_pton(AF_INET6, ip, out_v6) == 1)
		return AF_INET6;

	return -EINVAL;
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

LIB_EXPORT void l_rtnl_address_free(struct l_rtnl_address *addr)
{
	l_free(addr);
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
	if (unlikely(!addr))
		return false;

	addr->preferred_lifetime = preferred_lifetime;
	addr->valid_lifetime = valid_lifetime;

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
	struct in_addr in_addr;
	struct rtattr *attr;

	for (attr = IFA_RTA(ifa); RTA_OK(attr, bytes);
						attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case IFA_LOCAL:
			if (!ip)
				break;

			in_addr = *((struct in_addr *) RTA_DATA(attr));
			*ip = l_strdup(inet_ntoa(in_addr));

			break;
		case IFA_BROADCAST:
			if (!broadcast)
				break;

			in_addr = *((struct in_addr *) RTA_DATA(attr));
			*broadcast = l_strdup(inet_ntoa(in_addr));

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

static uint32_t l_rtnl_route4_add(struct l_netlink *rtnl, int ifindex,
					uint8_t scope, uint8_t dst_len,
					const char *dst, const char *gateway,
					const char *src,
					uint32_t priority_offset, uint8_t proto,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	L_AUTO_FREE_VAR(struct rtmsg *, rtmmsg) = NULL;
	struct in_addr in_addr;
	size_t bufsize;
	void *rta_buf;
	uint16_t flags;

	if (!dst && !gateway)
		return 0;

	bufsize = NLMSG_ALIGN(sizeof(struct rtmsg)) +
			RTA_SPACE(sizeof(uint32_t)) +
			(priority_offset ? RTA_SPACE(sizeof(uint32_t)) : 0) +
			(gateway ? RTA_SPACE(sizeof(struct in_addr)) : 0) +
			(src ? RTA_SPACE(sizeof(struct in_addr)) : 0) +
			(dst ? RTA_SPACE(sizeof(struct in_addr)) : 0);

	rtmmsg = l_malloc(bufsize);
	memset(rtmmsg, 0, bufsize);

	rtmmsg->rtm_family = AF_INET;
	rtmmsg->rtm_table = RT_TABLE_MAIN;
	rtmmsg->rtm_protocol = proto;
	rtmmsg->rtm_type = RTN_UNICAST;
	rtmmsg->rtm_scope = scope;

	flags = NLM_F_CREATE | NLM_F_REPLACE;

	rta_buf = (void *) rtmmsg + NLMSG_ALIGN(sizeof(struct rtmsg));
	rta_buf += rta_add_u32(rta_buf, RTA_OIF, ifindex);

	if (priority_offset)
		rta_buf += rta_add_u32(rta_buf, RTA_PRIORITY,
						priority_offset + ifindex);

	if (dst) {
		if (inet_pton(AF_INET, dst, &in_addr) < 1)
			return 0;

		rtmmsg->rtm_dst_len = dst_len;
		rta_buf += rta_add_data(rta_buf, RTA_DST, &in_addr,
							sizeof(struct in_addr));
	}

	if (gateway) {
		if (inet_pton(AF_INET, gateway, &in_addr) < 1)
			return 0;

		rta_buf += rta_add_data(rta_buf, RTA_GATEWAY, &in_addr,
							sizeof(struct in_addr));
	}

	if (src) {
		if (inet_pton(AF_INET, src, &in_addr) < 1)
			return 0;

		rtmmsg->rtm_src_len = 32;
		rta_buf += rta_add_data(rta_buf, RTA_PREFSRC, &in_addr,
							sizeof(struct in_addr));
	}

	return l_netlink_send(rtnl, RTM_NEWROUTE, flags, rtmmsg,
				rta_buf - (void *) rtmmsg, cb, user_data,
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
	return l_rtnl_route4_add(rtnl, ifindex, RT_SCOPE_LINK, dst_len, dst, NULL,
				src, 0, proto, cb, user_data, destroy);
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
	return l_rtnl_route4_add(rtnl, ifindex, RT_SCOPE_UNIVERSE, 0, NULL,
				gateway, src, priority_offset, proto, cb,
				user_data, destroy);
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

static uint32_t l_rtnl_route6_change(struct l_netlink *rtnl,
					uint16_t nlmsg_type, int ifindex,
					const char *gateway,
					uint32_t priority_offset,
					uint8_t proto,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	L_AUTO_FREE_VAR(struct rtmsg *, rtmmsg) = NULL;
	struct in6_addr in6_addr;
	size_t bufsize;
	void *rta_buf;
	uint16_t flags;

	if (!gateway)
		return 0;

	bufsize = NLMSG_ALIGN(sizeof(struct rtmsg)) +
			RTA_SPACE(sizeof(uint32_t)) +
			(priority_offset ? RTA_SPACE(sizeof(uint32_t)) : 0) +
			RTA_SPACE(sizeof(struct in6_addr));

	rtmmsg = l_malloc(bufsize);
	memset(rtmmsg, 0, bufsize);

	rtmmsg->rtm_family = AF_INET6;
	rtmmsg->rtm_table = RT_TABLE_MAIN;
	rtmmsg->rtm_protocol = proto;
	rtmmsg->rtm_type = RTN_UNICAST;
	rtmmsg->rtm_scope = RT_SCOPE_UNIVERSE;

	flags = NLM_F_CREATE | NLM_F_REPLACE;

	rta_buf = (void *) rtmmsg + NLMSG_ALIGN(sizeof(struct rtmsg));
	rta_buf += rta_add_u32(rta_buf, RTA_OIF, ifindex);

	if (priority_offset)
		rta_buf += rta_add_u32(rta_buf, RTA_PRIORITY,
						priority_offset + ifindex);

	if (gateway) {
		if (inet_pton(AF_INET6, gateway, &in6_addr) < 1)
			return 0;

		rta_buf += rta_add_data(rta_buf, RTA_GATEWAY, &in6_addr,
						sizeof(struct in6_addr));
	}

	return l_netlink_send(rtnl, nlmsg_type, flags, rtmmsg,
				rta_buf - (void *) rtmmsg, cb, user_data,
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
	return l_rtnl_route6_change(rtnl, RTM_NEWROUTE, ifindex, gateway,
					priority_offset, proto, cb,
					user_data, destroy);
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
	return l_rtnl_route6_change(rtnl, RTM_DELROUTE, ifindex, gateway,
					priority_offset, proto, cb,
					user_data, destroy);
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

	if (addr->preferred_lifetime || addr->valid_lifetime) {
		struct ifa_cacheinfo cinfo;

		memset(&cinfo, 0, sizeof(cinfo));
		cinfo.ifa_prefered = addr->preferred_lifetime;
		cinfo.ifa_valid = addr->valid_lifetime;

		buf += rta_add_data(buf, IFA_CACHEINFO, &cinfo, sizeof(cinfo));
	}

done:
	id = l_netlink_send(rtnl, nlmsg_type, 0, ifamsg, buf - (void *) ifamsg,
				cb, user_data, destroy);
	l_free(ifamsg);

	return id;
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
