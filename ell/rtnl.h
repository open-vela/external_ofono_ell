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

#ifndef __ELL_RTNL_H
#define __ELL_RTNL_H

#include <stdint.h>
#include <linux/rtnetlink.h>
#include <ell/cleanup.h>

#ifdef __cplusplus
extern "C" {
#endif

struct l_rtnl_address;
struct l_rtnl_route;

typedef void (*l_rtnl_neighbor_get_cb_t) (int error, const uint8_t *hwaddr,
						size_t hwaddr_len,
						void *user_data);

struct l_rtnl_address *l_rtnl_address_new(const char *ip, uint8_t prefix_len);
struct l_rtnl_address *l_rtnl_address_clone(const struct l_rtnl_address *orig);
void l_rtnl_address_free(struct l_rtnl_address *addr);
DEFINE_CLEANUP_FUNC(l_rtnl_address_free);
bool l_rtnl_address_get_address(const struct l_rtnl_address *addr,
				char *out_buf);
const void *l_rtnl_address_get_in_addr(const struct l_rtnl_address *addr);
uint8_t l_rtnl_address_get_family(const struct l_rtnl_address *addr);
uint8_t l_rtnl_address_get_prefix_length(const struct l_rtnl_address *addr);
bool l_rtnl_address_get_broadcast(const struct l_rtnl_address *addr,
					char *out_buf);
bool l_rtnl_address_set_broadcast(struct l_rtnl_address *addr,
						const char *broadcast);
const char *l_rtnl_address_get_label(const struct l_rtnl_address *addr);
bool l_rtnl_address_set_label(struct l_rtnl_address *addr, const char *label);
bool l_rtnl_address_set_noprefixroute(struct l_rtnl_address *addr,
							bool noprefixroute);
uint32_t l_rtnl_address_get_valid_lifetime(const struct l_rtnl_address *addr);
uint32_t l_rtnl_address_get_preferred_lifetime(
					const struct l_rtnl_address *addr);
bool l_rtnl_address_set_lifetimes(struct l_rtnl_address *addr,
						uint32_t preferred_lifetime,
						uint32_t valid_lifetime);
bool l_rtnl_address_get_expiry(const struct l_rtnl_address *addr,
				uint64_t *preferred_expiry_time,
				uint64_t *valid_expiry_time);
bool l_rtnl_address_set_expiry(struct l_rtnl_address *addr,
				uint64_t preferred_expiry_time,
				uint64_t valid_expiry_time);
bool l_rtnl_address_set_scope(struct l_rtnl_address *addr, uint8_t scope);

struct l_rtnl_route *l_rtnl_route_new_gateway(const char *gw);
struct l_rtnl_route *l_rtnl_route_new_prefix(const char *ip,
							uint8_t prefix_len);
struct l_rtnl_route *l_rtnl_route_new_static(const char *gw, const char *ip,
							uint8_t prefix_len);
void l_rtnl_route_free(struct l_rtnl_route *rt);
DEFINE_CLEANUP_FUNC(l_rtnl_route_free);
uint8_t l_rtnl_route_get_family(const struct l_rtnl_route *rt);
bool l_rtnl_route_get_gateway(const struct l_rtnl_route *rt, char *out_buf);
const void *l_rtnl_route_get_gateway_in_addr(const struct l_rtnl_route *rt);
bool l_rtnl_route_get_dst(const struct l_rtnl_route *rt, char *out_buf,
				uint8_t *out_prefix_len);
const void *l_rtnl_route_get_dst_in_addr(const struct l_rtnl_route *rt,
						uint8_t *out_prefix_len);
uint32_t l_rtnl_route_get_lifetime(const struct l_rtnl_route *rt);
bool l_rtnl_route_set_lifetime(struct l_rtnl_route *rt, uint32_t lt);
uint64_t l_rtnl_route_get_expiry(const struct l_rtnl_route *rt);
bool l_rtnl_route_set_expiry(struct l_rtnl_route *rt, uint64_t expiry_time);
uint32_t l_rtnl_route_get_mtu(const struct l_rtnl_route *rt);
bool l_rtnl_route_set_mtu(struct l_rtnl_route *rt, uint32_t mtu);
uint8_t l_rtnl_route_get_preference(const struct l_rtnl_route *rt);
bool l_rtnl_route_set_preference(struct l_rtnl_route *rt, uint8_t preference);
bool l_rtnl_route_get_prefsrc(const struct l_rtnl_route *rt, char *out_address);
bool l_rtnl_route_set_prefsrc(struct l_rtnl_route *rt, const char *address);
uint32_t l_rtnl_route_get_priority(const struct l_rtnl_route *rt);
bool l_rtnl_route_set_priority(struct l_rtnl_route *rt, uint32_t priority);
uint8_t l_rtnl_route_get_protocol(const struct l_rtnl_route *rt);
bool l_rtnl_route_set_protocol(struct l_rtnl_route *rt, uint8_t protocol);
uint8_t l_rtnl_route_get_scope(const struct l_rtnl_route *rt);
bool l_rtnl_route_set_scope(struct l_rtnl_route *rt, uint8_t scope);

uint32_t l_rtnl_set_linkmode_and_operstate(struct l_netlink *rtnl, int ifindex,
					uint8_t linkmode, uint8_t operstate,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy);

uint32_t l_rtnl_set_mac(struct l_netlink *rtnl, int ifindex,
					const uint8_t addr[static 6],
					bool power_up,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy);

uint32_t l_rtnl_set_powered(struct l_netlink *rtnl, int ifindex, bool powered,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy);

void l_rtnl_ifaddr4_extract(const struct ifaddrmsg *ifa, int bytes,
				char **label, char **ip, char **broadcast);
uint32_t l_rtnl_ifaddr4_dump(struct l_netlink *rtnl, l_netlink_command_func_t cb,
				void *user_data,
				l_netlink_destroy_func_t destroy);
uint32_t l_rtnl_ifaddr4_add(struct l_netlink *rtnl, int ifindex,
				uint8_t prefix_len, const char *ip,
				const char *broadcast,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy);
uint32_t l_rtnl_ifaddr4_delete(struct l_netlink *rtnl, int ifindex,
				uint8_t prefix_len, const char *ip,
				const char *broadcast,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy);

void l_rtnl_route4_extract(const struct rtmsg *rtmsg, uint32_t len,
				uint32_t *table, uint32_t *ifindex,
				char **dst, char **gateway, char **src);
uint32_t l_rtnl_route4_dump(struct l_netlink *rtnl,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy);
uint32_t l_rtnl_route4_add_connected(struct l_netlink *rtnl, int ifindex,
					uint8_t dst_len, const char *dst,
					const char *src, uint8_t proto,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy);
uint32_t l_rtnl_route4_add_gateway(struct l_netlink *rtnl, int ifindex,
					const char *gateway, const char *src,
					uint32_t priority_offset,
					uint8_t proto,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy);

void l_rtnl_ifaddr6_extract(const struct ifaddrmsg *ifa, int len,
								char **ip);
uint32_t l_rtnl_ifaddr6_dump(struct l_netlink *rtnl,
				l_netlink_command_func_t cb,
				void *user_data,
				l_netlink_destroy_func_t destroy);
uint32_t l_rtnl_ifaddr6_add(struct l_netlink *rtnl, int ifindex,
				uint8_t prefix_len, const char *ip,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy);
uint32_t l_rtnl_ifaddr6_delete(struct l_netlink *rtnl, int ifindex,
					uint8_t prefix_len, const char *ip,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy);
void l_rtnl_route6_extract(const struct rtmsg *rtmsg, uint32_t len,
				uint32_t *table, uint32_t *ifindex,
				char **dst, char **gateway, char **src);
uint32_t l_rtnl_route6_dump(struct l_netlink *rtnl,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy);
uint32_t l_rtnl_route6_add_gateway(struct l_netlink *rtnl, int ifindex,
					const char *gateway,
					uint32_t priority_offset,
					uint8_t proto,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy);
uint32_t l_rtnl_route6_delete_gateway(struct l_netlink *rtnl, int ifindex,
					const char *gateway,
					uint32_t priority_offset,
					uint8_t proto,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy);

struct l_rtnl_address *l_rtnl_ifaddr_extract(const struct ifaddrmsg *ifa,
								int bytes);

uint32_t l_rtnl_ifaddr_add(struct l_netlink *rtnl, int ifindex,
					const struct l_rtnl_address *addr,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy);
uint32_t l_rtnl_ifaddr_delete(struct l_netlink *rtnl, int ifindex,
					const struct l_rtnl_address *addr,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy);

uint32_t l_rtnl_route_add(struct l_netlink *rtnl, int ifindex,
					const struct l_rtnl_route *rt,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy);
uint32_t l_rtnl_route_delete(struct l_netlink *rtnl, int ifindex,
					const struct l_rtnl_route *rt,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy);

uint32_t l_rtnl_neighbor_get_hwaddr(struct l_netlink *rtnl, int ifindex,
					int family, const void *ip,
					l_rtnl_neighbor_get_cb_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy);
uint32_t l_rtnl_neighbor_set_hwaddr(struct l_netlink *rtnl, int ifindex,
					int family, const void *ip,
					const uint8_t *hwaddr,
					size_t hwaddr_len,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy);

struct l_netlink *l_rtnl_get();

#ifdef __cplusplus
}
#endif

#endif /* __ELL_RTNL_H */
