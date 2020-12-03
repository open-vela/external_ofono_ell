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

#include <sys/socket.h>
#include <arpa/inet.h>

#include "private.h"
#include "acd.h"
#include "util.h"

struct l_acd {
	int ifindex;

	uint32_t ip;

	l_acd_event_func_t event_func;
	l_acd_destroy_func_t destroy;
	void *user_data;

	l_acd_debug_cb_t debug_handler;
	l_acd_destroy_func_t debug_destroy;
	void *debug_data;
};

LIB_EXPORT struct l_acd *l_acd_new(int ifindex)
{
	struct l_acd *acd = l_new(struct l_acd, 1);

	acd->ifindex = ifindex;

	return acd;
}

LIB_EXPORT bool l_acd_start(struct l_acd *acd, const char *ip)
{
	struct in_addr ia;

	if (unlikely(!acd || !ip))
		return false;

	if (inet_pton(AF_INET, ip, &ia) != 1)
		return false;

	acd->ip = ntohl(ia.s_addr);

	return true;
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

	return true;
}

LIB_EXPORT void l_acd_destroy(struct l_acd *acd)
{
	if (unlikely(!acd))
		return;

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
