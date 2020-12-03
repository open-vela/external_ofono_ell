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

#ifndef __ELL_ACD_H
#define __ELL_ACD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

struct l_acd;

enum l_acd_event {
	L_ACD_EVENT_AVAILABLE,
	L_ACD_EVENT_CONFLICT,
	L_ACD_EVENT_LOST,
};

enum l_acd_defend_policy {
	L_ACD_DEFEND_POLICY_NONE,	/* Never defend */
	L_ACD_DEFEND_POLICY_DEFEND,	/* Default, defend once */
	L_ACD_DEFEND_POLICY_INFINITE,	/* Defend indefinitely */
};

typedef void (*l_acd_event_func_t)(enum l_acd_event event, void *user_data);
typedef void (*l_acd_destroy_func_t)(void *user_data);

typedef void (*l_acd_debug_cb_t)(const char *str, void *user_data);

struct l_acd *l_acd_new(int ifindex);
bool l_acd_start(struct l_acd *acd, const char *ip);
bool l_acd_set_event_handler(struct l_acd *acd, l_acd_event_func_t cb,
				void *user_data, l_acd_destroy_func_t destroy);
bool l_acd_stop(struct l_acd *acd);
void l_acd_destroy(struct l_acd *acd);
bool l_acd_set_debug(struct l_acd *acd, l_acd_debug_cb_t function,
			void *user_data, l_acd_destroy_func_t destory);
bool l_acd_set_skip_probes(struct l_acd *acd, bool skip);
bool l_acd_set_defend_policy(struct l_acd *acd,
				enum l_acd_defend_policy policy);
#ifdef __cplusplus
}
#endif

#endif /* __ELL_CERT_H */
