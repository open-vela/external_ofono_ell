/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef __ELL_STRING_H
#define __ELL_STRING_H

#include <stdbool.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

struct l_string;

struct l_string *l_string_new(size_t initial_length);
char *l_string_free(struct l_string *string, bool free_data);

struct l_string *l_string_append(struct l_string *dest, const char *src);
struct l_string *l_string_append_c(struct l_string *dest, const char c);
struct l_string *l_string_append_fixed(struct l_string *dest, const char *src,
					size_t max);

void l_string_append_vprintf(struct l_string *dest,
					const char *format, va_list args);
void l_string_append_printf(struct l_string *dest, const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_STRING_H */
