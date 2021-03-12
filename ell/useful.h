/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2021  Intel Corporation. All rights reserved.
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

#define align_len(len, boundary) (((len)+(boundary)-1) & ~((boundary)-1))

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

static inline size_t minsize(size_t a, size_t b)
{
	if (a <= b)
		return a;

	return b;
}

#define __AUTODESTRUCT(var, func)			\
	void cleanup_ ## var(void *ptr)			\
	{ func(*(void **) ptr); }			\
	__attribute((cleanup(cleanup_ ## var)))

#define _AUTODESTRUCT(var, func)			\
	__AUTODESTRUCT(var, func)

#define _auto_(func)					\
	_AUTODESTRUCT(__COUNTER__, func)
