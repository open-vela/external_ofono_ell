/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2015  Intel Corporation. All rights reserved.
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
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include <ell/ell.h>

#include "ell/useful.h"

static unsigned int nlpo2(unsigned int x)
{
	x--;
	x |= (x >> 1);
	x |= (x >> 2);
	x |= (x >> 4);
	x |= (x >> 8);
	x |= (x >> 16);
	return x + 1;
}

static unsigned int fls(unsigned int x)
{
	return x ? sizeof(x) * 8 - __builtin_clz(x) : 0;
}

static unsigned int align_power2(unsigned int u)
{
	return 1 << fls(u - 1);
}

static void test_power2(const void *data)
{
	size_t i;

	for (i = 1; i < 1000000; i++) {
		size_t size1, size2, size3 = 1;

		size1 = nlpo2(i);
		size2 = align_power2(i);

		/* Find the next power of two */
		while (size3 < i && size3 < SIZE_MAX)
			size3 <<= 1;

		assert(size1 == size2);
		assert(size2 == size3);
		assert(size3 == size1);
	}
}

static void test_alloc(const void *data)
{
	int i;

	for (i = 2; i < 10000; i++) {
		struct l_ringbuf *rb;

		rb = l_ringbuf_new(i);
		assert(rb != NULL);

		assert(l_ringbuf_capacity(rb) == l_ringbuf_avail(rb));

		l_ringbuf_free(rb);
	}
}

static void test_printf(const void *data)
{
	static size_t rb_size = 500;
	static size_t rb_capa = 512;
	struct l_ringbuf *rb;
	int i;

	rb = l_ringbuf_new(rb_size);
	assert(rb != NULL);
	assert(l_ringbuf_capacity(rb) == rb_capa);

	for (i = 0; i < 10000; i++) {
		size_t len, count = i % rb_capa;
		char *str, *ptr;

		if (!count)
			continue;

		len = asprintf(&str, "%*c", (int) count, 'x');
		assert(len == count);

		len = l_ringbuf_printf(rb, "%s", str);
		assert(len == count);
		assert(l_ringbuf_len(rb) == count);
		assert(l_ringbuf_avail(rb) == rb_capa - len);

		ptr = l_ringbuf_peek(rb, 0, &len);
		assert(ptr != NULL);
		assert(len == count);
		assert(strncmp(str, ptr, len) == 0);

		len = l_ringbuf_drain(rb, count);
		assert(len == count);
		assert(l_ringbuf_len(rb) == 0);
		assert(l_ringbuf_avail(rb) == rb_capa);

		free(str);
	}

	l_ringbuf_free(rb);
}

static void test_append(const void *unused)
{
	static const uint8_t data[6] = { 1, 2, 3, 4, 5, 6 };
	static const size_t rb_size = 12;
	static const size_t rb_capa = 16;
	size_t len_no_wrap;
	ssize_t appended;
	ssize_t space_left;
	void *rb_data;
	struct l_ringbuf *rb;

	rb = l_ringbuf_new(rb_size);
	assert(rb != NULL);
	assert(l_ringbuf_capacity(rb) == rb_capa);

	appended = l_ringbuf_append(rb, data, sizeof(data));
	assert(appended == sizeof(data));

	appended = l_ringbuf_append(rb, data, sizeof(data));
	assert(appended == sizeof(data));

	space_left = minsize(l_ringbuf_avail(rb), sizeof(data));
	appended = l_ringbuf_append(rb, data, sizeof(data));
	assert(appended == space_left);

	rb_data = l_ringbuf_peek(rb, 0, &len_no_wrap);
	assert(memcmp(rb_data, data, sizeof(data)) == 0);
	l_ringbuf_drain(rb, sizeof(data));

	rb_data = l_ringbuf_peek(rb, 0, &len_no_wrap);
	assert(memcmp(rb_data, data, sizeof(data)) == 0);
	l_ringbuf_drain(rb, sizeof(data));

	rb_data = l_ringbuf_peek(rb, 0, &len_no_wrap);
	assert(memcmp(rb_data, data, len_no_wrap) == 0);
	l_ringbuf_drain(rb, len_no_wrap);

	l_ringbuf_free(rb);
}

static void test_append2(const void *unused)
{
	static const uint8_t expected_data1[14] =  {3, 4, 5, 6, 1, 2, 3, 4, 5,
							6, 1, 2, 3, 4 };
	static const uint8_t expected_data2[2] = { 5, 6 };
	static const uint8_t data[6] = { 1, 2, 3, 4, 5, 6 };
	static const size_t rb_size = 12;
	static const size_t rb_capa = 16;
	size_t len_no_wrap;
	ssize_t appended;
	ssize_t space_left;
	void *rb_data;
	struct l_ringbuf *rb;

	rb = l_ringbuf_new(rb_size);
	assert(rb != NULL);
	assert(l_ringbuf_capacity(rb) == rb_capa);

	appended = l_ringbuf_append(rb, data, sizeof(data));
	assert(appended == sizeof(data));

	appended = l_ringbuf_append(rb, data, sizeof(data));
	assert(appended == sizeof(data));

	space_left = minsize(l_ringbuf_avail(rb), sizeof(data));
	l_ringbuf_drain(rb, sizeof(data) - space_left);

	appended = l_ringbuf_append(rb, data, sizeof(data));
	assert(appended == sizeof(data));

	rb_data = l_ringbuf_peek(rb, 0, &len_no_wrap);
	assert(len_no_wrap == sizeof(expected_data1));
	assert(memcmp(expected_data1, rb_data, len_no_wrap) == 0);

	l_ringbuf_drain(rb, len_no_wrap);

	rb_data = l_ringbuf_peek(rb, 0, &len_no_wrap);
	assert(len_no_wrap == sizeof(expected_data2));
	assert(memcmp(expected_data2, rb_data, len_no_wrap) == 0);

	l_ringbuf_free(rb);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("/ringbuf/power2", test_power2, NULL);
	l_test_add("/ringbuf/alloc", test_alloc, NULL);
	l_test_add("/ringbuf/printf", test_printf, NULL);
	l_test_add("/ringbuf/append", test_append, NULL);
	l_test_add("/ringbuf/append2", test_append2, NULL);

	return l_test_run();
}
