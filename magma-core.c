/*
 * Magma Cipher
 *
 * Copyright (c) 2011-2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * Standards: GOST 28147-89, GOST R 34.12-2015 
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "magma-core.h"
#include "magma-defs.h"

struct state {
	u32 k[8];
	u32 k87[256], k65[256], k43[256], k21[256];
};

static void table_init (struct state *o, const struct pi *b)
{
	int i, h, l;

	for (i = 0; i < 256; ++i) {
		h = i / 16;
		l = i % 16;

		o->k87[i] = rol32 ((b->pi[7][h] << 4 | b->pi[6][l]) << 24, 11);
		o->k65[i] = rol32 ((b->pi[5][h] << 4 | b->pi[4][l]) << 16, 11);
		o->k43[i] = rol32 ((b->pi[3][h] << 4 | b->pi[2][l]) << 8,  11);
		o->k21[i] = rol32 ((b->pi[1][h] << 4 | b->pi[0][l]),       11);
	}
}

static int set_key (struct state *o, const u8 *key, size_t len)
{
	size_t i;

	if (len != 32)
		return -EINVAL;

	for (i = 0; i < 8; ++i, key += 4)
		o->k[i] = read_be32 (key);

	table_init (o, &sb_magma);
	return 0;
}

static u32 f (struct state *o, u32 x)
{
	return o->k87[x >> 24 & 255] | o->k65[x >> 16 & 255] |
	       o->k43[x >>  8 & 255] | o->k21[x       & 255];
}

/* Instead of swapping halves, swap names each round */
#define direct_rounds(o, a, b) \
	b ^= f (o, a + o->k[0]); a ^= f (o, b + o->k[1]); \
	b ^= f (o, a + o->k[2]); a ^= f (o, b + o->k[3]); \
	b ^= f (o, a + o->k[4]); a ^= f (o, b + o->k[5]); \
	b ^= f (o, a + o->k[6]); a ^= f (o, b + o->k[7]);

#define reverse_rounds(o, a, b) \
	b ^= f (o, a + o->k[7]); a ^= f (o, b + o->k[6]); \
	b ^= f (o, a + o->k[5]); a ^= f (o, b + o->k[4]); \
	b ^= f (o, a + o->k[3]); a ^= f (o, b + o->k[2]); \
	b ^= f (o, a + o->k[1]); a ^= f (o, b + o->k[0]);

static void encrypt (void *state, const void *in, void *out)
{
	struct state *o = state;
	u32 a, b;

	a = read_be32 (in + 4);
	b = read_be32 (in);

	direct_rounds  (o, a, b);
	direct_rounds  (o, a, b);
	direct_rounds  (o, a, b);
	reverse_rounds (o, a, b);

	write_be32 (a, out);
	write_be32 (b, out + 4);
}

static void decrypt (void *state, const void *in, void *out)
{
	struct state *o = state;
	u32 a, b;

	a = read_be32 (in + 4);
	b = read_be32 (in);

	direct_rounds  (o, a, b);
	reverse_rounds (o, a, b);
	reverse_rounds (o, a, b);
	reverse_rounds (o, a, b);

	write_be32 (a, out);
	write_be32 (b, out + 4);
}

static void *alloc (void)
{
	struct state *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	return o;
}

static int get (const void *state, int type, ...)
{
	switch (type) {
	case CRYPTO_BLOCK_SIZE: return 8;
	}

	return -ENOSYS;
}

static int set (void *state, int type, ...)
{
	va_list ap;
	int status;

	va_start (ap, type);

	switch (type) {
	case CRYPTO_KEY: {
			const void *key;
			size_t len;

			key = va_arg (ap, const void *);
			len = va_arg (ap, size_t);
			status = set_key (state, key, len);
			break;
		}
	default:
		status = -ENOSYS;
	}

	va_end (ap);
	return status;
}

const struct crypto_core magma_core = {
	.alloc		= alloc,
	.free		= free,

	.get		= get,
	.set 		= set,

	.encrypt	= encrypt,
	.decrypt	= decrypt,
};
