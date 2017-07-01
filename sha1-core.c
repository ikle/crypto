/*
 * NIST FIPS-180-4: Secure Hash Standard (SHS)
 *
 * SHA1 Core
 *
 * Copyright (c) 2017 Alexei A. Smekalkine
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include <string.h>

#include "core.h"
#include "sha1-core.h"

#define SHA1_WORD_SIZE	4
#define SHA1_WORD_COUNT	16
#define SHA1_ORDER	5

#define SHA1_BLOCK_SIZE	(SHA1_WORD_SIZE * SHA1_WORD_COUNT)
#define SHA1_HASH_SIZE	(SHA1_WORD_SIZE * SHA1_ORDER)

static const u32 H0[SHA1_ORDER] = {
	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
};

static u32 Ch (u32 x, u32 y, u32 z)
{
	return (x & y) ^ (~x & z);
}

static u32 Parity (u32 x, u32 y, u32 z)	/* = MD5.H */
{
	return x ^ y ^ z;
}

static u32 Maj (u32 x, u32 y, u32 z)
{
	return (x & y) ^ (x & z) ^ (y & z);
}

static const u32 K[4] = { 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 };

static size_t idx (size_t i)
{
	return i % SHA1_WORD_COUNT;
}

static void mix_word (u32 *W, int i)
{
	u32 x = W[idx (i)] ^ W[idx (i + 2)] ^ W[idx (i + 8)] ^ W[idx (i + 13)];

	W[idx (i)] = rol32 (x, 1);
}

#define STEP_ONE(f, K, a, b, c, d, e, i)  do {				\
		if ((i) >= SHA1_WORD_COUNT)				\
			mix_word (W, i);				\
									\
		e += rol32 (a, 5) + f (b, c, d) + K + W[idx (i)];	\
		b = rol32 (b, 30);					\
	} while (0)

#define STEP_GROUP(f, K, a, b, c, d, e, i)  do {			\
		STEP_ONE(f, K, a, b, c, d, e, (i) + 0);			\
		STEP_ONE(f, K, e, a, b, c, d, (i) + 1);			\
		STEP_ONE(f, K, d, e, a, b, c, (i) + 2);			\
		STEP_ONE(f, K, c, d, e, a, b, (i) + 3);			\
		STEP_ONE(f, K, b, c, d, e, a, (i) + 4);			\
	} while (0)							\

#define ROUND(f, K, a, b, c, d, e, i)  do {				\
		STEP_GROUP(f, K, a, b, c, d, e, (i) +  0);		\
		STEP_GROUP(f, K, a, b, c, d, e, (i) +  5);		\
		STEP_GROUP(f, K, a, b, c, d, e, (i) + 10);		\
		STEP_GROUP(f, K, a, b, c, d, e, (i) + 15);		\
	} while (0)							\

struct sha1_state {
	u32 hash[SHA1_ORDER];
	u64 count;
};

static void sha1_core_init (void *state)
{
	struct sha1_state *o = state;

	memcpy (o->hash, H0, sizeof (o->hash));
	barrier_data (o->hash);
	o->count = 0;
}

static void *sha1_core_alloc (void)
{
	struct sha1_state *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	sha1_core_init (o);
	return o;
}

static void load (const u32 *in, u32 *out)
{
	size_t i;

	for (i = 0; i < SHA1_WORD_COUNT; ++i)
		out[i] = read_be32 (in + i);
}

static void transform (void *state, const void *block, u64 count)
{
	struct sha1_state *o = state;
	u32 W[SHA1_WORD_COUNT];
	u32 a, b, c, d, e;

	load (block, W);

	a = o->hash[0];
	b = o->hash[1];
	c = o->hash[2];
	d = o->hash[3];
	e = o->hash[4];

	ROUND (Ch,     K[0], a, b, c, d, e,  0);
	ROUND (Parity, K[1], a, b, c, d, e, 20);
	ROUND (Maj,    K[2], a, b, c, d, e, 40);
	ROUND (Parity, K[3], a, b, c, d, e, 60);

	o->hash[0] += a;
	o->hash[1] += b;
	o->hash[2] += c;
	o->hash[3] += d;
	o->hash[4] += e;

	o->count += count;
}

static void sha1_core_transform (void *state, const void *block)
{
	struct sha1_state *o = state;

	transform (state, block, SHA1_BLOCK_SIZE);
}

static void sha1_core_result (void *state, void *out)
{
	struct sha1_state *o = state;
	u32 *result = out;
	size_t i;

	for (i = 0; i < SHA1_ORDER; ++i)
		write_be32 (o->hash[i], result + i);
}

static void sha1_core_final (void *state, const void *in, size_t len,
			     void *out)
{
	struct sha1_state *o = state;
	u8 block[SHA1_BLOCK_SIZE];
	u8 *const head = block;
	u8 *const one = head + len;
	u8 *const end = head + sizeof (block);
	u8 *const num = end - 8;

	memcpy (block, in, len);
	*one = 0x80;

	if (num > one) {
		memset (one + 1, 0, num - (one + 1));
	}
	else {
		memset (one + 1, 0, end - (one + 1));
		transform (state, block, 0);

		memset (head, 0, num - head);
	}

	write_be64 ((o->count + len) * 8, num);
	transform (state, block, 0);
	sha1_core_result (state, out);
	sha1_core_init (state);
}

const struct hash_core sha1_core = {
	.block_size	= SHA1_BLOCK_SIZE,
	.hash_size	= SHA1_HASH_SIZE,

	.alloc		= sha1_core_alloc,
	.free		= free,
	.transform	= sha1_core_transform,
	.final		= sha1_core_final,
};
