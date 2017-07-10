/*
 * Stribog Hash Algorithm
 *
 * Copyright (c) 2013-2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * Standard: GOST R 34.11-2012
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <crypto/endian.h>
#include <crypto/utils.h>

#include <hash/stribog.h>

#include "stribog-defs.h"

/* use pseudo words to optimize endian conversions */
#define STRIBOG_WORD_SIZE	8
#define STRIBOG_WORD_COUNT	8
#define STRIBOG_ORDER		8

#define STRIBOG_BLOCK_SIZE	(STRIBOG_WORD_SIZE * STRIBOG_WORD_COUNT)
#define STRIBOG_HASH_SIZE	(STRIBOG_WORD_SIZE * STRIBOG_ORDER)

static u8 pi (u8 a)
{
	return pi_table[a];
}

static u64 l (u64 b)
{
	u64 mask, c;
	int i;

	for (i = 0, mask = (1ULL << 63), c = 0; i < 64; mask >>= 1, ++i)
		if ((b & mask) != 0)
			c ^= A_table[i];

	return c;
}

static void xor512 (const u512 *a, const u512 *b, u512 *result)
{
	int i;

	for (i = 0; i < 8; ++i)
		result->q[i] = a->q[i] ^ b->q[i];
}

/*
 * stribog with the first variant faster on x86-64 in 1296/30 = 43.2,
 * after initialization optimization in 1296/24 = 54.0,
 * the second variant in 1296/1272 times, or just about 1.9%
 */
static void LPS (const u512 *a, u512 *result)
#if 1
{
	static u64 table[8][256];  /* 16K lookup table */
	static int deployed;

	int i, j;

	if (!deployed) {
		for (j = 0; j < 8; ++j)
			for (i = 0; i < 256; ++i)
				table[j][i] = l (((u64) pi (i)) << (j * 8));

		deployed = 1;
	}

	for (i = 0; i < 8; ++i) {
		result->q[i] = table[0][a->m[0][i]];

		for (j = 1; j < 8; ++j)
			result->q[i] ^= table[j][a->m[j][i]];
	}
}
#elif 1
{
	int i;
	const u8 *A = a->b;

	for (i = 0; i < 8; ++i, ++A)
		result->q[i] = l (
			((u64) pi (A[ 0])      ) |
			((u64) pi (A[ 8]) <<  8) |
			((u64) pi (A[16]) << 16) |
			((u64) pi (A[24]) << 24) |
			((u64) pi (A[32]) << 32) |
			((u64) pi (A[40]) << 40) |
			((u64) pi (A[48]) << 48) |
			((u64) pi (A[56]) << 56)
		);
}
#else
{
	int i, j;

	for (i = 0; i < 8; ++i)
		for (j = 0; j < 8; ++j)
			result->m[i][j] = pi (a->m[j][i]);

	for (i = 0; i < 8; ++i)
		result->q[i] = l (result->q[i]);
}
#endif

/*
 * LPSX(a, b) = LPS(a ^ b)
 *
 * NOTE: Inline prevention slightly reduces execution time, but greatly
 *       total code size -- it becomes twice less!
 */
static noinline void LPSX (const u512 *a, const u512 *b, u512 *result)
{
	u512 acc;

	xor512 (a, b, &acc);
	LPS (&acc, result);
}

static void E (u512 *K, const u512 *m, u512 *result)
{
	int i;

	LPSX (K, m, result);

	for (i = 0; i < 11; ++i) {
		LPSX (K, C_table + i, K);
		LPSX (K, result, result);
	}
	LPSX (K, C_table + 11, K);
	xor512 (K, result, result);
}

/* g(N, h, m) = E(LPS(N ^ h), m) ^ h ^ m */
static void g (const u512 *N, const u512 *h, const u512 *m, u512 *result)
{
	u512 A, B;

	LPSX (N, h, &A);
	E (&A, m, &B);
	xor512 (&B, h, &A);
	xor512 (&A, m, result);
}

/* OOPS: LE-variant, use u256.b for independence */
static void add512 (const u512 *a, const u512 *b, u512 *result)
{
	int i, carry;
	u64 *r = result->q;

	for (i = 0, carry = 0; i < 8; ++i, ++r) {
		u64 A = a->q[i], B = b->q[i];
		*r = A + B + carry;
		carry = (carry) ? A >= *r : A > *r;
	}
}

struct stribog_state {
	const struct crypto_core *core;
	u512 h, N, Sum;
};

static void stribog_core_init (void *state)
{
	struct stribog_state *o = state;

	/* IV for stribog-512, fill with 0x01 x 64 for stribog-256 */
	memset (&o->h, 0, sizeof (o->h));	barrier_data (&o->h);

	memset (&o->N, 0, sizeof (o->N));	barrier_data (&o->N);
	memset (&o->Sum, 0, sizeof (o->Sum));	barrier_data (&o->Sum);
}

static void *stribog_core_alloc (void)
{
	struct stribog_state *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	stribog_core_init (o);
	return o;
}

static int stribog_core_get (const void *state, int type, ...)
{
	switch (type) {
	case CRYPTO_BLOCK_SIZE:	return STRIBOG_BLOCK_SIZE;
	case CRYPTO_HASH_SIZE:	return STRIBOG_HASH_SIZE;
	}

	return -ENOSYS;
}

static int stribog_core_set (void *state, int type, ...)
{
	return -ENOSYS;
}

static void load (const u512 *in, u512 *out)
{
	size_t i;

	for (i = 0; i < STRIBOG_WORD_COUNT; ++i)
		out->q[i] = read_le64 (in->q + i);
}

static void transform (void *state, const void *block, const u512 *count)
{
	struct stribog_state *o = state;
	u512 W;
	size_t i;

	load (block, &W);

	g (&o->N, &o->h, &W, &o->h);
	add512 (&o->N, count, &o->N);  /* add data size in bits */
	add512 (&o->Sum, &W, &o->Sum);
}

static void stribog_core_transform (void *state, const void *block)
{
	static const u512 N512 = { 512 };

	transform (state, block, &N512);
}

static void stribog_core_result (void *state, void *out)
{
	struct stribog_state *o = state;
	u64 *result = out;
	size_t i;

	for (i = 0; i < STRIBOG_ORDER; ++i)
		write_le64 (o->h.q[i], result + i);
}

static void stribog_core_final (void *state, const void *in, size_t len,
				void *out)
{
	static const u512 N0;
	struct stribog_state *o = state;
	u8 block[STRIBOG_BLOCK_SIZE];
	u8 *const head = block;
	u8 *const one = head + len;
	u8 *const end = head + sizeof (block);
	u512 bits = {};

	if (len == STRIBOG_BLOCK_SIZE) {
		stribog_core_transform (state, in);
		len = 0;
	}

	memcpy (block, in, len);

	/* pad message */
	*one = 1;
	memset (one + 1, 0, end - (one + 1));

	bits.q[0] = len * 8;
	transform (state, block, &bits);

	g (&N0, &o->h, &o->N,   &o->h);
	g (&N0, &o->h, &o->Sum, &o->h);

	stribog_core_result (state, out);
	stribog_core_init (state);
}

const struct crypto_core stribog_core = {
	.alloc		= stribog_core_alloc,
	.free		= free,

	.get		= stribog_core_get,
	.set		= stribog_core_set,

	.transform	= stribog_core_transform,
	.final		= stribog_core_final,
};
