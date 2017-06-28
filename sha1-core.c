/*
 * NIST FIPS-180-4: Secure Hash Standard (SHS)
 *
 * SHA1 Core
 *
 * Copyright (c) 2017 Alexei A. Smekalkine
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <string.h>
#include <arpa/inet.h>

#include "sha1-core.h"

static const u32 H0[SHA1_ORDER] = {
	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
};

void sha1_core_init (void *state)
{
	memcpy (state, H0, sizeof (H0));
}

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

void sha1_core_transform (void *state, void *block)
{
	u32 *hash = state, *W = block;
	size_t i;
	u32 a, b, c, d, e;

	for (i = 0; i < SHA1_WORD_COUNT; ++i)
		W[i] = htonl (W[i]);

	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];
	e = hash[4];

	ROUND (Ch,     K[0], a, b, c, d, e,  0);
	ROUND (Parity, K[1], a, b, c, d, e, 20);
	ROUND (Maj,    K[2], a, b, c, d, e, 40);
	ROUND (Parity, K[3], a, b, c, d, e, 60);

	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
	hash[4] += e;
}

void sha1_core_final (void *state, void *block, u64 count)
{
	u8 *const head = block;
	const size_t offset = count % SHA1_BLOCK_SIZE;
	u8 *const one = head + offset;
	u8 *const end = head + SHA1_BLOCK_SIZE;
	u8 *const num = end - 8;

	*one = 0x80;

	if (num > one) {
		memset (one + 1, 0, num - (one + 1));
	}
	else {
		memset (one + 1, 0, end - (one + 1));
		sha1_core_transform (state, block);

		memset (head, 0, num - head);
	}

	write_be64 (count * 8, num);
	sha1_core_transform (state, block);
}

void sha1_core_result (void *state, void *out)
{
	u32 *hash = state, *result = out;
	size_t i;

	for (i = 0; i < SHA1_ORDER; ++i)
		write_be32 (hash[i], result + i);
}
