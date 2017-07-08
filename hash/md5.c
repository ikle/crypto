/*
 * The MD5 Message-Digest Algorithm
 *
 * Copyright (c) 2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * Standard: RFC 1321
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <core.h>
#include <hash/md5.h>

#define MD5_WORD_SIZE	4
#define MD5_WORD_COUNT	16
#define MD5_ORDER	4

#define MD5_BLOCK_SIZE	(MD5_WORD_SIZE * MD5_WORD_COUNT)
#define MD5_HASH_SIZE	(MD5_WORD_SIZE * MD5_ORDER)

static const u32 H0[MD5_ORDER] = {
	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
};

static u32 F (u32 x, u32 y, u32 z)
{
	return ((y ^ z) & x) ^ z;	/* = (x & y) | (~x & z) */
}

static u32 G (u32 x, u32 y, u32 z)
{
	return F (z, x, y);
}

static u32 H (u32 x, u32 y, u32 z)
{
	return x ^ y ^ z;
}

static u32 I (u32 x, u32 y, u32 z)
{
	return (~z | x) ^ y;
}

static const size_t k[64] = {
	/* i */
	0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
	/* 5i + 1 (mod 16) */
	1,  6, 11,  0,  5, 10, 15,  4,  9, 14,  3,  8, 13,  2,  7, 12,
	/* 3i + 5 (mod 16) */
	5,  8, 11, 14,  1,  4,  7, 10, 13,  0,  3,  6,  9, 12, 15,  2,
	/* 7i (mod 16) */
	0,  7, 14,  5, 12,  3, 10,  1,  8, 15,  6, 13,  4, 11,  2,  9,
};

static const size_t s[64] = {
	7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
};

/* T[i] = floor (2^32 * abs (sin (i + 1))) */
static const u32 T[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,

	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,

	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,

	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

#define STEP_ONE(f, a, b, c, d, i)  do {		\
		a += f (b, c, d) + W[k[i]] + T[i];	\
		a = rol32 (a, s[i]);			\
		a += b;					\
	} while (0)

#define STEP_GROUP(f, a, b, c, d, i)  do {		\
		STEP_ONE(f, a, b, c, d, (i) + 0);	\
		STEP_ONE(f, d, a, b, c, (i) + 1);	\
		STEP_ONE(f, c, d, a, b, (i) + 2);	\
		STEP_ONE(f, b, c, d, a, (i) + 3);	\
	} while (0);

#define ROUND(f, a, b, c, d, i)  do {			\
		STEP_GROUP(f, a, b, c, d, (i) +  0);	\
		STEP_GROUP(f, a, b, c, d, (i) +  4);	\
		STEP_GROUP(f, a, b, c, d, (i) +  8);	\
		STEP_GROUP(f, a, b, c, d, (i) + 12);	\
	} while (0)

struct md5_state {
	u32 hash[MD5_ORDER];
	u64 count;
};

static void md5_core_init (void *state)
{
	struct md5_state *o = state;

	memcpy (o->hash, H0, sizeof (o->hash));
	barrier_data (o->hash);
	o->count = 0;
}

static void *md5_core_alloc (void)
{
	struct md5_state *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	md5_core_init (o);
	return o;
}

static int md5_core_get (const void *state, int type, ...)
{
	switch (type) {
	case CRYPTO_BLOCK_SIZE:	return MD5_BLOCK_SIZE;
	case CRYPTO_HASH_SIZE:	return MD5_HASH_SIZE;
	}

	return -ENOSYS;
}

static int md5_core_set (void *state, int type, ...)
{
	return -ENOSYS;
}

static void load (const u32 *in, u32 *out)
{
	size_t i;

	for (i = 0; i < MD5_WORD_COUNT; ++i)
		out[i] = read_le32 (in + i);
}

static void transform (void *state, const void *block, u64 count)
{
	struct md5_state *o = state;
	u32 W[MD5_WORD_COUNT];
	u32 a, b, c, d;

	load (block, W);

	a = o->hash[0];
	b = o->hash[1];
	c = o->hash[2];
	d = o->hash[3];

	ROUND (F, a, b, c, d,  0);
	ROUND (G, a, b, c, d, 16);
	ROUND (H, a, b, c, d, 32);
	ROUND (I, a, b, c, d, 48);

	o->hash[0] += a;
	o->hash[1] += b;
	o->hash[2] += c;
	o->hash[3] += d;

	o->count += count;
}

static void md5_core_transform (void *state, const void *block)
{
	struct md5_state *o = state;

	transform (state, block, MD5_BLOCK_SIZE);
}

static void md5_core_result (void *state, void *out)
{
	struct md5_state *o = state;
	u32 *result = out;
	size_t i;

	for (i = 0; i < MD5_ORDER; ++i)
		write_le32 (o->hash[i], result + i);
}

static void md5_core_final (void *state, const void *in, size_t len, void *out)
{
	struct md5_state *o = state;
	u8 block[MD5_BLOCK_SIZE];
	u8 *const head = block;
	u8 *const one = head + len;
	u8 *const end = head + sizeof (block);
	u8 *const num = end - 8;

	if (len == MD5_BLOCK_SIZE) {
		transform (state, in, MD5_BLOCK_SIZE);
		len = 0;
	}

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

	write_le64 ((o->count + len) * 8, num);
	transform (state, block, 0);
	md5_core_result (state, out);
	md5_core_init (state);
}

const struct crypto_core md5_core = {
	.alloc		= md5_core_alloc,
	.free		= free,

	.get		= md5_core_get,
	.set		= md5_core_set,

	.transform	= md5_core_transform,
	.final		= md5_core_final,
};
