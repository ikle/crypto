/*
 * Crypto API Internal Helpers
 *
 * Copyright (c) 2011-2018 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H  1

#include <crypto/types.h>

#ifdef __GNUC__
#define barrier_data(p)  __asm__ __volatile__ ("" :: "r"(p) : "memory")
#else
#define barrier_data(p)
#endif

/* allows 0 <= count < 32 */
static inline u32 rol32 (u32 x, unsigned count)
{
	return x << count | x >> (32 - count);
}

static inline void xor_block (const u8 *a, const u8 *b, u8 *out, size_t count)
{
	size_t i;

	for (i = 0; i < count; ++i)
		out[i] = a[i] ^ b[i];
}

#endif  /* CRYPTO_UTILS_H */
