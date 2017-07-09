/*
 * CMAC: One-key MAC 1
 *
 * Copyright (c) 2011-2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * NIST SP 800-38B, GOST R 34.13-2015
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <string.h>
#include <crypto/utils.h>
#include <mac/cmac.h>

#include "../mop/mop.h"

static void cmac_update (void *state, const void *block)
{
	struct state *o = state;
	const size_t bs = o->algo->get (o->cipher, CRYPTO_BLOCK_SIZE);

	xor_block (o->iv, block, o->iv, bs);
	o->algo->encrypt (o->cipher, o->iv, o->iv);
}

static void mangle_key (const u8 *k0, u8 *k1, size_t len)
{
	int i;  /* must be signed! */
	int ci, co;

	for (ci = 0, i = len - 1; i >= 0; ci = co, --i) {
		co = (k0[i] & 0x80) != 0;
		k1[i] = (k0[i] << 1) | ci;
	}

	if (!co)
		return;

	if (len == 8)
		k1[len - 1] ^= 0x1b;
	else if (len == 16)
		k1[len - 1] ^= 0x87;
	/* else error: need polynomial */
}

static void cmac_final (void *state, const void *in, size_t len, void *out)
{
	struct state *o = state;
	const size_t bs = o->algo->get (o->cipher, CRYPTO_BLOCK_SIZE);
	u8 K[bs], W[bs];

	memset (K, 0, bs);
	o->algo->encrypt (o->cipher, K, K);
	mangle_key (K, K, bs);

	memcpy (W, in, len);

	if (len < bs) {
		W[len] = 0x80;
		memset (W + len + 1, 0, bs - len - 1);
		mangle_key (K, K, bs);
	}

	xor_block (W, o->iv, W, bs);
	xor_block (W, K,     W, bs);
	o->algo->encrypt (o->cipher, W, out);
}

const struct crypto_core cmac_core = {
	.alloc		= mop_alloc,
	.free		= mop_free,

	.get		= mop_get,
	.set		= mop_set,

	.transform	= cmac_update,
	.final		= cmac_final,
};
