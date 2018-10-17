/*
 * CFB: Cipher Feedback
 *
 * Copyright (c) 2011-2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * Standard: NIST FIPS 81, NIST SP 800-38A, GOST R 34.13-2015
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <string.h>
#include <crypto/utils.h>
#include <mop/cfb.h>

#include "mop.h"

static void cfb_encrypt (void *state, const void *in, void *out)
{
	struct state *o = state;
	const size_t bs = crypto_get_block_size (o->cipher);

	crypto_encrypt (o->cipher, o->iv, o->iv);

	xor_block (in, o->iv, out, bs);

	memcpy (o->iv, out, bs);
}

static void cfb_decrypt (void *state, const void *in, void *out)
{
	struct state *o = state;
	const size_t bs = crypto_get_block_size (o->cipher);

	crypto_encrypt (o->cipher, o->iv, o->iv);

	xor_block (in, o->iv, out, bs);

	memcpy (o->iv, in, bs);
}

const struct crypto_core cfb_core = {
	.alloc		= mop_alloc,
	.free		= mop_free,

	.get		= mop_get,
	.set		= mop_set,

	.encrypt	= cfb_encrypt,
	.decrypt	= cfb_decrypt,
};
