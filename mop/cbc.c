/*
 * CBC: Cipher Block Chaining
 *
 * Copyright (c) 2011-2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * Standard: NIST FIPS 81, NIST SP 800-38A, GOST R 34.13-2015
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <string.h>
#include <crypto/utils.h>
#include <mop/cbc.h>

#include "mop.h"

static void cbc_encrypt (void *state, const void *in, void *out)
{
	struct state *o = state;
	const size_t bs = cipher_get_block_size (o->cipher);

	xor_block (o->iv, in, o->iv, bs);

	cipher_encrypt_block (o->cipher, o->iv, o->iv);

	memcpy (out, o->iv, bs);
}

static void cbc_decrypt (void *state, const void *in, void *out)
{
	struct state *o = state;
	const size_t bs = cipher_get_block_size (o->cipher);

	cipher_decrypt_block (o->cipher, in, out);

	xor_block (o->iv, out, out, bs);

	memcpy (o->iv, in, bs);
}

const struct crypto_core cbc_core = {
	.alloc		= mop_alloc,
	.free		= mop_free,

	.get		= mop_get,
	.set		= mop_set,

	.encrypt	= cbc_encrypt,
	.decrypt	= cbc_decrypt,
};
