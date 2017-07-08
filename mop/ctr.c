/*
 * CTR: Counter
 *
 * Copyright (c) 2011-2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * Standard: NIST FIPS 81, NIST SP 800-38A, GOST R 34.13-2015
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <mop/ctr.h>

#include "mop.h"

static void ctr_crypt (void *state, const void *in, void *out)
{
	struct state *o = state;
	const size_t bs = o->algo->get (o->cipher, CRYPTO_BLOCK_SIZE);
	u8 *n;

	o->algo->encrypt (o->cipher, o->iv, out);
	xor_block (in, out, out, bs);

	n = o->iv + bs - 8;  /* bs >= 8 */
	write_be64 (read_be64 (n) + 1, n);
}

const struct crypto_core ctr_core = {
	.alloc		= mop_alloc,
	.free		= mop_free,

	.get		= mop_get,
	.set		= mop_set,

	.encrypt	= ctr_crypt,
	.decrypt	= ctr_crypt,
};
