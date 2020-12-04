/*
 * CTR: Counter
 *
 * Copyright (c) 2011-2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * Standard: NIST FIPS 81, NIST SP 800-38A, GOST R 34.13-2015
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <crypto/endian.h>
#include <crypto/utils.h>
#include <mop/ctr.h>

#include "mop.h"

/* count MUST be multiple of eight */
static void inc_block_be (const u8 *in, u8 *out, size_t count)
{
	u64 n, m, c;

	for (c = 0; count > 0; count -= 8) {
		n = read_be64 (in + count - 8);
		m = n + c + 1;
		c = m < n;
		write_be64 (m, out + count - 8);
	}
}

static void ctr_crypt (void *state, const void *in, void *out)
{
	struct state *o = state;
	const size_t bs = crypto_get_block_size (o->cipher);
	u8 pat[bs];

	crypto_encrypt (o->cipher, o->iv, pat);
	xor_block (in, pat, out, bs);

	inc_block_be (o->iv, o->iv, bs);
}

const struct crypto_core ctr_core = {
	.alloc		= mop_alloc,
	.free		= mop_free,

	.get		= mop_get,
	.set		= mop_set,

	.encrypt	= ctr_crypt,
	.decrypt	= ctr_crypt,
};
