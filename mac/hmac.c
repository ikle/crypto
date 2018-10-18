/*
 * HMAC: The Keyed-Hash Message Authentication Code
 *
 * Copyright (c) 2011-2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * Standard: RFC 2104, FIPS 198-1
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <crypto/api.h>
#include <crypto/types.h>
#include <crypto/utils.h>

#include <mac/hmac.h>

struct state {
	const struct crypto_core *core;
	void *block;
	size_t avail;
	struct crypto *hash;
	u8 *pad;
};

static void hmac_reset (struct state *o)
{
	if (o->hash == NULL)
		return;

	const size_t bs = crypto_get_block_size (o->hash);

	memset (o->pad, 0, bs);
	barrier_data (o->pad);

	crypto_reset (o->hash);
}

static void hmac_core_fini (struct state *o)
{
	if (o->hash == NULL)
		return;

	hmac_reset (o);

	crypto_free (o->hash);
	free (o->pad);

	o->hash = NULL;
}

static int set_algo (struct state *o, va_list ap)
{
	struct crypto *algo = va_arg (ap, struct crypto *);
	int error;

	if (algo == NULL)
		return -EINVAL;

	hmac_core_fini (o);
	o->hash = algo;

	const size_t bs = crypto_get_block_size  (o->hash);
	const size_t hs = crypto_get_output_size (o->hash);

	if (hs > bs) {
		error = -EINVAL;
		goto wrong_hash;
	}

	if ((o->pad = malloc (bs)) == NULL) {
		error = -ENOMEM;
		goto no_pad;
	}

	return 0;
no_pad:
wrong_hash:
	crypto_free (o->hash);
	o->hash = NULL;
	return error;
}

static void init_hash (struct state *o, size_t bs)
{
	size_t i;

	for (i = 0; i < bs; ++i)
		o->pad[i] ^= (0x5c ^ 0x36);

	o->hash->core->transform (o->hash, o->pad);
}

static int set_key (struct state *o, va_list ap)
{
	const void *key = va_arg (ap, const void *);
	size_t len = va_arg (ap, size_t);

	if (o->hash == NULL || key == NULL)
		return -EINVAL;

	const size_t bs = crypto_get_block_size (o->hash);
	size_t i;

	memset (o->pad, 0, bs);

	if (len > bs) {
		crypto_update (o->hash, key, len);
		crypto_fetch  (o->hash, o->pad, bs);
	}
	else
		memcpy (o->pad, key, len);

	for (i = 0; i < bs; ++i)
		o->pad[i] ^= 0x5c;

	init_hash (o, bs);
	return 0;
}

static void *hmac_core_alloc (void)
{
	struct state *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	o->hash = NULL;
	return o;
}

static int hmac_core_get (const void *state, int type, va_list ap)
{
	const struct state *o = state;

	switch (type) {
	case CRYPTO_BLOCK_SIZE:
	case CRYPTO_OUTPUT_SIZE:
		return o->hash == NULL ? -EINVAL :
					 o->core->get (o->hash, type, ap);
	}

	return -ENOSYS;
}

static int hmac_core_set (void *state, int type, va_list ap)
{
	switch (type) {
	case CRYPTO_RESET:
		hmac_reset (state);
		return 0;
	case CRYPTO_ALGO:
		return set_algo (state, ap);
	case CRYPTO_KEY:
		return set_key (state, ap);
	}

	return -ENOSYS;
}

static void hmac_core_free (void *state)
{
	hmac_core_fini (state);
	free (state);
}

static void hmac_core_transform (void *state, const void *block)
{
	struct state *o = state;

	o->hash->core->transform (o->hash, block);
}

static void hmac_core_final (void *state, const void *in, size_t len,
			     void *out)
{
	struct state *o = state;
	const size_t bs = crypto_get_block_size  (o->hash);
	const size_t hs = crypto_get_output_size (o->hash);

	o->hash->core->final (o->hash, in, len, out);
	init_hash (o, bs);
	o->hash->core->final (o->hash, out, hs, out);
	init_hash (o, bs);
}

const struct crypto_core hmac_core = {
	.alloc		= hmac_core_alloc,
	.free		= hmac_core_free,

	.get		= hmac_core_get,
	.set		= hmac_core_set,

	.transform	= hmac_core_transform,
	.final		= hmac_core_final,
};
