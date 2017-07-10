/*
 * HMAC: The Keyed-Hash Message Authentication Code
 *
 * Copyright (c) 2011-2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * Standard: RFC 2104, FIPS 198-1
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <crypto/types.h>
#include <crypto/utils.h>
#include <mac/hmac.h>

struct state {
	const struct crypto_core *core;
	const struct crypto_core *algo;
	void *hash;
	u8 *pad;
};

static void hmac_core_fini (struct state *o)
{
	if (o->algo == NULL)
		return;

	const size_t bs = o->algo->get (o->hash, CRYPTO_BLOCK_SIZE);

	memset (o->pad, 0, bs);
	barrier_data (o->pad);

	o->algo->free (o->hash);
	free (o->pad);

	o->algo = NULL;
}

static int set_algo (struct state *o, const struct crypto_core *algo)
{
	hmac_core_fini (o);

	if (algo == NULL)
		return -EINVAL;

	if ((o->hash = algo->alloc ()) == NULL)
		goto no_hash;

	const size_t bs = algo->get (o->hash, CRYPTO_BLOCK_SIZE);
	const size_t hs = algo->get (o->hash, CRYPTO_HASH_SIZE);

	if (hs > bs) {
		errno = EINVAL;
		goto wrong_hash;
	}

	if ((o->pad = malloc (bs)) == NULL)
		goto no_pad;

	o->algo = algo;
	return 0;
no_pad:
wrong_hash:
	algo->free (o->hash);
no_hash:
	return -errno;
}

static void init_hash (struct state *o, size_t bs)
{
	size_t i;

	for (i = 0; i < bs; ++i)
		o->pad[i] ^= (0x5c ^ 0x36);

	o->algo->transform (o->hash, o->pad);
}

static int set_key (struct state *o, const void *key, size_t len)
{
	const size_t bs = o->algo->get (o->hash, CRYPTO_BLOCK_SIZE);
	size_t i;

	memset (o->pad, 0, bs);

	if (len > bs)
		hash_core_process (o->algo, o->hash, key, len, o->pad);
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

	o->algo = NULL;
	return o;
}

static int hmac_core_get (const void *state, int type, ...)
{
	const struct state *o = state;

	switch (type) {
	case CRYPTO_BLOCK_SIZE:
	case CRYPTO_HASH_SIZE:
		return o->algo->get (o->hash, type);
	}

	return -ENOSYS;
}

static int hmac_core_set (void *state, int type, ...)
{
	va_list ap;
	int status;

	va_start (ap, type);

	switch (type) {
	case CRYPTO_ALGO: {
			const struct crypto_core *algo;

			algo = va_arg (ap, const struct crypto_core *);
			status = set_algo (state, algo);
			break;
		}
	case CRYPTO_KEY: {
			const void *key;
			size_t len;

			key = va_arg (ap, const void *);
			len = va_arg (ap, size_t);
			status = set_key (state, key, len);
			break;
		}
	default:
		status = -ENOSYS;
	}

	va_end (ap);
	return status;
}

static void hmac_core_free (void *state)
{
	hmac_core_fini (state);
	free (state);
}

static void hmac_core_transform (void *state, const void *block)
{
	struct state *o = state;

	o->algo->transform (o->hash, block);
}

static void hmac_core_final (void *state, const void *in, size_t len,
			     void *out)
{
	struct state *o = state;
	const size_t bs = o->algo->get (o->hash, CRYPTO_BLOCK_SIZE);
	const size_t hs = o->algo->get (o->hash, CRYPTO_HASH_SIZE);

	o->algo->final (o->hash, in, len, out);
	init_hash (o, bs);
	o->algo->final (o->hash, out, hs, out);
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
