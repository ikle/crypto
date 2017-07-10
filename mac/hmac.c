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
	void *hash;
	u8 *pad;
	void *hi, *ho;
};

static void hmac_core_fini (struct state *o)
{
	if (o->core == NULL)
		return;

	const size_t bs = o->core->get (o->hash, CRYPTO_BLOCK_SIZE);

	memset (o->pad, 0, bs);
	barrier_data (o->pad);

	o->core->free (o->hash);
	free (o->pad);

	o->core->free (o->hi);
	o->core->free (o->ho);

	o->core = NULL;
}

static int set_algo (struct state *o, const struct crypto_core *core)
{
	hmac_core_fini (o);

	if (core == NULL)
		return -EINVAL;

	if ((o->hash = core->alloc ()) == NULL)
		goto no_hash;

	const size_t bs = core->get (o->hash, CRYPTO_BLOCK_SIZE);
	const size_t hs = core->get (o->hash, CRYPTO_HASH_SIZE);

	if (hs > bs) {
		errno = EINVAL;
		goto wrong_hash;
	}

	if ((o->pad = malloc (bs)) == NULL)
		goto no_pad;

	o->core = core;
	return 0;
no_pad:
wrong_hash:
	core->free (o->hash);
no_hash:
	return -errno;
}

static int set_key (struct state *o, const void *key, size_t len)
{
	if ((o->core->free (o->hi), o->hi = o->core->alloc ()) == NULL)
		return -errno;  /* PTR_ERR (o->hi) */

	if ((o->core->free (o->ho), o->ho = o->core->alloc ()) == NULL)
		return -errno;  /* PTR_ERR (o->ho) */

	const size_t bs = o->core->get (o->hi, CRYPTO_BLOCK_SIZE);
	size_t i;

	memset (o->pad, 0, bs);

	if (len > bs)
		hash_core_process (o->core, o->ho, key, len, o->pad);
	else
		memcpy (o->pad, key, len);

	for (i = 0; i < bs; ++i)
		o->pad[i] ^= 0x5c;

	o->core->transform (o->ho, o->pad);

	for (i = 0; i < bs; ++i)
		o->pad[i] ^= (0x5c ^ 0x36);

	o->core->transform (o->hi, o->pad);

	return 0;
}

static void *hmac_core_alloc (void)
{
	struct state *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	o->core = NULL;
	o->hi = NULL;
	o->ho = NULL;
	return o;
}

static int hmac_core_get (const void *state, int type, ...)
{
	const struct state *o = state;

	switch (type) {
	case CRYPTO_BLOCK_SIZE:
	case CRYPTO_HASH_SIZE:
		return o->core->get (o->hi, type);
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
			const struct crypto_core *core;

			core = va_arg (ap, const struct crypto_core *);
			status = set_algo (state, core);
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

	o->core->transform (o->hi, block);
}

static void hmac_core_final (void *state, const void *in, size_t len,
			     void *out)
{
	struct state *o = state;
	const size_t hs = o->core->get (o->hi, CRYPTO_HASH_SIZE);

	o->core->final (o->hi, in, len, out);
	o->core->final (o->ho, out, hs, out);
}

const struct crypto_core hmac_core = {
	.alloc		= hmac_core_alloc,
	.free		= hmac_core_free,

	.get		= hmac_core_get,
	.set		= hmac_core_set,

	.transform	= hmac_core_transform,
	.final		= hmac_core_final,
};
