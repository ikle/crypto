/*
 * HMAC: The Keyed-Hash Message Authentication Code
 *
 * Copyright (c) 2011-2017 Alexei A. Smekalkine
 *
 * Standard: RFC 2104, FIPS 198-1
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "core.h"
#include "hash-core.h"
#include "md5-core.h"

struct state {
	const struct hash_core *core;
	void *hi, *ho;
};

static int set_algo (struct state *o, const struct hash_core *core)
{
	if (o->core != NULL) {
		o->core->free (o->hi); o->hi = NULL;
		o->core->free (o->ho); o->ho = NULL;
	}

	if (core == NULL || core->hash_size > core->block_size)
		return 0;  /* EINVAL */

	o->core = core;
	return 1;
}

static int set_key (struct state *o, const void *key, size_t len)
{
	const size_t bs = o->core->block_size;
	u8 block[bs];
	size_t i;

	if ((o->core->free (o->hi), o->hi = o->core->alloc ()) == NULL)
		return 0;  /* PTRERR (o->hi) */

	if ((o->core->free (o->ho), o->ho = o->core->alloc ()) == NULL)
		return 0;  /* PTRERR (o->ho) */

	memset (block, 0, bs);

	if (len > bs)
		hash_core_process (o->core, o->ho, key, len, block);
	else
		memcpy (block, key, len);

	for (i = 0; i < bs; ++i)
		block[i] ^= 0x5c;

	o->core->transform (o->ho, block);

	for (i = 0; i < bs; ++i)
		block[i] ^= (0x5c ^ 0x36);

	o->core->transform (o->hi, block);

	return 1;
}

static void *hmac_core_alloc (void)
{
	struct state *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	o->core = NULL;
	o->hi = NULL;
	o->ho = NULL;

#if 0
	return o;
#else
	/* temporary MD5("", data) */
	if (set_algo (o, &md5_core) && set_key (o, NULL, 0))
		return o;

	o->core->free (o->hi);
	o->core->free (o->ho);
	free (o);

	return NULL;
#endif
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
	return -ENOSYS;
}

static void hmac_core_free (void *state)
{
	struct state *o = state;

	if (o->core != NULL) {
		o->core->free (o->hi);
		o->core->free (o->ho);
	}

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

	o->core->final (o->hi, in, len, out);
	o->core->final (o->ho, out, o->core->hash_size, out);
}

/* MD5-only temporary */
#define MD5_BLOCK_SIZE	64
#define MD5_HASH_SIZE	16

const struct hash_core hmac_core = {
	.block_size	= MD5_BLOCK_SIZE,
	.hash_size	= MD5_HASH_SIZE,

	.alloc		= hmac_core_alloc,
	.free		= hmac_core_free,

	.get		= hmac_core_get,
	.set		= hmac_core_set,

	.transform	= hmac_core_transform,
	.final		= hmac_core_final,
};
