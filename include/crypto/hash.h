/*
 * Crypto Hash API
 *
 * Copyright (c) 2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CRYPTO_HASH_H
#define CRYPTO_HASH_H  1

#include <crypto/core.h>

struct hash {
	const struct crypto_core *core;
	void *block;
	size_t avail;
	/* core-specific state follows */
};

static inline
struct hash *hash_alloc (const struct crypto_core *core)
{
	struct hash *o;

	if ((o = core->alloc ()) == NULL)
		return NULL;

	o->core  = core;
	o->block = NULL;
	o->avail = 0;
	return o;
}

#include <stdlib.h>

static inline
void hash_free (struct hash *o)
{
	if (o == NULL)
		return;

	free (o->block);
	o->core->free (o);
}

static inline
size_t hash_get_block_size (const struct hash *o)
{
	return o->core->get (o, CRYPTO_BLOCK_SIZE);
}

static inline
size_t hash_get_hash_size (const struct hash *o)
{
	return o->core->get (o, CRYPTO_HASH_SIZE);
}

static inline
int hash_set_algo (struct hash *o, struct hash *algo)
{
	return o->core->set (o, CRYPTO_ALGO, algo);
}

static inline
int hash_set_key (struct hash *o, const void *key, size_t len)
{
	return o->core->set (o, CRYPTO_KEY, key, len);
}

/*
 * If out != NULL then process last possiby partial block and write final
 * hash value to out.
 *
 * Returns number of bytes processed or zero on error.
 */
size_t hash_data (struct hash *o, const void *in, size_t len, void *out);

#endif  /* CRYPTO_HASH_H */
