/*
 * Crypto Cipher API
 *
 * Copyright (c) 2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CRYPTO_CIPHER_H
#define CRYPTO_CIPHER_H  1

#include <crypto-core.h>

struct cipher {
	const struct crypto_core *core;
	/* core-specific state follows */
};

static struct cipher *cipher_alloc (const struct crypto_core *core)
{
	struct cipher *o;

	if ((o = core->alloc ()) == NULL)
		return NULL;

	o->core = core;
	return o;
}

static void cipher_free (struct cipher *o)
{
	if (o == NULL)
		return;

	o->core->free (o);
}

static size_t cipher_get_block_size (const struct cipher *o)
{
	return o->core->get (o, CRYPTO_BLOCK_SIZE);
}

static int cipher_set_algo (struct cipher *o, const struct crypto_core *core)
{
	return o->core->set (o, CRYPTO_ALGO, core);
}

static int cipher_set_key (struct cipher *o, const void *key, size_t len)
{
	return o->core->set (o, CRYPTO_KEY, key, len);
}

static void cipher_encrypt_block (struct cipher *o, const void *in, void *out)
{
	o->core->encrypt (o, in ,out);
}

static void cipher_decrypt_block (struct cipher *o, const void *in, void *out)
{
	o->core->decrypt (o, in ,out);
}

#endif  /* CRYPTO_CIPHER_H */
