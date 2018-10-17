/*
 * Crypto Cipher API
 *
 * Copyright (c) 2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CRYPTO_CIPHER_H
#define CRYPTO_CIPHER_H  1

#include <crypto/core.h>

struct cipher {
	const struct crypto_core *core;
	/* core-specific state follows */
};

static inline
struct cipher *cipher_alloc (const struct crypto_core *core)
{
	struct cipher *o;

	if ((o = core->alloc ()) == NULL)
		return NULL;

	o->core = core;
	return o;
}

static inline
void cipher_free (struct cipher *o)
{
	if (o == NULL)
		return;

	o->core->free (o);
}

static inline
int cipher_get (const struct cipher *o, int type, ...)
{
	va_list ap;
	int ret;

	va_start (ap, type);
	ret = o->core->get (o, type, ap);
	va_end (ap);
	return ret;
}

static inline
int cipher_set (struct cipher *o, int type, ...)
{
	va_list ap;
	int ret;

	va_start (ap, type);
	ret = o->core->set (o, type, ap);
	va_end (ap);
	return ret;
}

static inline
size_t cipher_get_block_size (const struct cipher *o)
{
	return cipher_get (o, CRYPTO_BLOCK_SIZE);
}

static inline
int cipher_set_algo (struct cipher *o, const struct crypto_core *core)
{
	return cipher_set (o, CRYPTO_ALGO, core);
}

static inline
int cipher_set_key (struct cipher *o, const void *key, size_t len)
{
	return cipher_set (o, CRYPTO_KEY, key, len);
}

static inline
void cipher_encrypt_block (struct cipher *o, const void *in, void *out)
{
	o->core->encrypt (o, in ,out);
}

static inline
void cipher_decrypt_block (struct cipher *o, const void *in, void *out)
{
	o->core->decrypt (o, in ,out);
}

#endif  /* CRYPTO_CIPHER_H */
