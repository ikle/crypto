/*
 * PBKDF1: The Password-Based Key Deriavation Function #1
 *
 * Copyright (c) 2018 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * Standard: PKCS #5 v1.5
 * Standard: RFC 2898 (PKCS #5 v2.0), RFC 8018 (PKCS #5 v2.1)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <crypto/hash.h>
#include <crypto/types.h>

#include <kdf/pbkdf1.h>

struct state {
	const struct crypto_core *core;
	void *block;
	size_t avail;

	struct hash *prf;
	const void *salt;
	size_t salt_len;
	size_t count;
	u8 *hash;
};

static void pbkdf1_fini (struct state *o)
{
	hash_free (o->prf);
	o->prf = NULL;
	free (o->hash);
	o->hash = NULL;
}

static int set_prf (struct state *o, va_list ap)
{
	struct hash *prf = va_arg (ap, struct hash *);

	if (prf == NULL)
		return -EINVAL;

	pbkdf1_fini (o);
	o->prf = prf;

	const size_t hs = hash_get_hash_size (prf);

	if ((o->hash = malloc (hs)) == NULL)
		return -ENOMEM;

	return 0;
}

static int set_key (struct state *o, va_list ap)
{
	const void *key = va_arg (ap, const void *);
	size_t len = va_arg (ap, size_t);

	if (o->prf == NULL || key == NULL)
		return -EINVAL;

	// 1. hash_start (o->prf)
	hash_data (o->prf, key, len, NULL);
	// 3. mark "key installed"

	return 0;
}

static int set_salt (struct state *o, va_list ap)
{
	const void *salt = va_arg (ap, const void *);
	size_t len = va_arg (ap, size_t);

	if (o->prf == NULL || salt == NULL)
		return -EINVAL;

	o->salt     = salt;
	o->salt_len = len;
	return 0;
}

static void *pbkdf1_alloc (void)
{
	struct state *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	o->prf   = NULL;
	o->count = 0;
	o->hash  = NULL;
	return o;
}

static void pbkdf1_free (void *state)
{
	pbkdf1_fini (state);
	free (state);
}

static int pbkdf1_get (const void *state, int type, ...)
{
	const struct state *o = state;

	if (o->prf == NULL)
		return -EINVAL;

	switch (type) {
	case CRYPTO_HASH_SIZE:
		return hash_get_hash_size (o->prf);
	}

	return -ENOSYS;
}

static int pbkdf1_set (void *state, int type, ...)
{
	struct state *o = state;
	va_list ap;

	va_start (ap, type);

	switch (type) {
	case CRYPTO_ALGO:
		return set_prf (o, ap);
	case CRYPTO_KEY:
		return set_key (o, ap);
	case CRYPTO_SALT:
		return set_salt (o, ap);
	case CRYPTO_COUNT:
		o->count = va_arg (ap, size_t);
		return 0;
	}

	va_end (ap);
	return -ENOSYS;
}

static int pbkdf1_fetch (void *state, void *out, size_t len)
{
	struct state *o = state;

	if (o->prf == NULL || o->salt == NULL)
		return -EINVAL;

	size_t count = o->count == 0 ? 1000 : o->count;
	const size_t hs = hash_get_hash_size (o->prf);

	hash_data (o->prf, o->salt, o->salt_len, o->hash);

	/* 3. T_i = Hash (T_{i-1}) */
	for (--count; count > 0; --count)
		hash_data (o->prf, o->hash, hs, o->hash);

	if (len > hs)
		len = hs;

	memcpy (out, o->hash, len);
	return 0;
}

const struct crypto_core pbkdf1_core = {
	.alloc		= pbkdf1_alloc,
	.free		= pbkdf1_free,

	.get		= pbkdf1_get,
	.set		= pbkdf1_set,

	.fetch		= pbkdf1_fetch,
};
