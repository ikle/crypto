/*
 * Crypto Key Derivation Function API
 *
 * Copyright (c) 2017-2018 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CRYPTO_KDF_H
#define CRYPTO_KDF_H  1

#include <errno.h>
#include <crypto/core.h>
#include <crypto/hash.h>

/* old API */
struct kdf_core {
	int (*compute) (struct hash *prf, const void *key, size_t key_len,
			const void *salt, size_t salt_len,
			unsigned count, void *out, size_t len);
};

/* new API */
struct kdf {
	const struct crypto_core *core;
	void *block;
	size_t avail;
	/* core-specific state follows */
};

static inline
struct kdf *kdf_alloc (const struct crypto_core *core)
{
	return (void *) hash_alloc (core);
}

static inline
size_t kdf_get_size (const struct kdf *o)
{
	int ret;

	if ((ret = o->core->get (o, CRYPTO_HASH_SIZE)) > 0)
		return ret;

	errno = ret == 0 ? EINVAL : -ret;
	return 0;
}

static inline
int kdf_set_prf (struct kdf *o, struct hash *prf)
{
	errno = -o->core->set (o, CRYPTO_ALGO, prf);
	return errno == 0;
}

static inline
int kdf_set_key (struct kdf *o, const void *key, size_t len)
{
	errno = -o->core->set (o, CRYPTO_KEY, key, len);
	return errno == 0;
}

static inline
int kdf_set_salt (struct kdf *o, const void *salt, size_t len)
{
	errno = -o->core->set (o, CRYPTO_SALT, salt, len);
	return errno == 0;
}

static inline
int kdf_set_count (struct kdf *o, size_t count)
{
	errno = -o->core->set (o, CRYPTO_COUNT, count);
	return errno == 0;
}

static inline
int kdf_compute (struct kdf *o, void *to, size_t len)
{
	if (len > kdf_get_size (o)) {
		errno = EINVAL;
		return 0;
	}

	o->core->final (o, NULL, len, to);
	return 1;
}

#endif  /* CRYPTO_KDF_H */
