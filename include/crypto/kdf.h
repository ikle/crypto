/*
 * Crypto Key Derivation Function API
 *
 * Copyright (c) 2017-2018 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CRYPTO_KDF_H
#define CRYPTO_KDF_H  1

#include <crypto/hash.h>

struct kdf_core {
	int (*compute) (struct hash *prf, const void *key, size_t key_len,
			const void *salt, size_t salt_len,
			unsigned count, void *out, size_t len);
};

static inline
int kdf (const struct kdf_core *o,
	 struct hash *prf, const void *key, size_t key_len,
	 const void *salt, size_t salt_len,
	 unsigned count, void *out, size_t len)
{
	o->compute (prf, key, key_len, salt, salt_len, count, out, len);
}

#endif  /* CRYPTO_KDF_H */
