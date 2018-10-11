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

#ifndef CRYPTO_PBKDF1_H
#define CRYPTO_PBKDF1_H  1

#include <crypto/hash.h>

int pbkdf1 (struct hash *prf, const void *key, size_t key_len,
	    const void *salt, size_t salt_len,
	    unsigned count, void *out, size_t len);

#endif  /* CRYPTO_PBKDF1_H */
