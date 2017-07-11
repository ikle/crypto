/*
 * PBKDF2: The Password-Based Key Deriavation Function #2
 *
 * Copyright (c) 2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * Standard: RFC 2898 (PKCS #5 v2.0), RFC 8018 (PKCS #5 v2.1)
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CRYPTO_PBKDF2_H
#define CRYPTO_PBKDF2_H  1

#include <crypto/hash.h>

int pbkdf2 (struct hash *prf, const void *salt, size_t salt_len,
	    unsigned count, void *out, size_t len);

#endif  /* CRYPTO_PBKDF2_H */
