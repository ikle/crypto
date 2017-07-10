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

#include <crypto-core.h>

struct pbkdf2 *pbkdf2_alloc (const struct crypto_core *prf_core, void *prf,
			     const void *key,  size_t key_len,
			     const void *salt, size_t salt_len,
			     unsigned count);
void pbkdf2_free (struct pbkdf2 *o);

void pbkdf2 (struct pbkdf2 *o, void *out, size_t len);

#endif  /* CRYPTO_PBKDF2_H */
