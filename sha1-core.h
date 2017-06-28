/*
 * NIST FIPS-180-4: Secure Hash Standard (SHS)
 *
 * SHA1 Core
 *
 * Copyright (c) 2017 Alexei A. Smekalkine
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CRYPTO_SHA1_CORE_H
#define CRYPTO_SHA1_CORE_H  1

#include "core.h"

#define SHA1_WORD_SIZE	4
#define SHA1_WORD_COUNT	16
#define SHA1_ORDER	5

#define SHA1_BLOCK_SIZE	(SHA1_WORD_SIZE * SHA1_WORD_COUNT)
#define SHA1_HASH_SIZE  (SHA1_WORD_SIZE * SHA1_ORDER)

void sha1_core_init (void *state);
void sha1_core_transform (void *state, void *block);
void sha1_core_final (void *state, void *block, u64 count);
void sha1_core_result (void *state, void *out);

#endif  /* CRYPTO_SHA1_CORE_H */
