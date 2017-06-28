/*
 * RFC 1321: The MD5 Message-Digest Algorithm
 *
 * MD5 Core
 *
 * Copyright (c) 2017 Alexei A. Smekalkine
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CRYPTO_MD5_CORE_H
#define CRYPTO_MD5_CORE_H  1

#include "core.h"

#define MD5_WORD_SIZE	4
#define MD5_WORD_COUNT	16
#define MD5_ORDER	4

#define MD5_BLOCK_SIZE	(MD5_WORD_SIZE * MD5_WORD_COUNT)
#define MD5_HASH_SIZE	(MD5_WORD_SIZE * MD5_ORDER)

void md5_core_init (void *state);
void md5_core_transform (void *state, void *block);
void md5_core_final (void *state, void *block, u64 count);
void md5_core_result (void *state, void *out);

#endif  /* CRYPTO_MD5_CORE_H */
