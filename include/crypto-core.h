/*
 * Crypto API Core
 *
 * Copyright (c) 2017 Alexei A. Smekalkine
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CRYPTO_HASH_CORE_H
#define CRYPTO_HASH_CORE_H  1

#include <stddef.h>

enum crypto_type {
	CRYPTO_BLOCK_SIZE,
	CRYPTO_HASH_SIZE,
	CRYPTO_ALGO,
	CRYPTO_KEY,
	CRYPTO_IV,
};

struct crypto_core {
	void *(*alloc) (void);
	void (*free) (void *state);

	int (*get) (const void *state, int type, ...);
	int (*set) (void *state, int type, ...);

	/* encrypt/decrypt one block of data */
	void (*encrypt) (void *state, const void *in, void *out);
	void (*decrypt) (void *state, const void *in, void *out);

	void (*transform) (void *state, const void *block);
	void (*final) (void *state, const void *in, size_t len, void *out);
};

struct hash *hash_alloc (const struct crypto_core *core);
void hash_free (struct hash *h);

size_t hash_get_block_size (const struct hash *h);
size_t hash_get_hash_size  (const struct hash *h);

int hash_set_algo (struct hash *h, const struct crypto_core *core);
int hash_set_key  (struct hash *h, const void *key, size_t len);

/*
 * 1. Process integer number of input blocks.
 * 2. If out != NULL then process last possiby partial block and write
 *    final hash value to out.
 *
 * This function never stores input plain text data in context.
 *
 * Returns number of bytes processed.
 */
size_t hash_core_process (const struct crypto_core *core, void *state,
			  const void *in, size_t len, void *out);
size_t hash_data (struct hash *h, const void *in, size_t len, void *out);

#endif  /* CRYPTO_HASH_CORE_H */
