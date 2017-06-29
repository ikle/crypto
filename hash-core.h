/*
 * Hash API Core
 *
 * Copyright (c) 2017 Alexei A. Smekalkine
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CRYPTO_HASH_CORE_H
#define CRYPTO_HASH_CORE_H  1

#include <stddef.h>

struct hash_core {
	size_t block_size, hash_size;

	void *(*alloc) (void);
	void (*free) (void *state);
	void (*transform) (void *state, void *block);
	void (*final) (void *state, void *block, size_t len, void *out);
};

struct hash *hash_alloc (const struct hash_core *core);
void hash_free (struct hash *h);

int hash_update (struct hash *h, const void *in, size_t len);
int hash_final (struct hash *h, void *out);

#endif  /* CRYPTO_HASH_CORE_H */
