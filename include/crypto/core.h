/*
 * Crypto API Core
 *
 * Copyright (c) 2017-2018 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CRYPTO_CORE_H
#define CRYPTO_CORE_H  1

#include <stddef.h>

enum crypto_type {
	CRYPTO_RESET,
	CRYPTO_BLOCK_SIZE,
	CRYPTO_OUTPUT_SIZE,
	CRYPTO_ALGO,
	CRYPTO_KEY,
	CRYPTO_IV,
	CRYPTO_SALT,
	CRYPTO_COUNT,
};

struct crypto_core {
	void *(*alloc) (void);
	void (*free) (void *state);

	int (*get) (const void *state, int type, ...);
	int (*set) (void *state, int type, ...);

	/* encrypt/decrypt one block of data */
	void (*encrypt) (void *state, const void *in, void *out);
	void (*decrypt) (void *state, const void *in, void *out);

	/* transform one block of data, and finatize processing */
	void (*transform) (void *state, const void *block);
	void (*final) (void *state, const void *in, size_t len, void *out);

	/* update object with data, and fetch result */
	int (*update) (void *state, const void *in, size_t len);
	int (*fetch)  (void *state, void *out, size_t len);
};

#endif  /* CRYPTO_CORE_H */
