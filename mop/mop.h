/*
 * Block cipher mode of operation, common code
 *
 * Copyright (c) 2011-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * Standard: NIST FIPS 81, NIST SP 800-38A, GOST R 34.13-2015
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CRYPTO_MOP_CORE_H
#define CRYPTO_MOP_CORE_H  1

#include <stdarg.h>

#include <crypto/api.h>
#include <crypto/core.h>
#include <crypto/types.h>

struct state {
	struct crypto crypto;
	struct crypto *cipher;
	u8 *iv;
};

void *mop_alloc (void);
void mop_free (void *state);

int mop_get (const void *state, int type, va_list ap);
int mop_set (void *state, int type, va_list ap);

#endif  /* CRYPTO_MOP_CORE_H */
