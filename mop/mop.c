/*
 * Block cipher mode of operation, common code
 *
 * Copyright (c) 2011-2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * Standard: NIST FIPS 81, NIST SP 800-38A, GOST R 34.13-2015
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "mop.h"

void *mop_alloc (void)
{
	struct state *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	o->algo = NULL;
	return o;
}

static void reset (struct state *o)
{
	if (o->algo == NULL)
		return;

	const size_t bs = o->algo->get (o->cipher, CRYPTO_BLOCK_SIZE);

	memset (o->iv, 0, bs);
	barrier_data (o->iv);

	o->algo->free (o->cipher);
	free (o->iv);
}

void mop_free (void *state)
{
	struct state *o = state;

	if (o == NULL)
		return;

	reset (o);
	free (o);
}

static int set_algo (struct state *o, const struct crypto_core *algo)
{
	int error;

	if (algo == NULL)
		return -EINVAL;

	reset (o);

	if ((o->cipher = algo->alloc ()) == NULL) {
		error = -errno;  /* PTR_ERR (o->cipher) */
		goto no_cipher;
	}

	const size_t bs = algo->get (o->cipher, CRYPTO_BLOCK_SIZE);

	if ((o->iv = calloc (1, bs)) == NULL) {
		error = -errno;  /* PTR_ERR (o->iv) */
		goto no_iv;
	}

	o->algo = algo;
	return 0;
no_iv:
	algo->free (o->cipher);
no_cipher:
	return error;
}

static int set_key (struct state *o, const void *key, size_t len)
{
	return o->algo->set (o->cipher, CRYPTO_KEY, key, len);
}

static int set_iv (struct state *o, const void *iv)
{
	const size_t bs = o->algo->get (o->cipher, CRYPTO_BLOCK_SIZE);

	memcpy (o->iv, iv, bs);
}

int mop_get (const void *state, int type, ...)
{
	const struct state *o = state;

	return o->algo->get (o->cipher, type);
}

int mop_set (void *state, int type, ...)
{
	va_list ap;
	int status;

	va_start (ap, type);

	switch (type) {
	case CRYPTO_ALGO: {
		const struct crypto_core *algo =
			va_arg (ap, const struct crypto_core *);

		status = set_algo (state, algo);
		break;
	}
	case CRYPTO_KEY: {
		const void *key = va_arg (ap, const void *);
		size_t len = va_arg (ap, size_t);

		status = set_key (state, key, len);
		break;
	}
	case CRYPTO_IV: {
		const void *iv = va_arg (ap, const void *);

		status = set_iv (state, iv);
		break;
	}
	default:
		status = -ENOSYS;
	}

	va_end (ap);
	return status;
}
