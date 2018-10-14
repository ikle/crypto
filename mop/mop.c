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

#include <crypto/utils.h>

#include "mop.h"

void *mop_alloc (void)
{
	struct state *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	o->cipher = NULL;
	return o;
}

static void mop_reset (struct state *o)
{
	if (o->cipher == NULL)
		return;

	const size_t bs = cipher_get_block_size (o->cipher);

	memset (o->iv, 0, bs);
	barrier_data (o->iv);

	o->cipher->core->set (o->cipher, CRYPTO_RESET);
}

static void mop_fini (struct state *o)
{
	if (o->cipher == NULL)
		return;

	mop_reset (o);

	cipher_free (o->cipher);
	free (o->iv);

	o->cipher = NULL;
}

void mop_free (void *state)
{
	struct state *o = state;

	if (o == NULL)
		return;

	mop_fini (o);
	free (o);
}

static int set_algo (struct state *o, va_list ap)
{
	struct cipher *algo = va_arg (ap, struct cipher *);
	int error;

	if (algo == NULL)
		return -EINVAL;

	mop_fini (o);

	o->cipher = algo;

	const size_t bs = cipher_get_block_size (o->cipher);

	if (bs < 8) {
		error = -EINVAL;  /* we wont support too weak ciphers */
		goto no_bs;
	}

	if ((o->iv = calloc (1, bs)) == NULL) {
		error = -errno;  /* PTR_ERR (o->iv) */
		goto no_iv;
	}

	return 0;
no_iv:
no_bs:
	cipher_free (o->cipher);
	o->cipher = NULL;
	return error;
}

static int set_iv (struct state *o, va_list ap)
{
	const void  *iv  = va_arg (ap, const void *);
	const size_t len = va_arg (ap, size_t);
	const size_t bs  = cipher_get_block_size (o->cipher);

	if (len != bs)
		return -EINVAL;

	memcpy (o->iv, iv, len);
	return 0;
}

int mop_get (const void *state, int type, ...)
{
	const struct state *o = state;

	if (type == CRYPTO_HASH_SIZE)
		type = CRYPTO_BLOCK_SIZE;

	return o->cipher->core->get (o->cipher, type);
}

int mop_set (void *state, int type, ...)
{
	struct state *o = state;
	va_list ap;

	va_start (ap, type);

	switch (type) {
	case CRYPTO_RESET:
		mop_reset (state);
		return 0;
	case CRYPTO_ALGO:
		return set_algo (state, ap);
	case CRYPTO_KEY: {
		const void *key = va_arg (ap, const void *);
		size_t len = va_arg (ap, size_t);

		return cipher_set_key (o->cipher, key, len);
	}
	case CRYPTO_IV:
		return set_iv (state, ap);
	}

	va_end (ap);
	return -ENOSYS;
}
