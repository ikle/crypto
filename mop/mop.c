/*
 * Block cipher mode of operation, common code
 *
 * Copyright (c) 2011-2023 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * Standard: NIST FIPS 81, NIST SP 800-38A, GOST R 34.13-2015
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
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

	const size_t bs = crypto_get_block_size (o->cipher);

	memset_secure (o->iv, 0, bs);
	crypto_reset (o->cipher);
}

static void mop_fini (struct state *o)
{
	if (o->cipher == NULL)
		return;

	mop_reset (o);

	crypto_free (o->cipher);
	free (o->iv);

	o->cipher = NULL;
}

void mop_free (void *state)
{
	if (state == NULL)
		return;

	mop_fini (state);
	free (state);
}

static int set_algo (struct state *o, va_list ap)
{
	struct crypto *algo = va_arg (ap, struct crypto *);
	int error;

	if (algo == NULL)
		return -EINVAL;

	mop_fini (o);
	o->cipher = algo;

	const size_t bs = crypto_get_block_size (o->cipher);

	if (bs < 8 || bs % 8 != 0) {
		/* we wont support too weak or strange ciphers */
		error = -EINVAL;
		goto no_bs;
	}

	if ((o->iv = calloc (1, bs)) == NULL) {
		error = -ENOMEM;
		goto no_iv;
	}

	return 0;
no_iv:
no_bs:
	crypto_free (o->cipher);
	o->cipher = NULL;
	return error;
}

static int set_iv (struct state *o, va_list ap)
{
	const void  *iv  = va_arg (ap, const void *);
	const size_t len = va_arg (ap, size_t);
	const size_t bs  = crypto_get_block_size (o->cipher);

	if (len != bs)
		return -EINVAL;

	memcpy (o->iv, iv, len);
	return 0;
}

int mop_get (const void *state, int type, va_list ap)
{
	const struct state *o = state;

	if (type == CRYPTO_OUTPUT_SIZE)
		type = CRYPTO_BLOCK_SIZE;

	return o->cipher->core->get (o->cipher, type, ap);
}

int mop_set (void *state, int type, va_list ap)
{
	struct state *o = state;

	switch (type) {
	case CRYPTO_RESET:
		mop_reset (state);
		return 0;
	case CRYPTO_ALGO:
		return set_algo (state, ap);
	case CRYPTO_KEY:
		return o->cipher->core->set (o->cipher, type, ap);
	case CRYPTO_IV:
		return set_iv (state, ap);
	}

	return -ENOSYS;
}
