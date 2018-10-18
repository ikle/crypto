/*
 * PBKDF2: The Password-Based Key Deriavation Function #2
 *
 * Copyright (c) 2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * Standard: RFC 2898 (PKCS #5 v2.0), RFC 8018 (PKCS #5 v2.1)
 * Standard: GOST R 50.1.111-2016
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <crypto/api.h>
#include <crypto/endian.h>
#include <crypto/types.h>
#include <crypto/utils.h>

#include <kdf/pbkdf2.h>

static void F (struct crypto *prf, const u8 *salt, size_t salt_len,
	       size_t count, size_t index, void *out)
{
	u8 buf[4];
	const size_t hs = crypto_get_output_size (prf);
	u8 hash[hs];

	crypto_update (prf, salt, salt_len);
	write_be32 (index, buf);
	crypto_update (prf, buf, 4);
	crypto_fetch  (prf, hash, hs);
	memcpy (out, hash, hs);

	for (; count > 1; --count) {
		crypto_update (prf, hash, hs);
		crypto_fetch  (prf, hash, hs);
		xor_block (out, hash, out, hs);
	}
}

struct state {
	const struct crypto_core *core;
	void *block;
	size_t avail;

	struct crypto *prf;
	const void *salt;
	size_t salt_len;
	size_t count;
};

static void pbkdf2_fini (struct state *o)
{
	crypto_free (o->prf);
	o->prf = NULL;
}

static int set_prf (struct state *o, va_list ap)
{
	struct crypto *prf = va_arg (ap, struct crypto *);

	if (prf == NULL)
		return -EINVAL;

	pbkdf2_fini (o);
	o->prf = prf;

	return 0;
}

static int set_salt (struct state *o, va_list ap)
{
	const void *salt = va_arg (ap, const void *);
	size_t len = va_arg (ap, size_t);

	if (o->prf == NULL || salt == NULL)
		return -EINVAL;

	o->salt     = salt;
	o->salt_len = len;
	return 0;
}

static void *pbkdf2_alloc (void)
{
	struct state *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	o->prf   = NULL;
	o->count = 0;
	return o;
}

static void pbkdf2_free (void *state)
{
	pbkdf2_fini (state);
	free (state);
}

static int pbkdf2_get (const void *state, int type, va_list ap)
{
	const struct state *o = state;

	if (o->prf == NULL)
		return -EINVAL;

	switch (type) {
	case CRYPTO_OUTPUT_SIZE:
		return UINT32_MAX;
	}

	return -ENOSYS;
}

static int pbkdf2_set (void *state, int type, va_list ap)
{
	struct state *o = state;

	switch (type) {
	case CRYPTO_RESET:
		return o->prf->core->set (o->prf, type, ap);
	case CRYPTO_ALGO:
		return set_prf (o, ap);
	case CRYPTO_KEY:
		return o->prf == NULL ? -EINVAL :
					o->prf->core->set (o->prf, type, ap);
	case CRYPTO_SALT:
		return set_salt (o, ap);
	case CRYPTO_COUNT:
		o->count = va_arg (ap, size_t);
		return 0;
	}

	return -ENOSYS;
}

static int pbkdf2_fetch (void *state, void *out, size_t len)
{
	struct state *o = state;

	if (o->prf == NULL || o->salt == NULL)
		return -EINVAL;

	size_t count = o->count == 0 ? 1000 : o->count;
	u8 *p;
	size_t i;
	const size_t hs = crypto_get_output_size (o->prf);
	u8 hash[hs];

	for (p = out, i = 1; len > hs; p += hs, len -= hs, ++i)
		F (o->prf, o->salt, o->salt_len, count, i, p);

	F (o->prf, o->salt, o->salt_len, count, i, hash);
	memcpy (p, hash, len);

	return 0;
}

const struct crypto_core pbkdf2_core = {
	.alloc		= pbkdf2_alloc,
	.free		= pbkdf2_free,

	.get		= pbkdf2_get,
	.set		= pbkdf2_set,

	.fetch		= pbkdf2_fetch,
};
