/*
 * PBKDF2: The Password-Based Key Deriavation Function #2
 *
 * Copyright (c) 2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * Standard: RFC 2898 (PKCS #5 v2.0), RFC 8018 (PKCS #5 v2.1)
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <crypto/types.h>
#include <crypto/endian.h>
#include <crypto/utils.h>
#include <crypto/pbkdf2.h>

struct pbkdf2 {
	const struct crypto_core *algo;	/* PRF core  */
	void *prf;			/* PRF state */
	const u8 *salt;
	size_t len;			/* salt length */
	unsigned count;
};

static void F (struct pbkdf2 *o, unsigned count, size_t index, void *out)
{
	size_t eaten, left;
	const size_t bs = o->algo->get (o->prf, CRYPTO_BLOCK_SIZE);
	u8 buf[bs + 4];

	eaten = hash_core_process (o->algo, o->prf, o->salt, o->len, NULL);
	left = o->len - eaten;

	memcpy (buf, o->salt + eaten, left);
	write_be32 (index, buf + left);

	const size_t hs = o->algo->get (o->prf, CRYPTO_HASH_SIZE);
	u8 hash[hs];

	hash_core_process (o->algo, o->prf, buf, left + 4, hash);
	memcpy (out, hash, hs);

	for (; count > 1; --count) {
		hash_core_process (o->algo, o->prf, hash, hs, hash);
		xor_block (out, hash, out, hs);
	}
}

struct pbkdf2 *pbkdf2_alloc (const struct crypto_core *prf_algo, void *prf,
			     const void *key,  size_t key_len,
			     const void *salt, size_t salt_len,
			     unsigned count)
{
	struct pbkdf2 *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		goto no_object;

	if ((errno = -prf_algo->set (prf, CRYPTO_KEY, key, key_len)) != 0)
		goto no_key;

	o->algo  = prf_algo;
	o->prf   = prf,
	o->salt  = salt;
	o->len   = salt_len;
	o->count = count;
	return o;
no_key:
	free (o);
no_object:
	return NULL;
}

void pbkdf2_free (struct pbkdf2 *o)
{
	free (o);
}

void pbkdf2 (struct pbkdf2 *o, void *out, size_t len)
{
	u8 *p;
	size_t i;
	const size_t hs = o->algo->get (o->prf, CRYPTO_HASH_SIZE);
	u8 hash[hs];

	for (p = out, i = 1; len > hs; p += hs, len -= hs, ++i)
		F (o, o->count, i, p);

	F (o, o->count, i, hash);
	memcpy (p, hash, len);
}
