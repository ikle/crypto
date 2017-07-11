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
	struct hash *prf;
	const u8 *salt;
	size_t len;			/* salt length */
	unsigned count;
};

static void F (struct pbkdf2 *o, unsigned count, size_t index, void *out)
{
	size_t eaten, left;
	const size_t bs = hash_get_block_size (o->prf);
	u8 buf[bs + 4];

	eaten = hash_data (o->prf, o->salt, o->len, NULL);
	left = o->len - eaten;

	memcpy (buf, o->salt + eaten, left);
	write_be32 (index, buf + left);

	const size_t hs = hash_get_hash_size (o->prf);
	u8 hash[hs];

	hash_data (o->prf, buf, left + 4, hash);
	memcpy (out, hash, hs);

	for (; count > 1; --count) {
		hash_data (o->prf, hash, hs, hash);
		xor_block (out, hash, out, hs);
	}
}

struct pbkdf2 *pbkdf2_alloc (struct hash *prf,
			     const void *key,  size_t key_len,
			     const void *salt, size_t salt_len,
			     unsigned count)
{
	struct pbkdf2 *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		goto no_object;

	if ((errno = -hash_set_key (prf, key, key_len)) != 0)
		goto no_key;

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
	const size_t hs = hash_get_hash_size (o->prf);
	u8 hash[hs];

	for (p = out, i = 1; len > hs; p += hs, len -= hs, ++i)
		F (o, o->count, i, p);

	F (o, o->count, i, hash);
	memcpy (p, hash, len);
}
