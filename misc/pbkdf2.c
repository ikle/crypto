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

#include <string.h>

#include <crypto/types.h>
#include <crypto/endian.h>
#include <crypto/utils.h>

#include <crypto/pbkdf2.h>

static void F (struct hash *prf, const u8 *salt, size_t salt_len,
	       unsigned count, size_t index, void *out)
{
	size_t eaten, left;
	const size_t bs = hash_get_block_size (prf);
	u8 buf[bs + 4];

	eaten = hash_data (prf, salt, salt_len, NULL);
	left = salt_len - eaten;

	memcpy (buf, salt + eaten, left);
	write_be32 (index, buf + left);

	const size_t hs = hash_get_hash_size (prf);
	u8 hash[hs];

	hash_data (prf, buf, left + 4, hash);
	memcpy (out, hash, hs);

	for (; count > 1; --count) {
		hash_data (prf, hash, hs, hash);
		xor_block (out, hash, out, hs);
	}
}

int pbkdf2 (struct hash *prf, const void *salt, size_t salt_len,
	    unsigned count, void *out, size_t len)
{
	u8 *p;
	size_t i;
	const size_t hs = hash_get_hash_size (prf);
	u8 hash[hs];

	for (p = out, i = 1; len > hs; p += hs, len -= hs, ++i)
		F (prf, salt, salt_len, count, i, p);

	F (prf, salt, salt_len, count, i, hash);
	memcpy (p, hash, len);

	return 0;
}
