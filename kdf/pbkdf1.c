/*
 * PBKDF1: The Password-Based Key Deriavation Function #1
 *
 * Copyright (c) 2018 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * Standard: PKCS #5 v1.5
 * Standard: RFC 2898 (PKCS #5 v2.0), RFC 8018 (PKCS #5 v2.1)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <string.h>

#include <crypto/types.h>

#include <kdf/pbkdf1.h>

int pbkdf1 (struct hash *prf, const void *key, size_t key_len,
	    const void *salt, size_t salt_len,
	    unsigned count, void *out, size_t len)
{
	const size_t hs = hash_get_hash_size  (prf);
	const size_t bs = hash_get_block_size (prf);
	size_t n;
	u8 block[bs];
	u8 hash[hs];

	/* 1. Check output length */

	if (len > hs)
		return -EINVAL;

	if (count == 0)
		count = 1000;

	/* 2. T_1 = Hash (P | S) */

	n = hash_data (prf, key, key_len, NULL);
	key_len -= n;

	memcpy (block, key + n, key_len);
	n = bs - key_len;

	if (salt_len < n) {
		memcpy (block + key_len, salt, salt_len);
		hash_data (prf, block, key_len + salt_len, hash);
	}
	else {
		memcpy (block + key_len, salt, n);
		hash_data (prf, block, bs, NULL);
		hash_data (prf, salt + n, salt_len - n, hash);
	}

	/* 3. T_i = Hash (T_{i-1}) */
	for (--count; count > 0; --count)
		hash_data (prf, hash, hs, hash);

	memcpy (out, hash, len);
	return 0;
}
