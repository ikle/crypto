/*
 * Crypto API
 *
 * Copyright (c) 2018 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <crypto/api.h>
#include <crypto/core.h>

#include <hash/md5.h>
#include <hash/sha1.h>
#include <hash/stribog.h>

#include <cipher/kuznechik.h>
#include <cipher/magma.h>

#include <mac/hmac.h>
#include <mac/cmac.h>

#include <mop/cbc.h>
#include <mop/cfb.h>
#include <mop/ctr.h>
#include <mop/ofb.h>

#include <kdf/pbkdf1.h>
#include <kdf/pbkdf2.h>

struct core_map {
	const char *algo;
	const struct crypto_core *core;
};

static const struct core_map map[] = {
	{"md5",		&md5_core	},
	{"sha1",	&sha1_core	},
	{"stribog",	&stribog_core	},

	{"kuznechik",	&kuznechik_core	},
	{"magma",	&magma_core	},
	{"gost89",	&gost89_core	},

	{"hmac",	&hmac_core	},
	{"cmac",	&cmac_core	},

	{"cbc",		&cbc_core	},
	{"cfb",		&cfb_core	},
	{"ctr",		&ctr_core	},
	{"ofb",		&ofb_core	},

	{"pbkdf1",	&pbkdf1_core	},
	{"pbkdf2",	&pbkdf2_core	},
	{},
};

static const struct crypto_core *find (const char *algo)
{
	const struct core_map *p;

	for (p = map; p->algo != NULL; ++p)
		if (strcmp (p->algo, algo) == 0)
			return p->core;

	errno = ENOENT;
	return NULL;
}

struct crypto {
	const struct crypto_core *core;
	void *block;
	size_t avail;
	/* core-specific state follows */
};

struct crypto *crypto_alloc (const char *algo)
{
	const struct crypto_core *core;
	struct crypto *o;

	if (algo == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if ((core = find (algo)) == NULL ||
	    (o = core->alloc ()) == NULL)
		return NULL;

	o->core  = core;
	o->block = NULL;
	o->avail = 0;
	return o;
}

void crypto_free (struct crypto *o)
{
	if (o == NULL)
		return;

	free (o->block);
	o->core->free (o);
}

int crypto_get (const struct crypto *o, int type, ...)
{
	va_list ap;
	int ret;

	va_start (ap, type);
	ret = o->core->get (o, type, ap);
	va_end (ap);
	return ret;
}

int crypto_set (struct crypto *o, int type, ...)
{
	va_list ap;
	int ret;

	va_start (ap, type);
	ret = o->core->set (o, type, ap);
	va_end (ap);
	return ret;
}

void crypto_reset (struct crypto *o)
{
	errno = -crypto_set (o, CRYPTO_RESET);
}

/* returns requested size on success, zero overwise */

size_t crypto_get_block_size (struct crypto *o)
{
	int ret = crypto_get (o, CRYPTO_BLOCK_SIZE);

	if (ret == 0)
		ret = -ENOSYS;

	if (ret < 0) {
		errno = -ret;
		return 0;
	}

	return ret;
}

size_t crypto_get_output_size (struct crypto *o)
{
	int ret = crypto_get (o, CRYPTO_OUTPUT_SIZE);

	if (ret == 0)
		ret = -ENOSYS;

	if (ret < 0) {
		errno = -ret;
		return 0;
	}

	return ret;
}

/* returns non-zero on success, zero overwise */

int crypto_set_algo (struct crypto *o, struct crypto *algo)
{
	errno = -crypto_set (o, CRYPTO_ALGO, algo);

	if (errno == ENOSYS)
		crypto_free (algo);

	return errno == 0;
}

int crypto_set_paramset (struct crypto *o, const void *set, size_t len)
{
	errno = -crypto_set (o, CRYPTO_PARAMSET, set, len);
	return errno == 0;
}

int crypto_set_key (struct crypto *o, const void *key, size_t len)
{
	errno = -crypto_set (o, CRYPTO_KEY, key, len);
	return errno == 0;
}

int crypto_set_iv (struct crypto *o, const void *iv, size_t len)
{
	errno = -crypto_set (o, CRYPTO_IV, iv, len);
	return errno == 0;
}

int crypto_set_salt (struct crypto *o, const void *salt, size_t len)
{
	errno = -crypto_set (o, CRYPTO_SALT, salt, len);
	return errno == 0;
}

int crypto_set_count (struct crypto *o, size_t count)
{
	errno = -crypto_set (o, CRYPTO_COUNT, count);
	return errno == 0;
}

/* process one block of data */

void crypto_encrypt (struct crypto *o, const void *in, void *out)
{
	if (o->core->encrypt != NULL)
		o->core->encrypt (o, in ,out);

	errno = -ENOSYS;
}

void crypto_decrypt (struct crypto *o, const void *in, void *out)
{
	if (o->core->decrypt != NULL)
		o->core->decrypt (o, in ,out);

	errno = -ENOSYS;
}

/* update/fetch helpers */

#include <crypto/types.h>

static int crypto_hash_update (struct crypto *o, const void *in, size_t len)
{
	const size_t bs = crypto_get_block_size (o);
	const char *data = in;
	size_t tail;

	if (bs == 0 || o->avail > bs)
		return -EINVAL;

	if (o->block == NULL &&
	    (o->block = malloc (bs)) == NULL)
		return -ENOMEM;

	if (o->avail == bs && len == 0)
		goto out;  /* it is a last block, delay processing */

	if (o->avail > 0) {
		tail = bs - o->avail;

		if (len < tail)
			goto out;

		memcpy (o->block + o->avail, data, tail);
		data += tail, len -= tail;
		o->core->transform (o, o->block);
		o->avail = 0;
	}

	for (; len > bs; data += bs, len -= bs)
		o->core->transform (o, data);

out:
	memcpy (o->block + o->avail, data, len);
	o->avail += len;
	return 0;
}

static int crypto_hash_fetch (struct crypto *o, void *out, size_t len)
{
	const size_t hs = crypto_get_output_size (o);

	if (hs == 0 || len > hs)
		return -EINVAL;

	u8 hash[hs];

	o->core->final (o, o->block, o->avail, hash);
	o->avail = 0;

	memcpy (out, hash, len);
	return 0;
}
/* update object with data, and fetch result */

int crypto_update (struct crypto *o, const void *in, size_t len)
{
	if (o->core->update != NULL) {
		errno = -o->core->update (o, in, len);
		return errno == 0;
	}

	if (o->core->transform != NULL) {
		errno = -crypto_hash_update (o, in, len);
		return 1;
	}

	errno = -ENOSYS;
	return 0;
}

int crypto_fetch (struct crypto *o, void *out, size_t len)
{
	if (o->core->fetch != NULL) {
		errno = -o->core->fetch (o, out, len);
		return errno == 0;
	}

	if (o->core->final != NULL) {
		errno = -crypto_hash_fetch (o, out, len);
		return errno == 0;
	}

	errno = -ENOSYS;
	return 0;
}
