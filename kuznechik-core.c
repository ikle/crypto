/*
 * Kuznechik Cipher Algorithm
 *
 * Copyright (c) 2016-2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * Standard: GOST R 34.12-2015
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <string.h>

#include "kuznechik-core.h"
#include "kuznechik-defs.h"

struct state {
	u128 k[10];	/* round keys */
	u128 kd[10];	/* decryption keys */
};

static void S (u128 *x)
{
	int i;

	for (i = 0; i < 16; ++i)
		x->b[i] = sbox[x->b[i]];
}

static void S_inv (u128 *x)
{
	int i;

	for (i = 0; i < 16; ++i)
		x->b[i] = sbox_inv[x->b[i]];
}

/* poly multiplication mod p(x) = x^8 + x^7 + x^6 + x + 1 */
static u8 mul_gf256 (u8 x, u8 y)
{
	u8 z;

	for (z = 0; y != 0; y >>= 1) {
		if (y & 1)
			z ^= x;

		x = (x << 1) ^ (x & 0x80 ? 0xc3 : 0);
	}

	return z;
}

static void L (u128 *w)
{
	int i, j;
	u8 x;

	/* 16 rounds */
	for (j = 0; j < 16; j++) {
		/* An LFSR with 16 elements from GF(2^8) */
		x = w->b[15];  /* since lvec[15] = 1 */

		for (i = 14; i >= 0; i--) {
			w->b[i + 1] = w->b[i];
			x ^= mul_gf256 (w->b[i], lvec[i]);
		}

		w->b[0] = x;
	}
}

static void L_inv (u128 *w)
{
	int i, j;
	u8 x;

	/* 16 rounds */
	for (j = 0; j < 16; j++) {
		x = w->b[0];

		for (i = 0; i < 15; i++) {
			w->b[i] = w->b[i + 1];
			x ^= mul_gf256 (w->b[i], lvec[i]);
		}

		w->b[15] = x;
	}
}

static void xor128 (const u128 *a, const u128 *b, u128 *out)
{
#ifdef __SSE__
	out->o = a->o ^ b->o;
#else
	out->q[0] = a->q[0] ^ b->q[0];
	out->q[1] = a->q[1] ^ b->q[1];
#endif
}

static u128 table_SL[16][256];
static u128 table_L_inv[16][256];
static u128 table_S_inv_L_inv[16][256];

static void init_tables (void)
{
	static int done;
	int i, j;
	const u128 N0 = {};
	u128 x;

	if (done)
		return;

	for (i = 0; i < 16; i++)
		for (j = 0; j < 256; j++) {
			x = N0;
			x.b[i] = sbox[j];
			L (&x);
			table_SL[i][j] = x;

			x = N0;
			x.b[i] = j;
			L_inv (&x);
			table_L_inv[i][j] = x;

			x = N0;
			x.b[i] = sbox_inv[j];
			L_inv (&x);
			table_S_inv_L_inv[i][j] = x;
		}

	done = 1;
}

static int set_key (struct state *c, const void *key, size_t len)
{
	int i;
	const u128 N0 = {};
	u128 C, x, y, z;

	init_tables ();

	if (len != 32)
		return -EINVAL;

	memcpy (&x, key, 16);
	memcpy (&y, key + 16, 16);

	c->k[0] = x;
	c->k[1] = y;

	for (i = 1; i <= 32; i++) {
		C = N0;
		C.b[15] = i;  /* Big Endian number */
		L (&C);
		xor128 (&x, &C, &z);

		S (&z);
		L (&z);
		xor128 (&z, &y, &z);

		y = x;
		x = z;

		if ((i & 7) == 0) {
			c->k[(i >> 2)]     = x;
			c->k[(i >> 2) + 1] = y;
		}
	}

	/* set decryption keys */
	c->kd[0] = c->k[0];

	for (i = 1; i < 10; i++) {
		c->kd[i] = c->k[i];
		L_inv (&c->kd[i]);
	}

	return 0;
}

#ifdef NO_TABLES
static void encrypt (void *state, const void *in, void *out)
{
	struct state *c = state;
	int i;
	u128 x;

	memcpy (&x, in, sizeof (x));

	xor128 (&x, &c->k[0], &x);

	for (i = 1; i <= 9; i++) {
		S (&x);
		L (&x);
		xor128 (&x, &c->k[i], &x);
	}

	memcpy (out, &x, sizeof (x));
}

static void decrypt (void *state, const void *in, void *out)
{
	struct state *c = state;
	int i;
	u128 x;

	memcpy (&x, in, sizeof (x));

	xor128 (&x, &c->k[9], &x);

	for (i = 8; i >= 0; --i) {
		L_inv (&x);
		S_inv (&x);
		xor128 (&x, &c->k[i], &x);
	}

	memcpy (out, &x, sizeof (x));
}
#else
/* WARNING: in and out should not overlap */
static void table_it (u128 table[16][256], const u128 *in, u128 *out)
{
	int i;

	*out = table[0][in->b[0]];

	for (i = 1; i < 16; ++i)
		xor128 (out, &table[i][in->b[i]], out);
}

static void encrypt (void *state, const void *in, void *out)
{
	struct state *c = state;
	int i;
	u128 x, y;

	memcpy (&x, in, sizeof (x));

	xor128 (&x, &c->k[0], &x);

	for (i = 1; i <= 9; i++) {
		table_it (table_SL, &x, &y);
		xor128 (&y, &c->k[i], &x);
	}

	memcpy (out, &x, sizeof (x));
}

static void decrypt (void *state, const void *in, void *out)
{
	struct state *c = state;
	int i;
	u128 x, y;

	memcpy (&x, in, sizeof (x));

	table_it (table_L_inv, &x, &y);
	xor128 (&y, &c->kd[9], &x);

	for (i = 8; i > 0; --i) {
		table_it (table_S_inv_L_inv, &x, &y);
		xor128 (&y, &c->kd[i], &x);
	}

	S_inv (&x);
	xor128 (&x, &c->kd[0], &x);

	memcpy (out, &x, sizeof (x));
}
#endif  /* !NO_TABLES */

static void *alloc (void)
{
	struct state *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	return o;
}

static int get (const void *state, int type, ...)
{
	switch (type) {
	case CRYPTO_BLOCK_SIZE:	return 16;
	}

	return -ENOSYS;
}

static int set (void *state, int type, ...)
{
	va_list ap;
	int status;

	va_start (ap, type);

	switch (type) {
	case CRYPTO_KEY: {
			const void *key;
			size_t len;

			key = va_arg (ap, const void *);
			len = va_arg (ap, size_t);
			status = set_key (state, key, len);
			break;
		}
	default:
		status = -ENOSYS;
	}

	va_end (ap);
	return status;
}

const struct crypto_core kuznechik_core = {
	.alloc		= alloc,
	.free		= free,

	.get		= get,
	.set		= set,

	.encrypt	= encrypt,
	.decrypt	= decrypt,
};
