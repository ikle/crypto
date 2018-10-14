/*
 * Magma Cipher
 *
 * Copyright (c) 2011-2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * Standard: GOST 28147-89, GOST R 34.12-2015
 * Standard: RFC 4357
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CRYPTO_MAGMA_SB_H
#define CRYPTO_MAGMA_SB_H  1

#include <crypto/types.h>

struct gost89_sb {
	u8 pi[8][16];
};

/* GOST R 34.12-2015, 5.1.1 Nonlinear Bijective Transformation */

extern const struct gost89_sb magma_sb;

/* RFC 4357, 11.1 Encryption Algorithm Parameters */

extern const struct gost89_sb gost89_sb_test;
extern const struct gost89_sb gost89_sb_cpro_a;
extern const struct gost89_sb gost89_sb_cpro_b;
extern const struct gost89_sb gost89_sb_cpro_c;
extern const struct gost89_sb gost89_sb_cpro_d;

/* RFC 4357, 11.2 Digest Algorithm Parameters */

extern const struct gost89_sb gosthash_sb_test;
extern const struct gost89_sb gosthash_sb_cpro;

#endif  /* CRYPTO_MAGMA_SB_H */
