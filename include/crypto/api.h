/*
 * Crypto API
 *
 * Copyright (c) 2018 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CRYPTO_API_H
#define CRYPTO_API_H  1

#include <stddef.h>

struct crypto *crypto_alloc (const char *algo);
void crypto_free (struct crypto *o);

void crypto_reset (struct crypto *o);

/* returns requested size on success, zero overwise */
size_t crypto_get_block_size  (struct crypto *o);
size_t crypto_get_output_size (struct crypto *o);

/* returns non-zero on success, zero overwise */
int crypto_set_algo	(struct crypto *o, struct crypto *algo);
int crypto_set_paramset	(struct crypto *o, const void *set,  size_t len);
int crypto_set_key	(struct crypto *o, const void *key,  size_t len);
int crypto_set_iv	(struct crypto *o, const void *iv,   size_t len);
int crypto_set_salt	(struct crypto *o, const void *salt, size_t len);
int crypto_set_count	(struct crypto *o, size_t count);

/* process one block of data */
void crypto_encrypt (struct crypto *o, const void *in, void *out);
void crypto_decrypt (struct crypto *o, const void *in, void *out);

/* update object with data, and fetch result */
int crypto_update (struct crypto *o, const void *in, size_t len);
int crypto_fetch  (struct crypto *o, void *out, size_t len);

#endif  /* CRYPTO_API_H */
