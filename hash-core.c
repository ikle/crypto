#include <stdlib.h>
#include <string.h>

#include "crypto-core.h"

struct hash {
	const struct crypto_core *core;
	void *state;
};

struct hash *hash_alloc (const struct crypto_core *core)
{
	struct hash *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		goto no_object;

	if ((o->state = core->alloc ()) == NULL)
		goto no_state;

	o->core = core;
	return o;
no_state:
	free (o);
no_object:
	return NULL;
}

void hash_free (struct hash *o)
{
	if (o == NULL)
		return;

	o->core->free (o->state);
	free (o);
}

size_t hash_get_block_size (const struct hash *h)
{
	return h->core->get (h->state, CRYPTO_BLOCK_SIZE);
}

size_t hash_get_hash_size (const struct hash *h)
{
	return h->core->get (h->state, CRYPTO_HASH_SIZE);
}

int hash_set_algo (struct hash *h, const struct crypto_core *core)
{
	return h->core->set (h->state, CRYPTO_ALGO, core);
}

int hash_set_key  (struct hash *h, const void *key, size_t len)
{
	return h->core->set (h->state, CRYPTO_KEY, key, len);
}

/*
 * 1. Process integer number of input blocks.
 * 2. If out != NULL then process last partial block and write final hash
 *    value to out.
 *
 * This function never stores input plain text data in context.
 *
 * Returns number of bytes processed.
 */
size_t hash_core_process (const struct crypto_core *core, void *state,
			  const void *in, size_t len, void *out)
{
	const size_t bs = core->get (state, CRYPTO_BLOCK_SIZE);
	const char *data = in;
	size_t tail;

	for (tail = len; tail > bs; data += bs, tail -= bs)
		core->transform (state, data);

	if (out == NULL)
		return len - tail;

	core->final (state, data, tail, out);
	return len;
}

size_t hash_data (struct hash *o, const void *in, size_t len, void *out)
{
	return hash_core_process (o->core, o->state, in, len, out);
}
