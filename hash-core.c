#include <stdlib.h>
#include <string.h>

#include "core.h"
#include "hash-core.h"

struct hash {
	const struct hash_core *core;
	void *state;
};

struct hash *hash_alloc (const struct hash_core *core)
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

	if (o->core->free != NULL)
		o->core->free (o->state);
	else
		free (o->state);

	free (o);
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
size_t hash_data (struct hash *o, const void *in, size_t len, void *out)
{
	const size_t need = o->core->block_size;
	const char *data = in;
	size_t total;

	for (total = 0; len >= need; data += need, len -= need, total += need)
		o->core->transform (o->state, data);

	if (out != NULL) {
		o->core->final (o->state, data, len, out);
		total += len;
	}

	return total;
}
