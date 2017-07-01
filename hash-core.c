#include <stdlib.h>
#include <string.h>

#include "core.h"
#include "hash-core.h"

struct hash {
	const struct hash_core *core;
	void *state;
	size_t avail;
	char block[];
};

struct hash *hash_alloc (const struct hash_core *core)
{
	struct hash *o;

	if ((o = malloc (sizeof (*o) + core->block_size)) == NULL)
		goto no_object;

	if ((o->state = core->alloc ()) == NULL)
		goto no_state;

	o->core = core;
	o->avail = 0;
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

int hash_update (struct hash *o, const void *in, size_t len)
{
	size_t need = o->core->block_size - o->avail;
	const char *data = in;

	if (len < need) {
		memcpy (o->block + o->avail, data, len);
		o->avail += len;
		return 0;
	}

	memcpy (o->block + o->avail, in, need);
	o->core->transform (o->state, o->block), data += need, len -= need;

	for (need = o->core->block_size; len >= need; data += need, len -= need) {
		memcpy (o->block, data, need);
		o->core->transform (o->state, o->block);
	}

	memcpy (o->block, data, len);
	o->avail = len;
	return 0;
}

int hash_final (struct hash *o, void *out)
{
	o->core->final (o->state, o->block, o->avail, out);
	memset (o->block, 0, o->core->block_size);
	barrier_data (o->block);
	return 0;
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
