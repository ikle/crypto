#include <crypto/hash.h>

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
	const size_t bs = hash_get_block_size (o);
	const char *data = in;
	size_t tail;

	for (tail = len; tail > bs; data += bs, tail -= bs)
		o->core->transform (o, data);

	if (out == NULL)
		return len - tail;

	o->core->final (o, data, tail, out);
	return len;
}
