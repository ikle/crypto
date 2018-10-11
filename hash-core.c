#include <stdlib.h>
#include <string.h>

#include <crypto/hash.h>

/*
 * If out != NULL then process last possiby partial block and write final
 * hash value to out.
 *
 * Returns number of bytes processed or zero on error.
 */
size_t hash_data (struct hash *o, const void *in, size_t len, void *out)
{
	const size_t bs = hash_get_block_size (o);
	const char *data = in;
	size_t tail;
	const size_t total = len;

	if (o->block == NULL &&
	    (o->block = malloc (bs)) == NULL)
		return 0;

	if (o->avail >= bs)
		return 0;

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

	if (out != NULL) {
		o->core->final (o, o->block, o->avail, out);
		o->avail = 0;
	}

	return total;
}
