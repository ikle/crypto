#include <crypto-core.h>

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
