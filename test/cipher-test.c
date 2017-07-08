#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <crypto-core.h>

#include <cipher/kuznechik.h>
#include <cipher/magma.h>

static void error (const char *message, int system)
{
	fprintf (stderr, "cipher-test: ");

	if (system)
		perror (message);
	else
		fprintf (stderr, "%s\n", message);

	exit (1);
}

static void show (const unsigned char *data, size_t len)
{
	for (; len > 0; ++data, --len)
		printf ("%02x", *data);

	printf ("\n");
}

/* convert string to blob in-place */
static size_t hex2blob (char *s)
{
	size_t i;
	int n;
	unsigned x;

	for (i = 0; ; ++i) {
		if ((n = sscanf (s + (i * 2), "%2x", &x)) == 1)
			s[i] = x;
		else if (n == EOF)
			break;
		else {
			errno = EINVAL;
			return 0;
		}
	}

	return i;
}

static void usage (void)
{
	fprintf (stderr, "usage:\n\tcipher-test <algorithm> <key> "
				"(encode | decode) <block>\n");

	exit (1);
}

static const struct crypto_core *find_core (const char *name)
{
	const struct crypto_core *core =
		strcmp (name, "kuznechik") == 0 ? &kuznechik_core :
		strcmp (name, "magma")     == 0 ? &magma_core :
		NULL;

	return core;
}

int main (int argc, char *argv[])
{
	const struct crypto_core *core;
	void *o;
	void *key, *op, *block;
	size_t ks, bs;  /* input key and block sizes */

	if (argc != 5)
		usage ();

	if ((core = find_core (argv[1])) == NULL)
		error ("cannot find cipher", 0);

	if ((o = core->alloc ()) == NULL)
		error ("cannot initialize algorithm", 1);

	if ((ks = hex2blob (key = argv[2])) == 0 ||
	    (errno = -core->set (o, CRYPTO_KEY, key, ks)) != 0)
		error ("key", 1);

	if ((bs = hex2blob (block = argv[4])) == 0)
		error ("block", 1);

	if (core->get (o, CRYPTO_BLOCK_SIZE) != bs)
		error ("wrong block length", 0);

	if (strcmp (op = argv[3], "encode") == 0)
		core->encrypt (o, block, block);
	else if (strcmp (op, "decode") == 0)
		core->decrypt (o, block, block);
	else
		error ("wrong operation", 0);

	show (block, bs);
	core->free (o);
	return 0;
}
