#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <crypto-core.h>

#include <hash/md5.h>
#include <hash/sha1.h>
#include <hash/stribog.h>

#include <cipher/kuznechik.h>
#include <cipher/magma.h>

#include <mac/hmac.h>
#include <mac/cmac.h>

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
	fprintf (stderr, "usage:\n\tcipher-test <algorithm> ["
				"key <key> | "
				"(encrypt | decrypt) <block> "
				"] ...\n");

	exit (1);
}

static const struct crypto_core *find_core (const char *name)
{
	const struct crypto_core *core =
		strcmp (name, "md5")       == 0 ? &md5_core :
		strcmp (name, "sha1")      == 0 ? &sha1_core :
		strcmp (name, "stribog")   == 0 ? &stribog_core :
		strcmp (name, "kuznechik") == 0 ? &kuznechik_core :
		strcmp (name, "magma")     == 0 ? &magma_core :
		strcmp (name, "hmac")      == 0 ? &hmac_core :
		strcmp (name, "cmac")      == 0 ? &cmac_core :
		NULL;

	return core;
}

static void set_algo (const struct crypto_core *core, void *o,
		      const char *name)
{
	const struct crypto_core *algo;

	if ((algo = find_core (name)) == NULL)
		error ("unknown algorithm", 0);

	if ((errno = -core->set (o, CRYPTO_ALGO, algo)) != 0)
		error ("set algo", 1);
}

static void set_key (const struct crypto_core *core, void *o, char *key)
{
	size_t ks;

	errno = 0;
	ks = hex2blob (key);

	if ((ks == 0 && errno != 0) ||
	    (errno = -core->set (o, CRYPTO_KEY, key, ks)) != 0)
		error ("set key", 1);
}

static void *get_block (const struct crypto_core *core, void *o, void *arg)
{
	const size_t bs = core->get (o, CRYPTO_BLOCK_SIZE);

	if (arg == NULL)
		error ("block required", 0);

	if (hex2blob (arg) != bs)
		error ("wrong block size", 0);

	return arg;
}

static void hash_blob (const struct crypto_core *core, void *o, char *data)
{
	const size_t hs = core->get (o, CRYPTO_HASH_SIZE);
	char hash[hs];
	size_t len;

	if (data == NULL)
		error ("data required", 0);

	len = hex2blob (data);
	hash_core_process (core, o, data, len, hash);
	show (hash, hs);
}

static void hash (const struct crypto_core *core, void *o, char *data)
{
	const size_t hs = core->get (o, CRYPTO_HASH_SIZE);
	char hash[hs];

	if (data == NULL)
		error ("data required", 0);

	hash_core_process (core, o, data, strlen (data), hash);
	show (hash, hs);
}

static void encrypt (const struct crypto_core *core, void *o, char *block)
{
	const size_t bs = core->get (o, CRYPTO_BLOCK_SIZE);

	block = get_block (core, o, block);
	core->encrypt (o, block, block);
	show (block, bs);
}

static void decrypt (const struct crypto_core *core, void *o, char *block)
{
	const size_t bs = core->get (o, CRYPTO_BLOCK_SIZE);

	block = get_block (core, o, block);
	core->decrypt (o, block, block);
	show (block, bs);
}

int main (int argc, char *argv[])
{
	const struct crypto_core *core;
	void *o;
	void *op;

	if (argc < 2)
		usage ();

	if ((core = find_core (argv[1])) == NULL)
		error ("cannot find cipher", 0);

	if ((o = core->alloc ()) == NULL)
		error ("cannot initialize algorithm", 1);

	for (argv += 2; (op = argv[0]) != NULL; ++argv) {
		if (strcmp (op, "algo") == 0) {
			++argv;
			set_algo (core, o, argv[0]);
			continue;
		}

		if (strcmp (op, "key") == 0) {
			++argv;
			set_key (core, o, argv[0]);
			continue;
		}

		if (strcmp (op, "hash") == 0) {
			++argv;
			hash (core, o, argv[0]);
			continue;
		}

		if (strcmp (op, "hash-blob") == 0) {
			++argv;
			hash_blob (core, o, argv[0]);
			continue;
		}

		if (strcmp (op, "encrypt") == 0) {
			++argv;
			encrypt (core, o, argv[0]);
			continue;
		}

		if (strcmp (op, "decrypt") == 0) {
			++argv;
			decrypt (core, o, argv[0]);
			continue;
		}

		error ("wrong operation", 0);
	}

	core->free (o);
	return 0;
}
