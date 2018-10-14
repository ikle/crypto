#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hash/sha1.h>
#include <kdf/pbkdf2.h>
#include <mac/hmac.h>

static void error (const char *message, int system)
{
	fprintf (stderr, "pbkdf2-test: ");

	if (system)
		perror (message);
	else
		fprintf (stderr, "%s\n", message);

	exit (1);
}

static void show (const void *data, size_t len)
{
	const unsigned char *p = data;

	for (; len > 0; ++p, --len)
		printf ("%02x", *p);

	printf ("\n");
}

int main (int argc, char *argv[])
{
	struct hash *sha1, *prf;

	if (argc != 5)
		error ("usage:\n\tpbkdf2-test <password> <salt> <count>"
		       " <out-length>\n", 0);

	if ((sha1 = hash_alloc (&sha1_core)) == NULL)
		error ("cannot allocate SHA1 context", 1);

	if ((prf = hash_alloc (&hmac_core)) == NULL)
		error ("cannot allocate HMAC context", 1);

	if ((errno = -hash_set_algo (prf, sha1)) != 0)
		error ("cannot initialize HMAC-SHA1", 1);

	const char *key  = argv[1];
	const char *salt = argv[2];
	const unsigned count = atoi (argv[3]);
	const unsigned len = atoi (argv[4]);
	char buf[len];

	errno = -pbkdf2_core.compute (prf, key, strlen (key),
				      salt, strlen (salt), count, buf, len);
	if (errno != 0)
		error ("cannot derive key", 1);

	show (buf, len);

	hash_free (prf);
	return 0;
}
