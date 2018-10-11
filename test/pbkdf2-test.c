#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hash/sha1.h>
#include <kdf/pbkdf2.h>
#include <mac/hmac.h>

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

int main (int argc, char *argv[])
{
	struct hash *prf;

	if (argc != 5)
		error ("usage:\n\tpbkdf2-test <password> <salt> <count>"
		       " <out-length>\n", 0);

	if ((prf = hash_alloc (&hmac_core)) == NULL)
		error ("cannot allocate HMAC context", 1);

	if ((errno = -hash_set_algo (prf, &sha1_core)) != 0)
		error ("cannot initialize HMAC-SHA1", 1);

	const char *key  = argv[1];
	const char *salt = argv[2];
	const unsigned count = atoi (argv[3]);
	const unsigned len = atoi (argv[4]);
	char buf[len];

	errno = -kdf (&pbkdf2_core,
		      prf, key, strlen (key), salt, strlen (salt),
		      count, buf, len);
	if (errno != 0)
		error ("cannot derive key", 1);

	show (buf, len);

	hash_free (prf);
	return 0;
}
