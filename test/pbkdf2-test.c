#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hash/sha1.h>
#include <mac/hmac.h>
#include <crypto/pbkdf2.h>

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
	void *prf;
	struct pbkdf2 *o;

	if (argc != 5)
		error ("usage:\n\tpbkdf2-test <password> <salt> <count>"
		       " <out-length>\n", 0);

	if ((prf = hmac_core.alloc ()) == NULL)
		error ("cannot allocate HMAC context", 1);

	if ((errno = -hmac_core.set (prf, CRYPTO_ALGO, &sha1_core)) != 0)
		error ("cannot initialize HMAC-SHA1", 1);

	const char *key  = argv[1];
	const char *salt = argv[2];
	const unsigned count = atoi (argv[3]);

	if ((o = pbkdf2_alloc (&hmac_core, prf, key, strlen (key),
			       salt, strlen (salt), count)) == NULL)
		error ("cannot allocate PBKDF2 context", 1);

	const unsigned len = atoi (argv[4]);
	char buf[len];

	pbkdf2 (o, buf, len);
	show (buf, len);

	hmac_core.free (prf);
	pbkdf2_free (o);
	return 0;
}
