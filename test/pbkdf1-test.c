#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hash/sha1.h>
#include <kdf/pbkdf1.h>

static void error (const char *message, int system)
{
	fprintf (stderr, "pbkdf1-test: ");

	if (system)
		perror (message);
	else
		fprintf (stderr, "%s\n", message);

	exit (1);
}

/* convert string or hex-string to blob in-place */
static int read_blob (char *s, size_t *len)
{
	size_t i;
	int n;
	unsigned x;

	if (s[0] == ':') {
		*len = strlen (s) - 1;
		memmove (s, s + 1, *len);
		return 1;
	}

	if (s[0] != 'x') {
		errno = EINVAL;
		return 0;
	}

	for (i = 0; ; ++i) {
		if ((n = sscanf (s + 1 + (i * 2), "%2x", &x)) == 1)
			s[i] = x;
		else if (n == EOF)
			break;
		else {
			errno = EINVAL;
			return 0;
		}
	}

	*len = i;
	return 1;
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
	struct hash *prf;
	struct kdf  *kdf;

	if (argc != 5)
		error ("usage:\n\tpbkdf1-test <password> <salt-blob> <count>"
		       " <out-length>\n", 0);

	if ((prf = hash_alloc (&sha1_core)) == NULL)
		error ("cannot allocate SHA1 context", 1);

	if ((kdf = kdf_alloc (&pbkdf1_core)) == NULL)
		error ("cannot allocate PBKDF1 context", 1);

	const char *key  = argv[1];
	char *salt = argv[2];
	size_t salt_len;
	const unsigned count = atoi (argv[3]);
	const unsigned len   = atoi (argv[4]);
	char buf[len];

	if (!read_blob (salt, &salt_len))
		error ("cannot parse salt blob", 1);

	if (!kdf_set_prf (kdf, prf)		  ||
	    !kdf_set_key (kdf, key, strlen (key)) ||
	    !kdf_set_salt (kdf, salt, salt_len)	  ||
	    !kdf_set_count (kdf, count))
		error ("cannot initialize KDF", 1);

	if (!kdf_compute (kdf, buf, len))
		error ("cannot derive key", 1);

	show (buf, len);

	hash_free (prf);
	return 0;
}
