#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hash/sha1.h>
#include <kdf/pbkdf1.h>

static void error (const char *message, int system)
{
	fprintf (stderr, "cipher-test: ");

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
		error ("usage:\n\tpbkdf1-test <password> <salt-blob> <count>"
		       " <out-length>\n", 0);

	if ((prf = hash_alloc (&sha1_core)) == NULL)
		error ("cannot allocate SHA1 context", 1);

	const char *key  = argv[1];
	char *salt = argv[2];
	size_t salt_len;
	const unsigned count = atoi (argv[3]);
	const unsigned len   = atoi (argv[4]);
	char buf[len];

	if (!read_blob (salt, &salt_len))
		error ("cannot parse salt blob", 1);

	errno = -kdf (&pbkdf1_core,
		      prf, key, strlen (key), salt, salt_len,
		      count, buf, len);
	if (errno != 0)
		error ("cannot derive key", 1);

	show (buf, len);

	hash_free (prf);
	return 0;
}
