#include <stdio.h>
#include <string.h>

#include "hash-core.h"

#include "md5-core.h"
#include "sha1-core.h"

static int error (const char *message, int system)
{
	fprintf (stderr, "hash-test: ");

	if (system)
		perror (message);
	else
		fprintf (stderr, "%s\n", message);

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
	const struct hash_core *core;
	struct hash *h;
	char buf[BUFSIZ];
	size_t len;

	if (argc < 2 || argc > 3) {
		fprintf (stderr, "usage:\n\thash-test <algorithm> [data]\n");
		return 1;
	}

	if (strcmp (argv[1], "md5") == 0)
		core = &md5_core;
	else if (strcmp (argv[1], "sha1") == 0)
		core = &sha1_core;
	else
		return error ("unknown algorithm", 0);

	if (sizeof (buf) < core->hash_size)
		return error ("hash size too large", 0);

	if ((h = hash_alloc (core)) == NULL)
		return error ("cannot initialize algorithm", 1);

	if (argc == 3)
		hash_update (h, argv[2], strlen (argv[2]));
	else
		while ((len = fread (buf, 1, sizeof (buf), stdin)) > 0)
			hash_update (h, buf, len);

	hash_final (h, buf);
	hash_free (h);

	show (buf, core->hash_size);
	return 0;
}
