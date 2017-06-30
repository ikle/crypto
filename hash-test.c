#include <stdio.h>
#include <string.h>

#include "hash-core.h"

#include "md5-core.h"
#include "sha1-core.h"
#include "stribog-core.h"

static int error (const char *message, int system)
{
	fprintf (stderr, "hash-test: ");

	if (system)
		perror (message);
	else
		fprintf (stderr, "%s\n", message);

	return 1;
}

static int usage (void)
{
	fprintf (stderr, "usage:\n\thash-test <algorithm> [[-s] data]\n");

	return 1;
}

static void show (const unsigned char *data, size_t len)
{
	for (; len > 0; ++data, --len)
		printf ("%02x", *data);

	printf ("\n");
}

static const struct hash_core *find_core (const char *name)
{
	if (strcmp (name, "md5") == 0)
		return &md5_core;

	if (strcmp (name, "sha1") == 0)
		return &sha1_core;

	if (strcmp (name, "stribog") == 0)
		return &stribog_core;

	return NULL;
}

#include <sys/times.h>
#include <unistd.h>

#define COUNT	(1000000)

static double ticks_to_secs (double ticks)
{
	int count;

	if ((count = sysconf (_SC_CLK_TCK)) == -1)
		count = 100;

	return ticks / count;
}

static void test_speed (struct hash *h, const char *string, void *out)
{
	const size_t len = strlen (string);
	struct tms t0, t1;
	int i;
	double duration;

	times (&t0);

	for (i = 0; i < COUNT; ++i) {
		hash_update (h, string, len);
		hash_final (h, out);
	}

	times (&t1);
	duration = ticks_to_secs ((double) t1.tms_utime - t0.tms_utime);

	printf ("hash/s = %f\n", COUNT / duration);
}

#define get_arg()	(argc < 2 ? NULL : (--argc, ++argv, argv[0]))

int main (int argc, char *argv[])
{
	const char *arg;
	const struct hash_core *core;
	struct hash *h;
	char buf[BUFSIZ];
	size_t len;

	if ((arg = get_arg ()) == NULL)
		return usage ();

	if ((core = find_core (arg)) == NULL)
		return error ("unknown algorithm", 0);

	if (sizeof (buf) < core->hash_size)
		return error ("hash size too large", 0);

	if ((h = hash_alloc (core)) == NULL)
		return error ("cannot initialize algorithm", 1);

	if ((arg = get_arg ()) != NULL && strcmp (arg, "-s") == 0) {
		if ((arg = get_arg ()) == NULL)
			return usage ();

		test_speed (h, arg, buf);
	}
	else {
		if (arg != NULL)
			hash_update (h, arg, strlen (arg));
		else
			while ((len = fread (buf, 1, sizeof (buf), stdin)) > 0)
				hash_update (h, buf, len);

		hash_final (h, buf);
	}

	hash_free (h);

	show (buf, core->hash_size);
	return 0;
}
