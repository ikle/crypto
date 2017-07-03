#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "hash-core.h"

#include "md5-core.h"
#include "sha1-core.h"
#include "stribog-core.h"

#include "hmac-core.h"

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
	fprintf (stderr, "usage:\n\thash-test <algorithm> "
				"(-t | -s <string> | [<file-name>])\n");

	return 1;
}

static void show (const unsigned char *data, size_t len)
{
	for (; len > 0; ++data, --len)
		printf ("%02x", *data);

	printf ("\n");
}

static struct hash *find_algo (const char *name)
{
	const struct hash_core *core =
		strcmp (name, "md5")      == 0 ? &md5_core :
		strcmp (name, "sha1")     == 0 ? &sha1_core :
		strcmp (name, "stribog")  == 0 ? &stribog_core :
		strcmp (name, "hmac-md5") == 0 ? &hmac_core :
		NULL;
	struct hash *h;

	if (core == NULL) {
		errno = ENOENT;
		return NULL;
	}

	if ((h = hash_alloc (core)) == NULL)
		return NULL;

	if (core == &hmac_core &&
	    ((errno = -hash_set_algo (h, &md5_core)) != 0 ||
	     (errno = -hash_set_key  (h, NULL, 0))   != 0))
		goto no_opts;

	return h;
no_opts:
	hash_free (h);
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

static void test_speed (struct hash *h, void *out)
{
	struct tms t0, t1;
	int i;
	double duration;

	times (&t0);

	for (i = 0; i < COUNT; ++i)
		hash_data (h, NULL, 0, out);

	times (&t1);
	duration = ticks_to_secs ((double) t1.tms_utime - t0.tms_utime);

	printf ("hash/s = %f\n", COUNT / duration);
}

static void hash_file (struct hash *h, FILE *f, void *out)
{
	char buf[BUFSIZ];
	size_t avail, processed;

	for (avail = 0; !feof (f);) {
		avail += fread (buf + avail, 1, sizeof (buf) - avail, f);
		avail -= (processed = hash_data (h, buf, avail, NULL));
		memmove (buf, buf + processed, avail);
	}

	hash_data (h, buf, avail, out);
}

#define get_arg()	(argc < 2 ? NULL : (--argc, ++argv, argv[0]))

int main (int argc, char *argv[])
{
	const char *arg;
	struct hash *h;
	size_t hs;
	FILE *f = stdin;

	if ((arg = get_arg ()) == NULL)
		return usage ();

	if ((h = find_algo (arg)) == NULL)
		return error ("cannot initialize algorithm", 1);

	char digest[hs = hash_get_hash_size (h)];

	if ((arg = get_arg ()) != NULL && strcmp (arg, "-t") == 0) {
		if (argv[1] != NULL)
			return usage ();

		test_speed (h, digest);
	}
	else if (arg != NULL && strcmp (arg, "-s") == 0) {
		if ((arg = get_arg ()) == NULL)
			return usage ();

		hash_data (h, arg, strlen (arg), digest);
		show (digest, hs);
	}
	else {
		if (arg != NULL && (f = fopen (arg, "rb")) == NULL)
			return error ("cannot open file", 1);

		hash_file (h, f, digest);
		show (digest, hs);
	}

	hash_free (h);
	return 0;
}
