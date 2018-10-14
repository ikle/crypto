#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>

#include <crypto/api.h>
#include <crypto/types.h>

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

static void usage (void)
{
	errx (0, "usage:\n\tcrypto ...\n");
}

static struct crypto *algo;

static void set_algo (int argc, char *argv[])
{
	struct crypto *o;

	if (argc < 2)
		errx (1, "algo requires an argument");

	if ((o = crypto_alloc (argv[1])) == NULL)
		err (1, "cannot find algo %s", argv[1]);

	if (algo != NULL && !crypto_set_algo (o, algo))
		err (1, "cannot set algo to %s", argv[1]);

	algo = o;
}

static void set_key (int argc, char *argv[])
{
	size_t len;

	if (argc < 2)
		errx (1, "key requires an argument");

	if (algo == NULL)
		errx (1, "algo does not defined");

	if (!read_blob (argv[1], &len))
		err (1, "key format error");

	if (!crypto_set_key (algo, argv[1], len))
		err (1, "cannot set key");
}

static void set_iv (int argc, char *argv[])
{
	size_t len;

	if (argc < 2)
		errx (1, "iv requires an argument");

	if (algo == NULL)
		errx (1, "algo does not defined");

	if (!read_blob (argv[1], &len))
		err (1, "IV format error");

	if (!crypto_set_iv (algo, argv[1], len))
		err (1, "cannot set IV");
}

static void set_salt (int argc, char *argv[])
{
	size_t len;

	if (argc < 2)
		errx (1, "salt requires an argument");

	if (algo == NULL)
		errx (1, "algo does not defined");

	if (!read_blob (argv[1], &len))
		err (1, "salt format error");

	if (!crypto_set_salt (algo, argv[1], len))
		err (1, "cannot set salt");
}

static void set_count (int argc, char *argv[])
{
	unsigned long count;
	char *end;

	if (argc < 2)
		errx (1, "count requires an argument");

	if (algo == NULL)
		errx (1, "algo does not defined");

	count = strtoul (argv[1], &end, 0);
	if (end[0] != '\0')
		err (1, "count format error");

	if (!crypto_set_count (algo, count))
		err (1, "cannot set count");
}

static void crypt (int encrypt, int argc, char *argv[])
{
	size_t len;
	size_t bs;

	if (argc < 2)
		errx (1, "encrypt/decrypt requires an argument");

	if (algo == NULL)
		errx (1, "algo does not defined");

	if (!read_blob (argv[1], &len))
		err (1, "data block format error");

	bs = crypto_get_input_size (algo);
	if (len != bs)
		errx (1, "wrong size of block: got %zu, want %zu", len, bs);

	u8 block[bs];

	if (encrypt)
		crypto_encrypt (algo, argv[1], block);
	else
		crypto_decrypt (algo, argv[1], block);

	show (block, bs);
}

static void update (int argc, char *argv[])
{
	size_t len;

	if (argc < 2)
		errx (1, "update requires an argument");

	if (algo == NULL)
		errx (1, "algo does not defined");

	if (!read_blob (argv[1], &len))
		err (1, "data block format error");

	if (!crypto_update (algo, argv[1], len))
		err (1, "cannot push data");
}

static void fetch (int argc, char *argv[])
{
	size_t len;
	char *end;

	if (argc < 2)
		errx (1, "fetch requires an argument");

	if (algo == NULL)
		errx (1, "algo does not defined");

	len = strtoul (argv[1], &end, 0);
	if (end[0] != '\0')
		err (1, "count format error");

	u8 block[len];

	if (!crypto_fetch (algo, block, len))
		err (1, "cannot fetch result");

	show (block, len);
}

int main (int argc, char *argv[])
{
	--argc, ++argv;

	while (argc > 0) {
		if (strcmp (argv[0], "algo") == 0) {
			set_algo (argc, argv);
			argc -= 2, argv += 2;
		}
		else if (strcmp (argv[0], "key") == 0) {
			set_key (argc, argv);
			argc -= 2, argv += 2;
		}
		else if (strcmp (argv[0], "iv") == 0) {
			set_iv (argc, argv);
			argc -= 2, argv += 2;
		}
		else if (strcmp (argv[0], "salt") == 0) {
			set_salt (argc, argv);
			argc -= 2, argv += 2;
		}
		else if (strcmp (argv[0], "count") == 0) {
			set_count (argc, argv);
			argc -= 2, argv += 2;
		}
		else if (strcmp (argv[0], "encrypt") == 0) {
			crypt (1, argc, argv);
			argc -= 2, argv += 2;
		}
		else if (strcmp (argv[0], "decrypt") == 0) {
			crypt (0, argc, argv);
			argc -= 2, argv += 2;
		}
		else if (strcmp (argv[0], "update") == 0) {
			update (argc, argv);
			argc -= 2, argv += 2;
		}
		else if (strcmp (argv[0], "fetch") == 0) {
			fetch (argc, argv);
			argc -= 2, argv += 2;
		}
		else
			usage ();
	}

	return 0;
}
