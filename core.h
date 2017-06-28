#ifndef CRYPTO_CORE_H
#define CRYPTO_CORE_H  1


#include <stddef.h>
#include <stdint.h>
#include <errno.h>

typedef uint8_t	 u8;
typedef uint32_t u32;
typedef uint64_t u64;

/*
 * container_of (ptr, type, member) -- case a member of a structure out to
 * the containing structure, where:
 *
 *   ptr    -- the pointer to the member;
 *   type   -- the type of the container structure this is embedded in;
 *   member -- the name of the member within the structure.
 */
#define container_of(ptr, type, member)  ((type *) \
	((char *) (ptr) - offsetof (type, member)))

#ifdef __GNUC__
#define barrier_data(p)  __asm__ __volatile__ ("" :: "r"(p) : "memory")
#else
#define barrier_data(p)
#endif

void explicit_bzero (void *data, size_t len);

#include <stdarg.h>

static void va_put_size (va_list ap, size_t size)
{
	size_t *p = va_arg (ap, size_t *);

	*p = size;
}

/* allows 0 <= count < 32 */
static u32 rol32 (u32 x, unsigned count)
{
	return x << count | x >> (32 - count);
}

static u32 read_le32 (const void *from)
{
	const u8 *in = from;
	const u32 a = in[0], b = in[1], c = in[2], d = in[3];

	return a | (b << 8) | (c << 16) | (d << 24);
}

static u32 read_be32 (const void *from)
{
	const u8 *in = from;
	const u32 a = in[0], b = in[1], c = in[2], d = in[3];

	return d | (c << 8) | (b << 16) | (a << 24);
}

static u64 read_le64 (const void *from)
{
	const u8 *in = from;
	const u64 a = in[0], b = in[1], c = in[2], d = in[3],
		  e = in[4], f = in[5], g = in[6], h = in[7];

	return         a | (b <<  8) | (c << 16) | (d << 24) |
	       (e << 32) | (f << 40) | (g << 48) | (h << 56);
}

static void write_le32 (u32 x, void *to)
{
	u8 *out = to;

	out[0] = x;
	out[1] = x >> 8;
	out[2] = x >> 16;
	out[3] = x >> 24;
}

static void write_be32 (u32 x, void *to)
{
	u8 *out = to;

	out[0] = x >> 24;
	out[1] = x >> 16;
	out[2] = x >> 8;
	out[3] = x;
}

static void write_le64 (u64 x, void *to)
{
	u8 *out = to;

	out[0] = x;
	out[1] = x >> 8;
	out[2] = x >> 16;
	out[3] = x >> 24;
	out[4] = x >> 32;
	out[5] = x >> 40;
	out[6] = x >> 48;
	out[7] = x >> 56;
}

static void write_be64 (u64 x, void *to)
{
	u8 *out = to;

	out[0] = x >> 56;
	out[1] = x >> 48;
	out[2] = x >> 40;
	out[3] = x >> 32;
	out[4] = x >> 24;
	out[5] = x >> 16;
	out[6] = x >> 8;
	out[7] = x;
}

#endif  /* CRYPTO_CORE_H */
