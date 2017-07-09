#ifndef CRYPTO_CORE_H
#define CRYPTO_CORE_H  1

#include <crypto/types.h>
#include <crypto/endian.h>

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

#define noinline __attribute__((noinline))
#define barrier_data(p)  __asm__ __volatile__ ("" :: "r"(p) : "memory")

#else

#define noinline
#define barrier_data(p)

#endif

/* allows 0 <= count < 32 */
static u32 rol32 (u32 x, unsigned count)
{
	return x << count | x >> (32 - count);
}

#endif  /* CRYPTO_CORE_H */
