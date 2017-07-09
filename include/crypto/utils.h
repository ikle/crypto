#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H  1

#include <crypto/types.h>

#ifdef __GNUC__
#define barrier_data(p)  __asm__ __volatile__ ("" :: "r"(p) : "memory")
#else
#define barrier_data(p)
#endif

/* allows 0 <= count < 32 */
static u32 rol32 (u32 x, unsigned count)
{
	return x << count | x >> (32 - count);
}

#endif  /* CRYPTO_UTILS_H */
