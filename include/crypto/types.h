#ifndef CRYPTO_TYPES_H
#define CRYPTO_TYPES_H  1

#include <stddef.h>
#include <stdint.h>

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

#ifdef __GNUC__
#define noinline __attribute__((noinline))
#else
#define noinline
#endif

#endif  /* CRYPTO_TYPES_H */
