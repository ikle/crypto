#ifndef CRYPTO_CORE_H
#define CRYPTO_CORE_H  1

#include <crypto/types.h>
#include <crypto/endian.h>
#include <crypto/utils.h>

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

#endif  /* CRYPTO_CORE_H */
