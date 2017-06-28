#include <string.h>
#include "core.h"

void explicit_bzero (void *data, size_t len)
{
	memset (data, 0, len);
	barrier_data (data);
}
