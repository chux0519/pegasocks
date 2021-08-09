#ifndef _PGS_DEFS
#define _PGS_DEFS

#include <string.h>

#define BUFSIZE_512 512
#define BUFSIZE_16K 16 * 1024
#define BUFSIZE_4K 4 * 1024
#define memzero(buf, n) (void)memset(buf, 0, n)

#endif
