/* Harness-build replacement for src/runtime/memops.c (linked instead of it, see
 * mayhem/Makefile). Upstream's runtime_memcpy/memset copy whole aligned machine words and
 * deliberately read up to 7 bytes past the end of the source buffer (harmless on hardware:
 * the word never crosses a page), which ASan reports on the first input of every target.
 * Routing the same four primitives to libc keeps their semantics (runtime_memcpy allows
 * overlap, so memmove) while letting ASan's interceptors bounds-check BOTH ends of every
 * copy the parsers make — so real overflows in callers are still caught. */
#include <string.h>

void runtime_memcpy(void *a, const void *b, unsigned long len)
{
    if (len)
        memmove(a, b, len);
}

void runtime_memset(unsigned char *a, unsigned char b, unsigned long len)
{
    if (len)
        memset(a, b, len);
}

int runtime_memcmp(const void *a, const void *b, unsigned long len)
{
    return len ? memcmp(a, b, len) : 0;
}

void *runtime_memchr(const void *a, int c, unsigned long len)
{
    return len ? memchr(a, c, len) : 0;
}
