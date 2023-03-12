#pragma once

#include <stddef.h>
#include <stdint.h>

#ifndef TLSF_API
#define TLSF_API
#endif

#define _TLSF_SL_COUNT 16
#define _TLSF_FL_COUNT (sizeof(size_t) == 8 ? 32 : 25)
#define _TLSF_FL_MAX (sizeof(size_t) == 8 ? 38 : 30)
#define TLSF_MAX_SIZE (((size_t) 1 << (_TLSF_FL_MAX - 1)) - sizeof(size_t))
#define TLSF_INIT ((tlsf){.size = 0})

typedef struct {
    uint32_t fl, sl[_TLSF_FL_COUNT];
    struct tlsf_block_ *block[_TLSF_FL_COUNT][_TLSF_SL_COUNT];
    size_t size;
} tlsf;

TLSF_API void *tlsf_resize(tlsf *, size_t);
TLSF_API void *tlsf_aalloc(tlsf *, size_t, size_t);
TLSF_API void *tlsf_malloc(tlsf *, size_t);
TLSF_API void *tlsf_realloc(tlsf *, void *, size_t);
TLSF_API void tlsf_free(tlsf *, void *);

#ifdef TLSF_ENABLE_CHECK
TLSF_API void tlsf_check(tlsf *);
#else
static inline void tlsf_check(tlsf *t)
{
    (void) t;
}
#endif
