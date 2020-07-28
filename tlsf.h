#ifndef _TLSF_H
#define _TLSF_H

#include <stddef.h>
#include <stdint.h>

#ifndef TLSF_API
#  define TLSF_API
#endif

#define TLSF_FL_COUNT  32
#define TLSF_SL_COUNT  16
#define TLSF_BITS      (8 * sizeof (void*))
#define TLSF_MAX_SHIFT (TLSF_BITS == 64 ? 37 : 29)
#define TLSF_MAX_SIZE  (((size_t)1 << TLSF_MAX_SHIFT) - sizeof (size_t))

typedef struct tlsf_ tlsf;
typedef struct tlsf_block_ tlsf_block;
typedef size_t (*tlsf_resize)(tlsf*, void*, size_t, size_t);

struct tlsf_block_ {
    // Points to the previous block.
    // This field is only valid if the previous block is free and
    // is actually stored at the end of the previous block.
    tlsf_block* prev;

    // Size and block bits
    size_t header;

    // Block payload
    char payload[0];

    // Next and previous free blocks.
    // These fields are only valid if the corresponding block is free.
    tlsf_block *next_free, *prev_free;
};

struct tlsf_ {
    // Bitmaps for free lists.
    uint32_t fl_bm, sl_bm[TLSF_FL_COUNT];

    // Head of free lists.
    tlsf_block* blocks[TLSF_FL_COUNT][TLSF_SL_COUNT];

    tlsf_resize resize;
    void*       start;
    size_t      size;
};

TLSF_API void tlsf_init(tlsf*, void*, tlsf_resize);
TLSF_API void* tlsf_malloc(tlsf*, size_t);
TLSF_API void* tlsf_realloc(tlsf*, void*, size_t);
TLSF_API void  tlsf_free(tlsf*, void*);

#ifdef TLSF_CHECK
TLSF_API void tlsf_check(tlsf*);
#else
static inline void tlsf_check(tlsf* t) { (void)t; }
#endif

#endif
