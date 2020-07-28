#ifndef _TLSF_H
#define _TLSF_H

#include <stddef.h>
#include <stdint.h>

#define TLSF_FL_COUNT  32
#define TLSF_SL_COUNT  16
#define TLSF_BITS      (8 * sizeof (void*))
#define TLSF_MAX_SHIFT (TLSF_BITS == 64 ? 37 : 29)
#define TLSF_MAX_SIZE  (((size_t)1 << TLSF_MAX_SHIFT) - sizeof (size_t))

typedef struct tlsf_ tlsf;
typedef struct tlsf_block_ tlsf_block;
typedef void* (*tlsf_map_t)(size_t*, void*);
typedef void  (*tlsf_unmap_t)(void*, size_t, void*);

struct tlsf_block_ {
    // Points to the previous block.
    // This field is only valid if the previous block is free and
    // is actually stored at the end of the previous block.
    tlsf_block* prev_block;

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

    tlsf_map_t   map;
    tlsf_unmap_t unmap;
    void*        user;
};

void tlsf_init(tlsf*, tlsf_map_t, tlsf_unmap_t, void*);
void* tlsf_malloc(tlsf*, size_t);
void* tlsf_realloc(tlsf*, void*, size_t);
void  tlsf_free(tlsf*, void*);

#ifdef TLSF_CHECK
void tlsf_check(tlsf*);
#else
static inline void tlsf_check(tlsf* t) { (void)t; }
#endif

#endif
