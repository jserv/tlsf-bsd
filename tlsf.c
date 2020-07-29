#include "tlsf.h"
#include <string.h>
#include <stdbool.h>

// All allocation sizes and addresses are aligned.
#define ALIGN_SIZE  ((size_t)1 << ALIGN_SHIFT)
#define ALIGN_SHIFT (sizeof (size_t) == 8 ? 3 : 2)

// First and second level counts
#define SL_SHIFT 4
#define SL_COUNT (1U << SL_SHIFT)
#define FL_MAX   _TLSF_FL_MAX
#define FL_SHIFT (SL_SHIFT + ALIGN_SHIFT)
#define FL_COUNT (FL_MAX - FL_SHIFT + 1)

// Block status bits are stored in the least significant bits of the size field.
#define BLOCK_BIT_FREE      ((size_t)1)
#define BLOCK_BIT_PREV_FREE ((size_t)2)
#define BLOCK_BITS          (BLOCK_BIT_FREE | BLOCK_BIT_PREV_FREE)

// A free block must be large enough to store its header minus the size of the prev field.
#define BLOCK_OVERHEAD   (sizeof (size_t))
#define BLOCK_SIZE_MIN   (sizeof (tlsf_block) - sizeof (tlsf_block*))
#define BLOCK_SIZE_MAX   ((size_t)1 << (FL_MAX - 1))
#define BLOCK_SIZE_SMALL ((size_t)1 << FL_SHIFT)

#ifdef TLSF_ASSERT
#  include <assert.h>
#  define ASSERT(cond, msg) assert((cond) && msg)
#else
#  define ASSERT(cond, msg)
#endif

typedef struct tlsf_block_ tlsf_block;
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

_Static_assert(sizeof(size_t) == 4 || sizeof (size_t) == 8, "size_t must be 32 or 64 bit");
_Static_assert(sizeof(size_t) == sizeof (void*), "size_t must equal pointer size");
_Static_assert(ALIGN_SIZE == BLOCK_SIZE_SMALL / SL_COUNT, "sizes are not properly set");
_Static_assert(BLOCK_SIZE_MIN < BLOCK_SIZE_SMALL, "min allocation size is wrong");
_Static_assert(BLOCK_SIZE_MAX == TLSF_MAX_SIZE + BLOCK_OVERHEAD, "max allocation size is wrong");
_Static_assert(FL_COUNT <= 32, "index too large");
_Static_assert(SL_COUNT <= 32, "index too large");
_Static_assert(FL_COUNT == _TLSF_FL_COUNT, "invalid level configuration");
_Static_assert(SL_COUNT == _TLSF_SL_COUNT, "invalid level configuration");

static inline uint32_t bitmap_ffs(uint32_t x) {
    uint32_t i = (uint32_t)__builtin_ffs((int32_t)x);
    ASSERT(i, "no set bit found");
    return i - 1U;
}

static inline uint32_t log2floor(size_t x) {
    ASSERT(x > 0, "log2 of zero");
    return sizeof (size_t) == 8
        ? (uint32_t)(63 - (uint32_t)__builtin_clzll((unsigned long long)x))
        : (uint32_t)(31 - (uint32_t)__builtin_clzl((unsigned long)x));
}

static inline size_t block_size(const tlsf_block* block) {
    return block->header & ~BLOCK_BITS;
}

static inline void block_set_size(tlsf_block* block, size_t size) {
    ASSERT(!(size % ALIGN_SIZE), "invalid size");
    block->header = size | (block->header & BLOCK_BITS);
}

static inline bool block_is_free(const tlsf_block* block) {
    return !!(block->header & BLOCK_BIT_FREE);
}

static inline bool block_is_prev_free(const tlsf_block* block) {
    return !!(block->header & BLOCK_BIT_PREV_FREE);
}

static inline void block_set_prev_free(tlsf_block* block, bool free) {
    block->header = free ? block->header | BLOCK_BIT_PREV_FREE : block->header & ~BLOCK_BIT_PREV_FREE;
}

static inline size_t align_up(size_t x, size_t align) {
    ASSERT(!(align & (align - 1)), "must align to a power of two");
    return (x + (align - 1)) & ~(align - 1);
}

static inline char* align_ptr(char* p, size_t align) {
    return (char*)align_up((size_t)p, align);
}

static inline tlsf_block* to_block(void* ptr) {
    tlsf_block* block = (tlsf_block*)ptr;
    ASSERT(block->payload == align_ptr(block->payload, ALIGN_SIZE), "block not aligned properly");
    return block;
}

static inline tlsf_block* block_from_payload(void* ptr) {
    return to_block((char*)ptr - offsetof(tlsf_block, payload));
}

// Return location of previous block.
static inline tlsf_block* block_prev(const tlsf_block* block) {
    ASSERT(block_is_prev_free(block), "previous block must be free");
    return block->prev;
}

// Return location of next existing block.
static inline tlsf_block* block_next(tlsf_block* block) {
    tlsf_block* next = to_block(block->payload + block_size(block) - BLOCK_OVERHEAD);
    ASSERT(block_size(block), "block is last");
    return next;
}

// Link a new block with its neighbor, return the neighbor.
static inline tlsf_block* block_link_next(tlsf_block* block) {
    tlsf_block* next = block_next(block);
    next->prev = block;
    return next;
}

static inline bool block_can_split(tlsf_block* block, size_t size) {
    return block_size(block) >= sizeof (tlsf_block) + size;
}

static inline void block_set_free(tlsf_block* block, bool free) {
    ASSERT(block_is_free(block) != free, "block free bit unchanged");
    block->header = free ? block->header | BLOCK_BIT_FREE : block->header & ~BLOCK_BIT_FREE;
    block_set_prev_free(block_link_next(block), free);
}

// Adjust allocation size to be aligned, and no smaller than internal minimum.
static inline size_t adjust_size(size_t size, size_t align) {
    size = align_up(size, align);
    return size < BLOCK_SIZE_MIN ? BLOCK_SIZE_MIN : size;
}

// Rounds up to the next block size
static inline size_t round_block_size(size_t size) {
    size_t t = ((size_t)1 << (log2floor(size) - SL_SHIFT)) - 1;
    return size >= BLOCK_SIZE_SMALL ? (size + t) & ~t : size;
}

static inline void mapping(size_t size, uint32_t *fl, uint32_t *sl) {
    if (size < BLOCK_SIZE_SMALL) {
        // Store small blocks in first list.
        *fl = 0;
        *sl = (uint32_t)size / (BLOCK_SIZE_SMALL / SL_COUNT);
    } else {
        uint32_t t = log2floor(size);
        *sl = (uint32_t)(size >> (t - SL_SHIFT)) ^ SL_COUNT;
        *fl = t - FL_SHIFT + 1;
    }
    ASSERT(*fl < FL_COUNT, "wrong first level");
    ASSERT(*sl < SL_COUNT, "wrong second level");
}

static tlsf_block* search_suitable_block(tlsf* t, uint32_t *fl, uint32_t *sl) {
    ASSERT(*fl < FL_COUNT, "wrong first level");
    ASSERT(*sl < SL_COUNT, "wrong second level");

    // Search for a block in the list associated with the given fl/sl index.
    uint32_t sl_map = t->sl[*fl] & (~0U << *sl);
    if (!sl_map) {
        // No block exists. Search in the next largest first-level list.
        uint32_t fl_map = t->fl & (uint32_t)(~(uint64_t)0 << (*fl + 1));
        // No free blocks available, memory has been exhausted.
        if (!fl_map)
            return 0;

        *fl = bitmap_ffs(fl_map);
        ASSERT(*fl < FL_COUNT, "wrong first level");

        sl_map = t->sl[*fl];
        ASSERT(sl_map, "second level bitmap is null");
    }

    *sl = bitmap_ffs(sl_map);
    ASSERT(*sl < SL_COUNT, "wrong second level");

    return t->block[*fl][*sl];
}

// Remove a free block from the free list.
static void remove_free_block(tlsf* t, tlsf_block* block, uint32_t fl, uint32_t sl) {
    ASSERT(fl < FL_COUNT, "wrong first level");
    ASSERT(sl < SL_COUNT, "wrong second level");

    tlsf_block* prev = block->prev_free;
    tlsf_block* next = block->next_free;
    if (next)
        next->prev_free = prev;
    if (prev)
        prev->next_free = next;

    // If this block is the head of the free list, set new head.
    if (t->block[fl][sl] == block) {
        t->block[fl][sl] = next;

        // If the new head is null, clear the bitmap.
        if (!next) {
            t->sl[fl] &= ~(1U << sl);

            // If the second bitmap is now empty, clear the fl bitmap.
            if (!t->sl[fl])
                t->fl &= ~(1U << fl);
        }
    }
}

// Insert a free block into the free block list.
static void insert_free_block(tlsf* t, tlsf_block* block, uint32_t fl, uint32_t sl) {
    tlsf_block* current = t->block[fl][sl];
    ASSERT(block, "cannot insert a null entry into the free list");
    block->next_free = current;
    block->prev_free = 0;

    if (current)
        current->prev_free = block;

    /*
     * Insert the new block at the head of the list, and mark the first-
     * and second-level bitmaps appropriately.
     */
    t->block[fl][sl] = block;
    t->fl |= 1U << fl;
    t->sl[fl] |= 1U << sl;
}

// Remove a given block from the free list.
static void block_remove(tlsf* t, tlsf_block* block) {
    uint32_t fl, sl;
    mapping(block_size(block), &fl, &sl);
    remove_free_block(t, block, fl, sl);
}

// Insert a given block into the free list.
static void block_insert(tlsf* t, tlsf_block* block) {
    uint32_t fl, sl;
    mapping(block_size(block), &fl, &sl);
    insert_free_block(t, block, fl, sl);
}

// Split a block into two, the second of which is free.
static tlsf_block* block_split(tlsf_block* block, size_t size) {
    tlsf_block* rest = to_block(block->payload + size - BLOCK_OVERHEAD);
    size_t rest_size = block_size(block) - (size + BLOCK_OVERHEAD);
    ASSERT(block_size(block) == rest_size + size + BLOCK_OVERHEAD, "rest block size is wrong");
    ASSERT(rest_size >= BLOCK_SIZE_MIN, "block split with invalid size");
    rest->header = rest_size;
    ASSERT(!(rest_size % ALIGN_SIZE), "invalid block size");
    block_set_free(rest, true);
    block_set_size(block, size);
    return rest;
}

// Absorb a free block's storage into an adjacent previous free block.
static tlsf_block* block_absorb(tlsf_block* prev, tlsf_block* block) {
    ASSERT(block_size(prev), "previous block can't be last");
    // Note: Leaves flags untouched.
    prev->header += block_size(block) + BLOCK_OVERHEAD;
    block_link_next(prev);
    return prev;
}

// Merge a just-freed block with an adjacent previous free block.
static tlsf_block* block_merge_prev(tlsf* t, tlsf_block* block) {
    if (block_is_prev_free(block)) {
        tlsf_block* prev = block_prev(block);
        ASSERT(prev, "prev block can't be null");
        ASSERT(block_is_free(prev), "prev block is not free though marked as such");
        block_remove(t, prev);
        block = block_absorb(prev, block);
    }
    return block;
}

// Merge a just-freed block with an adjacent free block.
static tlsf_block* block_merge_next(tlsf* t, tlsf_block* block) {
    tlsf_block* next = block_next(block);
    ASSERT(next, "next block can't be null");
    if (block_is_free(next)) {
        ASSERT(block_size(block), "previous block can't be last");
        block_remove(t, next);
        block = block_absorb(block, next);
    }
    return block;
}

// Trim any trailing block space off the end of a block, return to pool.
static void block_rtrim_free(tlsf* t, tlsf_block* block, size_t size) {
    ASSERT(block_is_free(block), "block must be free");
    if (block_can_split(block, size)) {
        tlsf_block* rest = block_split(block, size);
        block_link_next(block);
        block_set_prev_free(rest, true);
        block_insert(t, rest);
    }
}

// Trim any trailing block space off the end of a used block, return to pool.
static void block_rtrim_used(tlsf* t, tlsf_block* block, size_t size) {
    ASSERT(!block_is_free(block), "block must be used");
    if (block_can_split(block, size)) {
        tlsf_block* rest = block_split(block, size);
        block_set_prev_free(rest, false);
        rest = block_merge_next(t, rest);
        block_insert(t, rest);
    }
}

static tlsf_block* block_ltrim_free(tlsf* t, tlsf_block* block, size_t size) {
    ASSERT(block_is_free(block), "block must be free");
    ASSERT(block_can_split(block, size), "block is too small");
    tlsf_block* rest = block_split(block, size - BLOCK_OVERHEAD);
    block_set_prev_free(rest, true);
    block_link_next(block);
    block_insert(t, block);
    return rest;
}

// Find a free block with an appropriate size.
static tlsf_block* block_find_free(tlsf* t, size_t size, size_t rounded) {
    uint32_t fl, sl;
    mapping(rounded, &fl, &sl);
    tlsf_block* block = search_suitable_block(t, &fl, &sl);
    if (block) {
        ASSERT(block_size(block) >= size, "insufficient block size");
        remove_free_block(t, block, fl, sl);
    }
    return block;
}

static tlsf_block* get_sentinel(tlsf* t) {
    return to_block((char*)t->start + (t->size ? t->size - 2*BLOCK_OVERHEAD : -BLOCK_OVERHEAD));
}

static void check_sentinel(tlsf* t, tlsf_block* block) {
    (void)t;
    (void)block;
    ASSERT(get_sentinel(t) == block, "not the sentinel");
    ASSERT(!block_size(block), "sentinel should be last");
    ASSERT(!block_is_free(block), "sentinel block should not be free");
}

static bool grow(tlsf* t, size_t size) {
    size_t req_size = (t->size ? t->size + BLOCK_OVERHEAD : 2*BLOCK_OVERHEAD) + size,
        new_size = t->resize(t, t->start, t->size, req_size);
    ASSERT(new_size == t->size || new_size == req_size, "invalid size after grow");
    if (new_size == t->size)
        return false;
    tlsf_block* block = get_sentinel(t);
    if (!t->size)
        block->header = 0;
    check_sentinel(t, block);
    block->header |= size | BLOCK_BIT_FREE;
    block = block_merge_prev(t, block);
    block_insert(t, block);
    tlsf_block* sentinel = block_link_next(block);
    sentinel->header = BLOCK_BIT_PREV_FREE;
    t->size = new_size;
    check_sentinel(t, sentinel);
    return true;
}

static void shrink(tlsf* t, tlsf_block* block) {
    check_sentinel(t, block_next(block));
    size_t size = block_size(block),
        req_size = (char*)block == (char*)t->start - BLOCK_OVERHEAD ? 0 : t->size - size - BLOCK_OVERHEAD;
    ASSERT(t->size >= size, "invalid heap size before shrink");
    t->size = t->resize(t, t->start, t->size, req_size);
    ASSERT(t->size == req_size, "invalid heap size after shrink");
    if (t->size) {
        block->header = 0;
        check_sentinel(t, block);
    }
}

static tlsf_block* block_alloc(tlsf* t, size_t size) {
    size_t rounded = round_block_size(size);
    tlsf_block* block = block_find_free(t, size, rounded);
    if (!block) {
        if (!grow(t, rounded))
            return 0;
        block = block_find_free(t, size, rounded);
        ASSERT(block, "no block found");
    }
    return block;
}

TLSF_API void tlsf_init(tlsf* t, void* start, tlsf_resize resize) {
    memset(t, 0, sizeof (tlsf));
    t->start = start;
    t->resize = resize;
    ASSERT((size_t)t->start % ALIGN_SIZE == 0, "wrong alignment");
}

static void* block_use(tlsf* t, tlsf_block* block, size_t size) {
    block_rtrim_free(t, block, size);
    block_set_free(block, false);
    return block->payload;
}

TLSF_API void* tlsf_malloc(tlsf* t, size_t size) {
    size = adjust_size(size, ALIGN_SIZE);
    if (size > TLSF_MAX_SIZE)
        return 0;
    tlsf_block* block = block_alloc(t, size);
    if (!block)
        return 0;
    return block_use(t, block, size);
}

TLSF_API void* tlsf_aalloc(tlsf* t, size_t align, size_t size) {
    size_t adjust = adjust_size(size, ALIGN_SIZE);

    if (align &&
        ((align & (align - 1)) || // align is not a power of two
         (size & (align - 1)) || // size is not a multiple of align
         adjust > TLSF_MAX_SIZE - align - sizeof (tlsf_block))) // size is too large
        return 0;

    if (align <= ALIGN_SIZE)
        return tlsf_malloc(t, size);

    size_t asize = adjust_size(adjust + align - 1 + sizeof (tlsf_block), align);
    tlsf_block* block = block_alloc(t, asize);
    if (!block)
        return 0;

    char* mem = align_ptr(block->payload + sizeof (tlsf_block), align);
    block = block_ltrim_free(t, block, (size_t)(mem - block->payload));
    return block_use(t, block, adjust);
}

TLSF_API void tlsf_free(tlsf* t, void* mem) {
    if (!mem)
        return;

    tlsf_block* block = block_from_payload(mem);
    ASSERT(!block_is_free(block), "block already marked as free");

    block_set_free(block, true);
    block = block_merge_prev(t, block);
    block = block_merge_next(t, block);

    if (!block_size(block_next(block)))
        shrink(t, block);
    else
        block_insert(t, block);
}

TLSF_API void* tlsf_realloc(tlsf* t, void* mem, size_t size) {
    // Zero-size requests are treated as free.
    if (mem && !size) {
        tlsf_free(t, mem);
        return 0;
    }

    // Null-pointer requests are treated as malloc.
    if (!mem)
        return tlsf_malloc(t, size);

    tlsf_block* block = block_from_payload(mem);
    tlsf_block* next = block_next(block);

    size_t cursize = block_size(block),
        combined = cursize + block_size(next) + BLOCK_OVERHEAD;
    size = adjust_size(size, ALIGN_SIZE);
    if (size > TLSF_MAX_SIZE)
        return 0;

    ASSERT(!block_is_free(block), "block already marked as free");

    // If the next block is used, or when combined with the current
    // block, does not offer enough space, we must relocate and copy.
    if (size > cursize && (!block_is_free(next) || size > combined)) {
        char* p = (char*)tlsf_malloc(t, size);
        if (p) {
            memcpy(p, mem, cursize);
            tlsf_free(t, mem);
        }
        return p;
    }

    // Do we need to expand to the next block?
    if (size > cursize) {
        block_merge_next(t, block);
        block_set_prev_free(block_next(block), false);
    }

    // Trim the resulting block and return the original pointer.
    block_rtrim_used(t, block, size);
    return mem;
}

#ifdef TLSF_CHECK
#include <stdio.h>
#include <stdlib.h>
#define CHECK(cond, msg)                                                \
    ({                                                                  \
        if (!(cond)) {                                                  \
            fprintf(stderr, "TLSF CHECK: %s - %s\n", msg, #cond);       \
            abort();                                                    \
        }                                                               \
    })

TLSF_API void tlsf_check(tlsf* t) {
    for (uint32_t i = 0; i < FL_COUNT; ++i) {
        for (uint32_t j = 0; j < SL_COUNT; ++j) {
            size_t fl_map = t->fl & (1U << i),
                sl_list = t->sl[i],
                sl_map = sl_list & (1U << j);
            tlsf_block* block = t->block[i][j];

            // Check that first- and second-level lists agree.
            if (!fl_map)
                CHECK(!sl_map, "second-level map must be null");

            if (!sl_map) {
                CHECK(!block, "block list must be null");
                continue;
            }

            // Check that there is at least one free block.
            CHECK(sl_list, "no free blocks in second-level map");

            while (block) {
                uint32_t fl, sl;
                CHECK(block_is_free(block), "block should be free");
                CHECK(!block_is_prev_free(block), "blocks should have coalesced");
                CHECK(!block_is_free(block_next(block)), "blocks should have coalesced");
                CHECK(block_is_prev_free(block_next(block)), "block should be free");
                CHECK(block_size(block) >= BLOCK_SIZE_MIN, "block not minimum size");

                mapping(block_size(block), &fl, &sl);
                CHECK(fl == i && sl == j, "block size indexed in wrong list");
                block = block->next_free;
            }
        }
    }
}
#endif
