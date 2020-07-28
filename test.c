/* Copyright (c) 2016 National Cheng Kung University, Taiwan.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style license.
 */
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <sys/mman.h>
#include "tlsf.h"

static void* tlsf_map(size_t* min_size, void* user) {
    size_t spacelen = *(size_t*)user;
    *min_size += spacelen;
    void* p = malloc(*min_size);
    assert(p);
    printf("map addr=%p size=%lu\n", p, *min_size);
    return p;
}

static void tlsf_unmap(void* p, size_t s, void* user) {
    (void)user;
    printf("unmap addr=%p size=%lu\n", p, s);
    free(p);
}

static void* tlsf_map_large(size_t* min_size, void* user) {
    if (user && *min_size < TLSF_MAX_SIZE)
        *min_size = TLSF_MAX_SIZE;
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    *min_size = page * ((*min_size + page - 1UL) / page);
    void* p = mmap(0, *min_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
    assert(p != (void*)(-1));
    return p;
}

static void tlsf_unmap_large(void* p, size_t s, void* user) {
    (void)user;
    int ret = munmap(p, s);
    assert(ret == 0);
}

static void random_test(size_t spacelen, const size_t cap) {
    const size_t maxitems = 2 * spacelen;

    void** p = (void**)malloc(maxitems * sizeof(void *));
    assert(p);

    tlsf t;
    tlsf_init(&t, tlsf_map, tlsf_unmap, &spacelen);

    /*
     * Allocate random sizes up to the cap threshold.
     * Track them in an array.
     */
    int64_t rest = (int64_t)spacelen * (rand() % 6 + 1);
    unsigned i = 0;
    while (rest > 0) {
        size_t len = ((size_t)rand() % cap) + 1;
        p[i] = tlsf_malloc(&t, len);
        assert(p[i]);
        rest -= (int64_t)len;

        if (rand() % 10 == 0) {
            len = ((size_t)rand() % cap) + 1;
            p[i] = tlsf_realloc(&t, p[i], len);
            assert(p[i]);
        }

        tlsf_check(&t);

        /* Fill with magic (only when testing up to 1MB). */
        uint8_t* data = (uint8_t*)p[i];
        if (spacelen <= 1024 * 1024)
            memset(data, 0, len);
        data[0] = 0xa5;

        if (i++ == maxitems)
            break;
    }

    /*
     * Randomly deallocate the memory blocks until all of them are freed.
     * The free space should match the free space after initialisation.
     */
    for (unsigned n = i; n;) {
        size_t target = (size_t)rand() % i;
        if (p[target] == NULL)
            continue;
        uint8_t* data = (uint8_t*)p[target];
        assert(data[0] == 0xa5);
        tlsf_free(&t, p[target]);
        p[target] = NULL;
        n--;

        tlsf_check(&t);
    }

    free(p);
}

#define	__arraycount(__x) (sizeof(__x) / sizeof(__x[0]))

static void random_sizes_test(void) {
    const size_t sizes[] = {32, 64, 128, 256, 1024, 1024 * 1024};//, 128 * 1024 * 1024};

    for (unsigned i = 0; i < __arraycount(sizes); i++) {
        unsigned n = 1024;

        while (n--) {
            size_t cap = (size_t)rand() % sizes[i] + 1;
            printf("sizes = %lu, cap = %lu\n", sizes[i], cap);
            random_test(sizes[i], cap);
        }
    }
}

static void large_alloc(tlsf* t, size_t s) {
    printf("large alloc %lu\n", s);
    for (size_t d = 0; d < 100 && d < s; ++d) {
        void* p = tlsf_malloc(t, s - d);
        assert(p);

        void* q = tlsf_malloc(t, s - d);
        assert(q);
        tlsf_free(t, q);

        q = tlsf_malloc(t, s - d);
        assert(q);
        tlsf_free(t, q);

        tlsf_free(t, p);
        tlsf_check(t);
    }
}

static void large_size_test(bool large_pool) {
    tlsf t;
    tlsf_init(&t, tlsf_map_large, tlsf_unmap_large, large_pool ? (void*)1 : 0);

    size_t s = 1;
    while (s <= TLSF_MAX_SIZE) {
        large_alloc(&t, s);
        s *= 2;
    }

    s = TLSF_MAX_SIZE;
    while (s > 0) {
        large_alloc(&t, s);
        s /= 2;
    }
}

int main(void) {
    srand((unsigned int)time(0));
    large_size_test(true);
    large_size_test(false);
    random_sizes_test();
    puts("OK!");
    return 0;
}
