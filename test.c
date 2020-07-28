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

static size_t PAGE;
static size_t MAX_PAGES;
static size_t curr_pages = 0;

static size_t resize(tlsf* t, void* start, size_t old_size, size_t req_size) {
    (void)t;

    size_t req_pages = (req_size + PAGE - 1) / PAGE;
    if (req_pages > MAX_PAGES)
        return old_size;

    if (req_pages != curr_pages) {
        if (req_pages < curr_pages)
            madvise((char*)start + PAGE * req_pages, (size_t)(curr_pages - req_pages) * PAGE, MADV_FREE);
        curr_pages = req_pages;
    }

    return req_size;
}

static void random_test(tlsf* t, size_t spacelen, const size_t cap) {
    const size_t maxitems = 2 * spacelen;

    void** p = (void**)malloc(maxitems * sizeof(void *));
    assert(p);

    /*
     * Allocate random sizes up to the cap threshold.
     * Track them in an array.
     */
    int64_t rest = (int64_t)spacelen * (rand() % 6 + 1);
    unsigned i = 0;
    while (rest > 0) {
        size_t len = ((size_t)rand() % cap) + 1;
        p[i] = tlsf_malloc(t, len);
        assert(p[i]);
        rest -= (int64_t)len;

        if (rand() % 10 == 0) {
            len = ((size_t)rand() % cap) + 1;
            p[i] = tlsf_realloc(t, p[i], len);
            assert(p[i]);
        }

        tlsf_check(t);

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
        tlsf_free(t, p[target]);
        p[target] = NULL;
        n--;

        tlsf_check(t);
    }

    free(p);
}

#define	__arraycount(__x) (sizeof(__x) / sizeof(__x[0]))

static void random_sizes_test(tlsf* t) {
    const size_t sizes[] = {32, 64, 128, 256, 1024, 1024 * 1024};//, 128 * 1024 * 1024};

    for (unsigned i = 0; i < __arraycount(sizes); i++) {
        unsigned n = 1024;

        while (n--) {
            size_t cap = (size_t)rand() % sizes[i] + 1;
            printf("sizes = %lu, cap = %lu\n", sizes[i], cap);
            random_test(t, sizes[i], cap);
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

static void large_size_test(tlsf* t) {
    size_t s = 1;
    while (s <= TLSF_MAX_SIZE) {
        large_alloc(t, s);
        s *= 2;
    }

    s = TLSF_MAX_SIZE;
    while (s > 0) {
        large_alloc(t, s);
        s /= 2;
    }
}

int main(void) {
    PAGE = (size_t)sysconf(_SC_PAGESIZE);
    MAX_PAGES = 10 * TLSF_MAX_SIZE / PAGE;

    void* p = mmap(0, MAX_PAGES * PAGE,
                   PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE,
                   -1, 0);
    tlsf t;
    tlsf_init(&t, p, resize);

    srand((unsigned int)time(0));
    large_size_test(&t);
    random_sizes_test(&t);
    puts("OK!");
    return 0;
}
