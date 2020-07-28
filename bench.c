/* Copyright (c) 2016 National Cheng Kung University, Taiwan.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style license.
 */
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <time.h>
#include "tlsf.h"

static tlsf t;

static void usage(const char *name) {
    printf("run a malloc benchmark.\n"
           "usage: %s [-s blk-size|blk-min:blk-max] [-l loop-count] "
           "[-n num-blocks] [-c]\n",
           name);
    exit(-1);
}

/* Parse an integer argument. */
static size_t parse_int_arg(const char *arg, const char *exe_name) {
    long ret = strtol(arg, NULL, 0);
    if (errno)
        usage(exe_name);

    return (size_t) ret;
}

/* Parse a size argument, which is either an integer or two integers
   separated by a colon, denoting a range. */
static void parse_size_arg(const char *arg, const char *exe_name,
                           size_t *blk_min, size_t *blk_max) {
    char *endptr;
    *blk_min = (size_t)strtol(arg, &endptr, 0);

    if (errno)
        usage(exe_name);

    if (endptr && *endptr == ':') {
        *blk_max = (size_t)strtol(endptr + 1, NULL, 0);
        if (errno)
            usage(exe_name);
    }

    if (*blk_min > *blk_max)
        usage(exe_name);
}

/* Get a random block size between blk_min and blk_max. */
static size_t get_random_block_size(size_t blk_min, size_t blk_max) {
    if (blk_max > blk_min)
        return blk_min + ((size_t)rand() % (blk_max - blk_min));
    return blk_min;
}

static void run_alloc_benchmark(size_t loops, size_t blk_min, size_t blk_max,
                                void **blk_array, size_t num_blks, bool clear) {
    while (loops--) {
        size_t next_idx = (size_t)rand() % num_blks;
        size_t blk_size = get_random_block_size(blk_min, blk_max);

        if (blk_array[next_idx]) {
            if (rand() % 10 == 0) {
                /* Insert the newly alloced block into the array at a random point. */
                blk_array[next_idx] = tlsf_realloc(&t, blk_array[next_idx], blk_size);
            } else {
                tlsf_free(&t, blk_array[next_idx]);
                /* Insert the newly alloced block into the array at a random point. */
                blk_array[next_idx] = tlsf_malloc(&t, blk_size);
            }
        } else {
            /* Insert the newly alloced block into the array at a random point. */
            blk_array[next_idx] = tlsf_malloc(&t, blk_size);
        }
        if (clear)
            memset(blk_array[next_idx], 0, blk_size);
    }

    /* Free up all allocated blocks. */
    for (size_t i = 0; i < num_blks; i++) {
        if (blk_array[i])
            tlsf_free(&t, blk_array[i]);
    }
}

static size_t max_size;

static size_t resize(tlsf* _t, void* _start, size_t old_size, size_t req_size) {
    (void)_t;
    (void)_start;
    return req_size > max_size ? old_size : req_size;
}

int main(int argc, char **argv) {
    size_t blk_min = 512, blk_max = 512, num_blks = 10000;
    size_t loops = 10000000;
    bool clear = false;
    int opt;

    while ((opt = getopt(argc, argv, "s:l:r:t:n:b:ch")) > 0) {
        switch (opt) {
        case 's':
            parse_size_arg(optarg, argv[0], &blk_min, &blk_max);
            break;
        case 'l':
            loops = parse_int_arg(optarg, argv[0]);
            break;
        case 'n':
            num_blks = parse_int_arg(optarg, argv[0]);
            break;
        case 'c':
            clear = true;
            break;
        case 'h':
            usage(argv[0]);
            break;
        default:
            usage(argv[0]);
            break;
        }
    }

    max_size = blk_max * num_blks;
    tlsf_init(&t, malloc(max_size), resize);

    void** blk_array = (void**)calloc(num_blks, sizeof(void*));
    assert(blk_array);

    struct timespec start, end;

    int err = clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
    assert(err == 0);

    printf("blk_min=%lu to blk_max=%lu\n", blk_min, blk_max);

    run_alloc_benchmark(loops, blk_min, blk_max,
                        blk_array, num_blks, clear);

    err = clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
    assert(err == 0);
    free(blk_array);

    double elapsed = (double)(end.tv_sec - start.tv_sec) + (double)(end.tv_nsec - start.tv_nsec) * 1e-9;

    struct rusage usage;
    err = getrusage(RUSAGE_SELF, &usage);
    assert(err == 0);

    /* Dump both machine and human readable versions */
    printf("%lu:%lu:%lu:%u:%lu:%.6f: took %.6f s for %lu malloc/free\nbenchmark loops of %lu-%lu bytes.  ~%.3f us per loop\n",
           blk_min, blk_max, loops,
           clear, usage.ru_maxrss, elapsed, elapsed, loops, blk_min,
           blk_max, elapsed / (double)loops * 1e6);

    return 0;
}
