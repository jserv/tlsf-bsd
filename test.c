/* Copyright (c) 2016 National Cheng Kung University, Taiwan.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style license.
 */
#define _DEFAULT_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <err.h>
#include "tlsf.h"

static void* tlsf_map(size_t* min_size, void* user) {
  size_t spacelen = *(size_t*)user;
  *min_size += spacelen;
  void* p = malloc(*min_size);
  printf("map addr=%p size=%lu\n", p, *min_size);
  return p;
}

static void tlsf_unmap(void* p, size_t s, void* user) {
  (void)user;
  printf("unmap addr=%p size=%lu\n", p, s);
  free(p);
}

static void random_test(size_t spacelen, const size_t cap) {
  const size_t maxitems = 2 * spacelen;

  void** p = (void**)malloc(maxitems * sizeof(void *));
  if (p == NULL) {
    err(EXIT_FAILURE, "malloc");
  }

  tlsf_t t = tlsf_create(tlsf_map, tlsf_unmap, &spacelen);
  assert(t != NULL);

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

#ifdef TLSF_DEBUG
    tlsf_check(t);
#endif

    /* Fill with magic (only when testing up to 1MB). */
    uint8_t* data = (uint8_t*)p[i];
    if (spacelen <= 1024 * 1024)
      memset(data, 0, len);
    data[0] = 0xa5;

    if (i++ == maxitems)
      break;
  }

#ifdef TLSF_STATS
  tlsf_printstats(t);
#endif

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

#ifdef TLSF_DEBUG
    tlsf_check(t);
#endif
  }

#ifdef TLSF_STATT
  tlsf_printstats(t);
#endif

  tlsf_destroy(t);
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

int main(void) {
  srand((unsigned int)time(0));
  random_sizes_test();
  puts("OK!");
  return 0;
}
