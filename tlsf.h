#ifndef _TLSF_H
#define _TLSF_H

/*
 * Two Level Segregated Fit memory allocator.
 * Written by Matthew Conte.
 * Maintained by Daniel Mendler.
 *
 * Based on the original documentation by Miguel Masmano:
 *  http://www.gii.upv.es/tlsf/main/docs
 *
 * This implementation was written to the specification
 * of the document, therefore no GPL restrictions apply.
 *
 * Copyright (c) 2006-2016, Matthew Conte
 * Copyright (c) 2017, Daniel Mendler
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL MATTHEW CONTE BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stddef.h>

// Ensure that __WORDSIZE is defined
#ifndef __WORDSIZE
#  include <sys/reg.h> // needed by musl
#  ifndef __WORDSIZE
#    error __WORDSIZE is not defined
#  endif
#endif

#if __WORDSIZE == 64
#  define TLSF_MAX_SHIFT 36 // 64G
#elif __WORDSIZE == 32
#  define TLSF_MAX_SHIFT 29 // 512M
#else
#  error __WORDSIZE must be 32 or 64
#endif

// Maximum allocation size
#define TLSF_MAX_SIZE  ((1UL << TLSF_MAX_SHIFT) - sizeof (size_t))

// Flags
#define TLSF_DEFAULT 0
#define TLSF_NOMAP   1
#define TLSF_ZERO    2
#define TLSF_INPLACE 4

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tlsf_s* tlsf_t;

typedef void* (*tlsf_map_t)(size_t* size, void* user);
typedef void  (*tlsf_unmap_t)(void* mem, size_t size, void* user);

tlsf_t tlsf_create(tlsf_map_t map, tlsf_unmap_t unmap, void* user);
void   tlsf_destroy(tlsf_t t);
void   tlsf_free(tlsf_t t, void* mem);
void*  tlsf_mallocx(tlsf_t t, size_t size, int flags);
void*  tlsf_reallocx(tlsf_t t, void* mem, size_t size, int flags);

static inline void* tlsf_malloc(tlsf_t t, size_t size) {
  return tlsf_mallocx(t, size, TLSF_DEFAULT);
}

static inline void* tlsf_calloc(tlsf_t t, size_t size) {
  return tlsf_mallocx(t, size, TLSF_ZERO);
}

static inline void* tlsf_realloc(tlsf_t t, void* mem, size_t size) {
  return tlsf_reallocx(t, mem, size, TLSF_DEFAULT);
}

#ifdef TLSF_STATS
typedef struct {
  size_t free_size;
  size_t used_size;
  size_t total_size;
  size_t pool_count;
  size_t malloc_count;
  size_t free_count;
} tlsf_stats_t;

const tlsf_stats_t* tlsf_stats(tlsf_t t);
void tlsf_printstats(tlsf_t t);
#endif

#ifdef TLSF_DEBUG
void tlsf_check(tlsf_t t);
#endif

#ifdef __cplusplus
}
#endif

#endif
