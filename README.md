# tlsf: Two-Level Segregated Fit Memory Allocator

Two-Level Segregated Fit memory allocator implementation derived from the BSD-licensed implementation by Matthew Conte.
This code was based on the TLSF 1.4 spec and documentation found at http://www.gii.upv.es/tlsf/main/docs.

Features
--------
  * O(1) cost for malloc, free, realloc, aligned_alloc
  * Low overhead per allocation (one word)
  * Low overhead for the TLSF metadata (~4kB)
  * Low fragmentation
  * Very small - only ~500 lines of code
  * Compiles to only a few kB of code and data
  * Uses a linear memory area, which is resized on demand
  * Not thread safe. API calls must be protected by a mutex in a multi-threaded environment.
  * Works in environments with only minimal libc, uses only stddef.h, stdbool.h, stdint.h and string.h.

