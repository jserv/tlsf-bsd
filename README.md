# tlsf-bsd: Two-Level Segregated Fit Memory Allocator

Two-Level Segregated Fit memory allocator implementation derived from the BSD-licensed implementation by [Matthew Conte](https://github.com/mattconte/tlsf).
This code was based on the [TLSF documentation](http://www.gii.upv.es/tlsf/main/docs).

This implementation was written to the specification of the document,
therefore no GPL restrictions apply.

## Features
* O(1) cost for `malloc`, `free`, `realloc`, `aligned_alloc`
* Low overhead per allocation (one word)
* Low overhead for the TLSF metadata (~4kB)
* Low fragmentation
* Very small - only ~500 lines of code
* Compiles to only a few kB of code and data
* Uses a linear memory area, which is resized on demand
* Not thread safe. API calls must be protected by a mutex in a multi-threaded environment.
* Works in environments with only minimal libc, uses only `stddef.h`, `stdbool.h`, `stdint.h` and `string.h`.

## How it works

This package offers constant, O(1)-time memory block allocation and deallocation.

The structure consists of an array indexed by `log(2, request_size)`.
In other words, requests are divided up according to the requsted size's most significant bit (MSB).
A pointer to the second level of the structure is contained in each item of the array.
At this level, the free blocks of each slab size are divided into x additional groups,
where x is a configurable number.
An array of size x that implements this partitioning is indexed by taking the value of the `log(2, x)` bits that follow the MSB.
Each value denotes the start of a linked list of free blocks (or is `NULL`).

Finding a free block in the correctly sized class (or, if none are available, in a larger size class) in constant time requires using the bitmaps representing the availability of free blocks (of a certain size class).

When `tlsf_free()` is called, the block examines if it may coalesce with nearby free blocks before returning to the free list.
```
+--------------------------------------------------------------------+
| Main structure:                                                    |
|   Segregated List(array of pointers to second levels)              |
|   Bitmap showing which levels have free blocks                     |
|                                                                    |
|     Blocks fit into different size ranges:                         |
|                                                                    |
|       |2^31|...|2^9|2^8|2^7|2^6|2^5|2^4                            |
+--------------------------------------------------------------------+
                            |       |
                            |       |       +-----------------------+
                            |       |       | Level Two             |
+-----------------------+   |       +-----> |   Array of free lists |
| Level Two             |<--+               |   Bitmap              |
|   Array of free lists |                   +-----------------------+
|   bitmaps             |
|   |   |   ... |   |   |
+-----------------------+
    |       \
    |        \
+-----------+  +------------+
| Free_Block | | Free_Block |
|            | |            |
|            | |            |
+------------+ +------------+
      |
      |
      |
+------------+
| Free_Block |
|            |
|            |
+------------+
```

## Reference

M. Masmano, I. Ripoll, A. Crespo, and J. Real.
TLSF: a new dynamic memory allocator for real-time systems.
In Proc. ECRTS (2004), IEEE Computer Society, pp. 79-86.

## Licensing

TLSF-BSD is freely redistributable under the 3-clause BSD License.
Use of this source code is governed by a BSD-style license that can be found
in the `LICENSE` file.
