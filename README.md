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

## Reference

M. Masmano, I. Ripoll, A. Crespo, and J. Real.
TLSF: a new dynamic memory allocator for real-time systems.
In Proc. ECRTS (2004), IEEE Computer Society, pp. 79-86.

## Licensing

TLSF-BSD is freely redistributable under the 3-clause BSD License.
Use of this source code is governed by a BSD-style license that can be found
in the `LICENSE` file.
