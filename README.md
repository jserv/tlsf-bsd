# tlsf: Two-Level Segregated Fit Memory Allocator

Two-Level Segregated Fit memory allocator implementation originally written by Matthew Conte
and heavily modified by Daniel Mendler. This code was based on the TLSF 1.4 spec and
documentation found at http://www.gii.upv.es/tlsf/main/docs.
The library is released under the BSD license.

Features
--------
  * O(1) cost for malloc, free, realloc
  * Low overhead per allocation (one word)
  * Low overhead for the TLSF metadata (~4kB)
  * Low fragmentation
  * Very small - only ~500 lines of code
  * Compiles to only a few kB of code and data
  * Requests memory from the os on demand via callback
  * Not designed to be thread safe; the user must provide this
