# tlsf: Two-Level Segregated Fit Memory Allocator

Two-Level Segregated Fit memory allocator implementation originally written by Matthew Conte (matt@baisoku.org)
and heavily modified by Daniel Mendler (mail@daniel-mendler.de).
This code was based on the TLSF 1.4 spec and documentation found at http://www.gii.upv.es/tlsf/main/docs
It also leverages the TLSF 2.0 improvement to shrink the per-block overhead from 8 to 4 bytes.
The library is released under the BSD license.

Features
--------
  * O(1) cost for malloc, free, realloc
  * Extremely low overhead per allocation (one word)
  * Low overhead for the TLSF metadata (~4kB)
  * Low fragmentation
  * Compiles to only a few kB of code and data
  * Requests memory from the os on demand via callback
  * Not designed to be thread safe; the user must provide this
