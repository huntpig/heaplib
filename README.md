# Heaplib

## What is heaplib?
Heaplib is a library aimed at aiding you in writing heap exploits
for dlmalloc. Currently, it has support for overwriting addresses
using backward consolidation only, though we plan to add support
for overwrites using forward consolidation too. Currently, its written
for the dlmalloc allocator(without the security checks upon unlink).

## How can I use the library?
I'm glad you asked. For a PoC, feel free to check out
https://github.com/eQu1NoX/heaplib/blob/master/sploit.py.

## O..k, so what exactly does it help me with?
Currently, heaplib assumes a rather simplistic model for heap
exploitation. In order to perform heap exploitation, you are required
to overwrite the metadata of an object that is about to be freed, such
that the metadata of that object can be controlled.

Lets use a few names, shall we.

Let "C" denote the chunk that is about to be freed(whose metadata we are
are able to overwrite). Let "BEFORE_C" denote the "fake crafted chunk"
that is placed somewhere in memory, such that free() thinks it is the
free chunk ... well, just behind "C". Let "AFTER_C" denote the "fake
crafted chunk" that is place somewhere in memory, such that free()
thinks it is the free chunk just after "C".

When performing a simple heap exploit, you typically want your input
to "overflow" into the metadata of "C". Hence, we can divide our input
into 3 sections.

1. PREV : This is the part of the input that lets you reach the
   metadata. For eg: suppose you need 32 bytes to reach the metadata of
   "C", the length of PREV would be 32 bytes.
2. METADATA : This is tuple of length two, containing the PREV_SIZE and
   SIZE values that will be used to overwrite the metadata of "C".
3. POST : This is the part of the input after the metadata that contains
  the crafted free block.

## Right, so how do I use the API?
First you create an instance of heaplib as follows:

```python
hpc = HeapPayloadCrafter(ADDRESS_TO_OVERWRITE, VALUE_TO_OVERWRITE_WITH,
                         post_length=32, pre_length=32,
                         pre_presets={31, "b"},
                         post_presets={0:"a"})
prev, metadata, post = hpc.generate_payload()
PREV_SIZE_C, SIZE_C = metadata
```

The first argument to HeapPayloadCrafter is the memory location you wish
to overwrite. The second argument is the value you with to overwrite it
with. The third argument is the number of bytes required to reach the
metadata of "C". The fourth argument is the number of bytes you have
available for use after the metadata of "C". The fifth and sixth
arguments are preset values for strings that need to be present in prev
or post. For eg: the nature of your application might require that you
need a "/" at the end of "PREV". Heaplib lets you tell it what your
presets are, and then crafts blocks to overwrite the memory addresses of
your choosing.

## Hmm, interesting. What are your future plans to do with this code?
Well, try to integrate it into something like
https://github.com/binjitsu/binjitsu once the codebase is cleaned up.
Also, take care of the Issues/Features listed out at
https://github.com/eQu1NoX/heaplib/issues.
