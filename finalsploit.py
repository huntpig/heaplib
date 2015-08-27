
from pwn import *
from heaplib import HeapFrame


"""
- Give in input of size 128 such that :
    - starts with FSRD
    - has a "/" somewhere(lets call this point "s")
    - has a "ROOT" before the "/"
    - pointer named `start` moves backward till it finds a "/"(lets call this point "d")
    - after "d" we probably have the metadata for the next block that we can overwrite,
      by placing it at "s"(it will get copied from d onward into the metadata)
    - However, that means we cannot use PREV_SIZE of "c" as the "SIZE" of chunk after c.

    => We need to be able to place the following at programmable offsets
        => crafted chunk
        => chunk after c
    => Also we need to stop using PREV_SIZE of c as SIZE of chunk after c

    Need someway to specify a string such that we can say what goes where
"""
