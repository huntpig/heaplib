
from heaplib import HeapPayloadCrafter, HeaplibException

from pwn import *

context.arch = "i386"

hpc = HeapPayloadCrafter(0x41414141, 0x42424242, post_length=20, pre_length=20)
prev, metadata, post = hpc.generate_payload()
PREV_SIZE_C, SIZE_C = metadata
print "-=====================]"
print "Crafted Metadata"
print "PREV_SIZE_C    = %s    %d" %(repr(pack(PREV_SIZE_C)), PREV_SIZE_C)
print "SIZE_C         = %s    %d" %(repr(pack(SIZE_C)), SIZE_C)
print "-=====================]"
print "PREV"
print repr(prev)
print "-=====================]"
print "POST"
print repr(post)


#hpc = HeapPayloadCrafter(0x41414141, 0x42424242, post_length=20, pre={0: "Z"*4}, pre_length=100)
#print hpc.generate_payload()

#hpc = HeapPayloadCrafter(0x41414141, 0x42424242, post_length=20, pre={0: "Z"*5}, pre_length=100)
#print hpc.generate_payload()
