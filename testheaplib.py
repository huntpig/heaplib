import unittest

from heaplib import HeapPayloadCrafter, HeaplibException

class HeaplibTest(unittest.TestCase):
    def setUp(self):
        self.hpc = HeapPayloadCrafter(0x41414141, 0x42424242)
        self.hpc_2 = HeapPayloadCrafter(0x41414141, 0x42424242, post_length=20, pre_length=20)

    def test_can_use_1(self):
        self.assertFalse(self.hpc.can_use("A**A", 0, 2))

    def test_can_use_2(self):
        self.assertFalse(self.hpc.can_use("AAAA", 0, 2))

    def test_populate_content_1(self):
        with self.assertRaises(HeaplibException):
            self.hpc.populate_content(length=120,
                                      presets={120: "A"})

    def test_populate_content_2(self):
        with self.assertRaises(HeaplibException):
            self.hpc.populate_content(length=120,
                                      presets={0:"A"*121})

    def test_populate_content_3(self):
        with self.assertRaises(HeaplibException):
            self.hpc.populate_content(length=120,
                                      presets={0: "AA", 1: "B"})

    def test_populate_content_4(self):
        with self.assertRaises(HeaplibException):
            self.hpc.populate_content(length=120,
                                      presets={120: "A"})

    def test_populate_content_5(self):
        with self.assertRaises(HeaplibException):
            self.hpc.populate_content(length=120,
                                      presets={-1: "A"})

    def test_populate_content_6(self):
        payload = self.hpc.populate_content(length=5,
                                            presets={2: "AA"})
        self.assertEquals(payload, list("**AA*"))

    def test_populate_content_7(self):
        with self.assertRaises(HeaplibException):
            self.hpc.populate_content(length=120,
                                      presets={119: "AA"})

    def test_generate_payload_1(self):
        prev, metadata, post = self.hpc_2.generate_payload()
        PREV_SIZE_C, SIZE_C = metadata
        self.assertEquals(PREV_SIZE_C, -1)
        self.assertEquals(SIZE_C, -4)
        self.assertEquals(prev, ['*', '*', '*', '*', '*', '*', '*', '*', '*', '*', '*', '*', '*', '*', '*', '*', '\xff', '\xff', '\xff', '\xff'])
        self.assertEquals(post, ['\xf0', '\xff', '\xff', '\xff', '\xf1', '\xff', '\xff', '\xff', '5', 'A', 'A', 'A', 'B', 'B', 'B', 'B', '*', '*', '*', '*'])
        self.assertEquals(len(prev), 20)
        self.assertEquals(len(post), 20)


if __name__ == '__main__':
    unittest.main()
