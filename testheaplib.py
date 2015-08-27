import unittest

from heaplib import HeapPayloadCrafter, HeaplibException

class HeaplibTest(unittest.TestCase):
    def setUp(self):
        self.hpc = HeapPayloadCrafter(0x41414141, 0x42424242)

    def test_can_use_1(self):
        self.assertFalse(self.hpc.can_use("A**A", 0, 2))

    def test_can_use_2(self):
        self.assertFalse(self.hpc.can_use("AAAA", 0, 2))

    def test_populate_content_1(self):
        with self.assertRaises(HeaplibException):
            self.hpc.populate_content(bytes_to_nextheader=120,
                                      preset_content={120: "A"})

    def test_populate_content_2(self):
        with self.assertRaises(HeaplibException):
            self.hpc.populate_content(bytes_to_nextheader=120,
                                      preset_content={0:"A"*121})

    def test_populate_content_3(self):
        with self.assertRaises(HeaplibException):
            self.hpc.populate_content(bytes_to_nextheader=120,
                                      preset_content={0: "AA", 1: "B"})

    def test_populate_content_4(self):
        with self.assertRaises(HeaplibException):
            self.hpc.populate_content(bytes_to_nextheader=120,
                                      preset_content={120: "A"})

    def test_populate_content_5(self):
        with self.assertRaises(HeaplibException):
            self.hpc.populate_content(bytes_to_nextheader=120,
                                      preset_content={-1: "A"})

    def test_populate_content_6(self):
        payload = self.hpc.populate_content(bytes_to_nextheader=5,
                                            preset_content={2: "AA"})
        self.assertEquals(payload, list("**AA*"))

    def test_populate_content_7(self):
        with self.assertRaises(HeaplibException):
            self.hpc.populate_content(bytes_to_nextheader=120,
                                      preset_content={119: "AA"})


if __name__ == '__main__':
    unittest.main()
