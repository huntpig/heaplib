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


if __name__ == '__main__':
    unittest.main()
