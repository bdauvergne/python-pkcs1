import unittest

from pkcs1 import rsassa_pkcs1_v15

import data

class RsassaPkcs1V15Tests(unittest.TestCase):
    data = data.RsassaPkcs1V15VectorsData()

    def test_rsassa_pkcs1_v15_sign(self):
        for example in self.data.examples:
            private_key = example.private_key
            for sample in example.samples:
                message = sample.message
                signature = sample.signature
                self.assertEqual(len(signature), private_key.byte_size)
                self.assertEqual(rsassa_pkcs1_v15.sign(private_key, message),
                        signature)

    def test_rsassa_pkcs1_v15_verify(self):
        for example in self.data.examples:
            public_key = example.public_key
            for sample in example.samples:
                message = sample.message
                signature = sample.signature
                self.assertEqual(len(signature), public_key.byte_size)
                self.assertTrue(rsassa_pkcs1_v15.verify(public_key, message,
                        signature))

