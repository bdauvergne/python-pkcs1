import unittest

from pkcs1 import rsaes_oaep

import data

class OaepTests(unittest.TestCase):
    oaep_int_data = data.OaepIntData()
    oaep_vect_data = data.OaepVectData()

    def test_oaep_int_encryption(self):
        data = self.oaep_int_data
        encrypted = rsaes_oaep.encrypt(data.public_key, data.message,
                seed=data.seed)
        self.assertEqual(data.encrypted, encrypted)

    def test_oaep_int_decryption(self):
        data = self.oaep_int_data
        message = rsaes_oaep.decrypt(data.private_key, data.encrypted)
        self.assertEqual(data.message, message)

    def test_oaep_vect_encryption(self):
        data = self.oaep_vect_data
        for example in data.examples:
            public_key = example.public_key
            for sample in example.samples:
                encrypted = rsaes_oaep.encrypt(public_key,
                        sample.message, seed=sample.seed)
                self.assertEqual(sample.encrypted, encrypted)

    def test_oaep_vect_decryption(self):
        data = self.oaep_vect_data
        for example in data.examples:
            private_key = example.private_key
            for sample in example.samples:
                message = rsaes_oaep.decrypt(private_key,
                        sample.encrypted)
                self.assertEqual(sample.message, message)
