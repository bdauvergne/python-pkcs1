import unittest
import functools

from pkcs1 import emsa_pss
from pkcs1 import rsassa_pss
from pkcs1 import keys

import data

class RsassaPssTests(unittest.TestCase):
    int_data = data.PssIntData()
    vect_data = data.PssVectData()

    def test_rsassa_pss_sign_int(self):
        # specialize the generic encoding function for the test vector salt
        emsa_pss_encode = functools.partial(emsa_pss.encode,
                salt=self.int_data.salt)
        signature = rsassa_pss.sign(self.int_data.private_key,
                self.int_data.message, emsa_pss_encode=emsa_pss_encode)
        self.assertEqual(signature, self.int_data.signature)

    def test_rsassa_pss_verify_int(self):
        result = rsassa_pss.verify(self.int_data.public_key,
                self.int_data.message, self.int_data.signature)
        self.assertTrue(result)

    def test_rsassa_pss_sign_vect(self):
        for example in self.vect_data.examples:
            private_key = example.private_key
            for sample in example.samples:
                emsa_pss_encode = functools.partial(emsa_pss.encode,
                        salt=sample.salt)
                signature = rsassa_pss.sign(private_key,
                        sample.message, emsa_pss_encode=emsa_pss_encode)
                self.assertEqual(signature, sample.signature)

    def test_rsassa_pss_verify_vect(self):
        for example in self.vect_data.examples:
            public_key = example.public_key
            for sample in example.samples:
                result = rsassa_pss.verify(public_key, sample.message, sample.signature)
                self.assertTrue(result)

    def test_generate_and_sign(self):
        pub, priv = keys.generate_key_pair(number=5, size=1024)
        message = 'hello world'
        signature = rsassa_pss.sign(priv, message)
        self.assertTrue(rsassa_pss.verify(pub, message, signature))
