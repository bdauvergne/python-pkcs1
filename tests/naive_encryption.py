import unittest
import random

import pkcs1.keys

class NaiveEncryptionTests(unittest.TestCase):
    def test_generate_and_encrypt(self):
        pub, priv = pkcs1.keys.generate_key_pair(number=5, size=1024)
        self.assertEqual(len(priv.primes), 5)
        self.assertEqual(priv.bit_size, 1024)
        u = 3253254345435435
        self.assertEqual(priv.rsadp(pub.rsaep(u)), u)

    def test_random_encrypt(self):
        pub, priv = pkcs1.keys.generate_key_pair(number=5, size=1024)
        for i in xrange(100):
            u = random.getrandbits(priv.bit_size-1)
            self.assertEqual(priv.rsadp(pub.rsaep(u)), u)
