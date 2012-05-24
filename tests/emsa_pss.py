import unittest
import os.path
import functools

import pkcs1
import pkcs1.emsa_pss
import pkcs1.rsassa_pss
import pkcs1.primitives

from helper import TestVectors

class EmsaPssData(TestVectors):
    path = os.path.join(os.path.dirname(__file__), 'data',
            'pss-int.txt')

    def parse(self, iterator):
        grammar = (
                ('modulus', 'Modulus', 1),
                ('public_exponent', 'Public exponent', 1),
                ('exponent', 'Exponent', 1),
                ('message', 'Message to be signed', 0),
                ('m_hash', 'Message hash', 0),
                ('salt', 'salt', 0),
                ('encoded', 'EM =', 0),
                ('signature', 'Signature', 0))
        for name, token, is_long in grammar:
            if is_long:
                setattr(self, name, self.jtrx(iterator, token))
            else:
                setattr(self, name, self.jtrs(iterator, token))

        self.public_key = pkcs1.RsaPublicKey(self.modulus, self.public_exponent)
        self.private_key = pkcs1.RsaPrivateKey(self.modulus, self.exponent)

class EmsaPssTests(unittest.TestCase):
    data = EmsaPssData()

    def test_emsa_pss(self):
        embits = self.data.public_key.k*8-1
        em = pkcs1.emsa_pss.emsa_pss_encode(self.data.message, embits,
                salt=self.data.salt)
        self.assertEqual(em, self.data.encoded)
        self.assertTrue(pkcs1.emsa_pss.emsa_pss_verify(self.data.message,
            em, embits, s_len=len(self.data.salt)))

    def test_rsassa_pss(self):
        emsa_pss_encode = functools.partial(pkcs1.emsa_pss.emsa_pss_encode,
                salt=self.data.salt)
        signature = pkcs1.rsassa_pss.rsassa_pss_sign(self.data.private_key,
                self.data.message, emsa_pss_encode=emsa_pss_encode)
        self.assertEqual(signature, self.data.signature)
        result = pkcs1.rsassa_pss.rsassa_pss_verify(self.data.public_key, self.data.message, signature)
        self.assertTrue(result)
