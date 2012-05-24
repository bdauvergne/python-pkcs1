import unittest
import pkcs1
import pkcs1.oaep

class OaepTests(unittest.TestCase):
    def test_encryption1(self):
        modulus = 'bbf82f090682ce9c2338ac2b9da871f7368d07eed41043a440d6b6f07454f51fb8dfbaaf035c02ab61ea48ceeb6fcd4876ed520d60e1ec4619719d8a5b8b807fafb8e0a3dfc737723ee6b4b7d93a2584ee6a649d060953748834b2454598394ee0aab12d7b61a51f527a9a41f6c1687fe2537298ca2a8f5946f8e5fd091dbdcb'
        exponent = '11'
        public_key = pkcs1.RsaPublicKey(int(modulus, 16), int(exponent, 16))
        message = '\xd4\x36\xe9\x95\x69\xfd\x32\xa7\xc8\xa0\x5b\xbc\x90\xd3\x2c\x49'
        seed = '\xaa\xfd\x12\xf6\x59\xca\xe6\x34\x89\xb4\x79\xe5\x07\x6d\xde\xc2\xf0\x6c\xb5\x8f'
        pkcs1.oaep.rsaes_oaep_encrypt(public_key, message, seed=seed)

