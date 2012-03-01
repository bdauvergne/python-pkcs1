import unittest
import os.path

import pkcs1
import pkcs1.encryption
import pkcs1.signature

from helper import TestVectors, SimpleObject

class Pkcsv15EncryptionData(TestVectors):
    path = os.path.join(os.path.dirname(__file__), 'data',
            'pkcs1v15crypt-vectors.txt')

    def parse(self, iterator):
        self.examples = []
        for j in range(15):
            self.parse_example(iterator)
            self.examples.append(SimpleObject(
                    public_key=self.public_key,
                    private_key=self.private_key,
                    samples=self.samples))

    def parse_example(self, iterator):
        grammar = (
                ('modulus', 'Modulus:'),
                ('public_exponent', 'Public exponent:'),
                ('exponent', 'Exponent:'))
        for name, token in grammar:
            setattr(self, name, self.jtrx(iterator, token))
        self.public_key = pkcs1.RsaPublicKey(self.modulus, self.public_exponent)
        self.private_key = pkcs1.RsaPrivateKey(self.modulus, self.exponent)
        pkcs1.check_rsa_keys_coherency(self.public_key, self.private_key)
        self.samples = []

        for j in range(20):
            self.parse_sample(iterator)
            self.samples.append(SimpleObject(**self.sample))

    def parse_sample(self, iterator):
        grammar = (
                ('message', 'Message:'),
                ('seed', 'Seed:'),
                ('encryption', 'Encryption:'))
        self.sample = {}
        for name, token in grammar:
            self.sample[name] = self.jtrs(iterator, token)

class Pkcsv15SignatureData(TestVectors):
    path = os.path.join(os.path.dirname(__file__), 'data',
            'pkcs1v15sign-vectors.txt')

    def parse(self, iterator):
        self.examples = []
        for j in range(15):
            self.parse_example(iterator)
            self.examples.append(SimpleObject(
                    public_key=self.public_key,
                    private_key=self.private_key,
                    samples=self.samples))

    def parse_example(self, iterator):
        grammar = (
                ('modulus', 'Modulus:'),
                ('public_exponent', 'Public exponent:'),
                ('exponent', 'Exponent:'))
        for name, token in grammar:
            setattr(self, name, self.jtrx(iterator, token))
        self.public_key = pkcs1.RsaPublicKey(self.modulus, self.public_exponent)
        self.private_key = pkcs1.RsaPrivateKey(self.modulus, self.exponent)
        pkcs1.check_rsa_keys_coherency(self.public_key, self.private_key)
        self.samples = []

        for j in range(20):
            self.parse_sample(iterator)
            self.samples.append(SimpleObject(**self.sample))

    def parse_sample(self, iterator):
        grammar = (
                ('message', 'Message to be signed:'),
                ('signature', 'Signature:'))
        self.sample = {}
        for name, token in grammar:
            self.sample[name] = self.jtrs(iterator, token)


class Pkcs15PaddingTests(unittest.TestCase):
    pkcs15_encryption_data = Pkcsv15EncryptionData()
    pkcs15_signature_data = Pkcsv15SignatureData()

    def test_encryption(self):
        for example in self.pkcs15_encryption_data.examples:
            public_key = example.public_key
            private_key = example.private_key
            for sample in example.samples:
                message = sample.message
                seed = sample.seed
                encryption = sample.encryption

                # internal coherency check
                self.assertEqual(len(message) + len(seed) + 3, len(encryption))
                self.assertEqual(
                        pkcs1.encryption.rsaes_pkcs1v15_encrypt(
                            public_key, message, ps=seed),
                        encryption)
                self.assertEqual(
                        pkcs1.encryption.rsaes_pkcs1v15_decrypt(
                            private_key, encryption),
                        message)

    def test_signature(self):
        for example in self.pkcs15_signature_data.examples:
            public_key = example.public_key
            private_key = example.private_key
            for sample in example.samples:
                message = sample.message
                signature = sample.signature
                self.assertEqual(len(signature), public_key.k)
                self.assertEqual(pkcs1.signature.rsassa_pkcs1_v15_sign(private_key, message),
                        signature)
                self.assertTrue(pkcs1.signature.rsassa_pkcs1_v15_verify(public_key, message,
                        signature))
