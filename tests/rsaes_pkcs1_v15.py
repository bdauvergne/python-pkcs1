import unittest

from pkcs1 import rsaes_pkcs1_v15

import data

class RsaesPkcs1V15Tests(unittest.TestCase):
    data = data.RsaesPkcs1V15VectorsData()

    def test_rsaes_pkcs1_v15_encrypt(self):
        for example in self.data.examples:
            public_key = example.public_key
            for sample in example.samples:
                message = sample.message
                seed = sample.seed
                encryption = sample.encryption

                # internal coherency check
                self.assertEqual(len(message) + len(seed) + 3, len(encryption))
                self.assertEqual( rsaes_pkcs1_v15.encrypt( public_key, message,
                    ps=seed), encryption)

    def test_rsaes_pkcs1_v15_decrypt(self):
        for example in self.data.examples:
            private_key = example.private_key
            for sample in example.samples:
                message = sample.message
                seed = sample.seed
                encryption = sample.encryption

                # internal coherency check
                self.assertEqual(len(message) + len(seed) + 3, len(encryption))
                self.assertEqual( rsaes_pkcs1_v15.decrypt( private_key,
                    encryption), message)
