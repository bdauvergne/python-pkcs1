from pkcs1 import rsaes_pkcs1_v15

import data

data = data.RsaesPkcs1V15VectorsData()


def test_rsaes_pkcs1_v15_encrypt():
    for example in data.examples:
        public_key = example.public_key
        for sample in example.samples:
            message = sample.message
            seed = sample.seed
            encryption = sample.encryption

            # internal coherency check
            assert len(message) + len(seed) + 3 == len(encryption)
            assert rsaes_pkcs1_v15.encrypt(public_key, message, ps=seed) == encryption


def test_rsaes_pkcs1_v15_decrypt():
    for example in data.examples:
        private_key = example.private_key
        for sample in example.samples:
            message = sample.message
            seed = sample.seed
            encryption = sample.encryption

            # internal coherency check
            assert len(message) + len(seed) + 3 == len(encryption)
            assert rsaes_pkcs1_v15.decrypt(private_key, encryption) == message
