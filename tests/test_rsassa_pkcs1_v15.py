from pkcs1 import rsassa_pkcs1_v15

import data

data = data.RsassaPkcs1V15VectorsData()


def test_rsassa_pkcs1_v15_sign():
    for example in data.examples:
        private_key = example.private_key
        for sample in example.samples:
            message = sample.message
            signature = sample.signature
            assert len(signature) == private_key.byte_size
            assert rsassa_pkcs1_v15.sign(private_key, message) == signature


def test_rsassa_pkcs1_v15_verify():
    for example in data.examples:
        public_key = example.public_key
        for sample in example.samples:
            message = sample.message
            signature = sample.signature
            assert len(signature) == public_key.byte_size
            assert rsassa_pkcs1_v15.verify(public_key, message, signature)
