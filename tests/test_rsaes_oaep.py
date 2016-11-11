from pkcs1 import rsaes_oaep

import data

oaep_int_data = data.OaepIntData()
oaep_vect_data = data.OaepVectData()


def test_oaep_int_encryption():
    data = oaep_int_data
    encrypted = rsaes_oaep.encrypt(data.public_key, data.message, seed=data.seed)
    assert data.encrypted == encrypted


def test_oaep_int_decryption():
    data = oaep_int_data
    message = rsaes_oaep.decrypt(data.private_key, data.encrypted)
    assert data.message == message


def test_oaep_vect_encryption():
    data = oaep_vect_data
    for example in data.examples:
        public_key = example.public_key
        for sample in example.samples:
            encrypted = rsaes_oaep.encrypt(public_key, sample.message, seed=sample.seed)
            assert sample.encrypted == encrypted


def test_oaep_vect_decryption():
    data = oaep_vect_data
    for example in data.examples:
        private_key = example.private_key
        for sample in example.samples:
            message = rsaes_oaep.decrypt(private_key, sample.encrypted)
            assert sample.message == message
