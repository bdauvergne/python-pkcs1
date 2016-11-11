import functools

from pkcs1 import emsa_pss
from pkcs1 import rsassa_pss
from pkcs1 import keys

import data

int_data = data.PssIntData()
vect_data = data.PssVectData()


def test_rsassa_pss_sign_int():
    # specialize the generic encoding function for the test vector salt
    emsa_pss_encode = functools.partial(emsa_pss.encode, salt=int_data.salt)
    signature = rsassa_pss.sign(int_data.private_key, int_data.message,
                                emsa_pss_encode=emsa_pss_encode)
    assert signature == int_data.signature


def test_rsassa_pss_verify_int():
    result = rsassa_pss.verify(int_data.public_key, int_data.message, int_data.signature)
    assert result


def test_rsassa_pss_sign_vect():
    for example in vect_data.examples:
        private_key = example.private_key
        for sample in example.samples:
            emsa_pss_encode = functools.partial(emsa_pss.encode, salt=sample.salt)
            signature = rsassa_pss.sign(private_key, sample.message,
                                        emsa_pss_encode=emsa_pss_encode)
            assert signature == sample.signature


def test_rsassa_pss_verify_vect():
    for example in vect_data.examples:
        public_key = example.public_key
        for sample in example.samples:
            result = rsassa_pss.verify(public_key, sample.message, sample.signature)
            assert result


def test_generate_and_sign():
    pub, priv = keys.generate_key_pair(number=5, size=1024)
    message = b'hello world'
    signature = rsassa_pss.sign(priv, message)
    assert rsassa_pss.verify(pub, message, signature)
