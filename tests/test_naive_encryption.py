import random

import pkcs1.keys


def test_generate_and_encrypt():
    pub, priv = pkcs1.keys.generate_key_pair(number=5, size=1024)
    assert len(priv.primes) == 5
    assert priv.bit_size == 1024
    u = 3253254345435435
    assert priv.rsadp(pub.rsaep(u)) == u


def test_random_encrypt():
    pub, priv = pkcs1.keys.generate_key_pair(number=5, size=1024)
    for i in xrange(100):
        u = random.getrandbits(priv.bit_size - 1)
        assert priv.rsadp(pub.rsaep(u)) == u

try:
    xrange
except NameError:
    xrange = range
