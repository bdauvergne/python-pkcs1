import math
import random
import fractions

from primes import get_prime, DEFAULT_ITERATION


'''Primitive functions extracted from the PKCS1 RFC'''

class RsaPublicKey(object):
    __slots__ = ('n', 'e', 'k')

    def __init__(self, n, e):
        self.k = integer_byte_size(n)
        self.n = n
        self.e = e

    def __repr__(self):
        return '<RsaPublicKey n: %d e: %d k: %d>' % (self.n, self.e, self.k)

class RsaPrivateKey(object):
    __slots__ = ('n', 'd', 'k')

    def __init__(self, n, d):
        self.k = integer_byte_size(n)
        self.n = n
        self.d = d

    def __repr__(self):
        return '<RsaPrivateKey n: %d d: %d k: %d>' % (self.n, self.d, self.k)


def integer_ceil(a, b):
    b = int(b)
    x = a % b
    if x > 0:
        return int(a) / b + 1
    else:
        return int(a) / b

def integer_byte_size(n):
    return integer_ceil(math.log(n, 2), 8)

def euclide_gcd(a,b):
    if a > b:
        x, y, h = euclide_gcd(b, a)
        return y, x, h
    c = b // a
    b = b % a
    if b == 0:
        return 1, 0, a
    x, y, h = euclide_gcd(a, b)
    return x-c*y, y, h


def i2osp(x, x_len):
    if x > 256**x_len:
        raise ValueError('integer too large')
    h = hex(x)[2:]
    if h[-1] == 'L':
        h = h[:-1]
    if len(h) & 1 == 1:
        h = '0%s' % h
    x = h.decode('hex')
    return '\x00' * int(x_len-len(x)) + x

def os2ip(x):
    h = x.encode('hex')
    return int(h, 16)

def rsaep(public_key, m):
    if not (0 <= m <= public_key.n-1):
        raise ValueError('message representative out of range')
    return pow(m, public_key.e, public_key.n)

def rsadp(private_key, c):
    if not (0 <= c <= private_key.n-1):
        raise ValueError('ciphertext representative out of range')
    return pow(c, private_key.d, private_key.n)

def rsasp1(private_key, m):
    if not (0 <= m <= private_key.n-1):
        raise ValueError('message representative out of range')
    return rsadp(private_key, m)

def rsavp1(public_key, s):
    if not (0 <= s <= public_key.n-1):
        raise ValueError('signature representative out of range')
    return rsaep(public_key, s)

def string_xor(a, b):
    return ''.join((chr(ord(x) ^ ord(y)) for (x,y) in zip(a,b)))

def generate_key_pair(size=512, random=random.SystemRandom, k=DEFAULT_ITERATION):
    print 'generating first prime'
    p = get_prime(size, random, k)
    print 'generating second prime'
    q = get_prime(size, random, k)
    n = p*q
    lbda = (p-1)*(q-1)
    print 'generating e'
    e = 0x10001
    while e < lbda:
        if fractions.gcd(e, lbda) == 1:
            break
        e += 2
    d, y, z = euclide_gcd(e, lbda)
    assert z == 1
    if d < 0:
        d += lbda
    assert (d*e) % lbda == 1
    public, private = RsaPublicKey(n, e), RsaPrivateKey(n, d)
    assert check_rsa_keys_coherency(public, private)
    return public, private

def check_rsa_keys_coherency(public_key, private_key):
    '''Check that the public and private key match each other'''
    return public_key.n == private_key.n
