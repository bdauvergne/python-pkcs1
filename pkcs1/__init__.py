# n = p * q
# \lambda(n) = (p-1)*(q-1)
# e * d == 1 mod \lambda(n) 

def i2osp(x, x_len):
    if x > 256**x_len:
        raise ValueError('x is too big')
    h = hex(x)[2:]
    if h[-1] == 'L':
        h = h[:-1]
    if len(h) & 1 == 1:
        h = '0%s' % h
    x = h.decode('hex')
    return '\x00' * (x_len-len(x))+x

def os2ip(x):
    h = x.encode('hex')
    return int(h, 16)

def rsaep(public_key, m):
    return pow(m, public_key.e, public_key.n)

def rsadp(private_key, c):
    if c < 0 or c >= private_key.n:
        raise ValueError('ciphertext representative out of range')
    return pow(c, private_key.d, private_key.n)

def rsasp1(private_key, m):
    return rsadp(private_key, m)

def rsavp1(public_key, c):
    return rsaep(public_key, c)


class PublicKey(object):
    __slots__ = ('n', 'e')

    def __init__(self, n, e):
        self.n = n
        self.e = e

class PrivateKey(object):
    __slots__ = ('n', 'd')

    def __init__(self, n, d):
        self.n = n
        self.e = d

if __name__ == '__main__':
    print repr(i2osp(12, 3))
    print os2ip(i2osp(12, 3))

