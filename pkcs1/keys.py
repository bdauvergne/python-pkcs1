import primitives
import exceptions

class RsaPublicKey(object):
    __slots__ = ('n', 'e', 'bit_size', 'byte_size')

    def __init__(self, n, e):
        self.n = n
        self.e = e
        self.bit_size = primitives.integer_bit_size(n)
        self.byte_size = primitives.integer_byte_size(n)


    def __repr__(self):
        return '<RsaPublicKey n: %d e: %d bit_size: %d>' % (self.n, self.e, self.bit_size)

    def rsavp1(self, s):
        if not (0 <= s <= self.n-1):
            raise exceptions.SignatureRepresentativeOutOfRange
        return self.rsaep(s)

    def rsaep(self, m):
        if not (0 <= m <= self.n-1):
            raise exceptions.MessageRepresentativeOutOfRange
        return primitives._pow(m, self.e, self.n)

class RsaPrivateKey(object):
    __slots__ = ('n', 'd', 'bit_size', 'byte_size')

    def __init__(self, n, d):
        self.n = n
        self.d = d
        self.bit_size = primitives.integer_bit_size(n)
        self.byte_size = primitives.integer_byte_size(n)

    def __repr__(self):
        return '<RsaPrivateKey n: %d d: %d bit_size: %d>' % (self.n, self.d, self.bit_size)

    def rsadp(self, c):
        if not (0 <= c <= self.n-1):
            raise exceptions.CiphertextRepresentativeOutOfRange
        return primitives._pow(c, self.d, self.n)

    def rsasp1(self, m):
        if not (0 <= m <= self.n-1):
            raise exceptions.MessageRepresentativeOutOfRange
        return self.rsadp(m)
