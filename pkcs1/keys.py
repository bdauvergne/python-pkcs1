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

class MultiPrimeRsaPrivateKey(object):
    __slots__ = ('primes', 'blind', 'blind_inv', 'n', 'e', 'exponents', 'crts', 'bit_size', 'byte_size')

    def __init__(self, primes, e):
        self.primes = primes
        self.n = primitives.product(*primes)
        self.e = e
        self.bit_size = primitives.integer_bit_size(self.n)
        self.byte_size = primitives.integer_byte_size(self.n)
        self.exponents = []
        for prime in primes:
            exponent, a, b = primitives.bezout(e, prime-1)
            assert b == 1
            if exponent < 0:
                exponent += prime-1
            self.exponents.append(exponent)
        self.crts = [1]
        R = primes[0]
        for prime in primes[1:]:
            crt, a, b = primitives.bezout(R, prime)
            assert b == 1
            R *= prime
            self.crts.append(crt)
        self.blind = None
        self.blind_inv = None


    def __repr__(self):
        return '<RsaPrivateKey n: %d primes: %s bit_size: %d>' % (self.n, self.primes, self.bit_size)


    def rsadp(self, c):
        if not (0 <= c <= self.n-1):
            raise exceptions.CiphertextRepresentativeOutOfRange
        R = 1
        m = 0
        if self.blind:
            c = (c * self.blind) % self.n
        for prime, exponent, crt in zip(self.primes, self.exponents, self.crts):
            m_i = primitives._pow(c, exponent, prime)
            h = ((m_i - m) * crt) % prime
            m += R * h
            R *= prime
        if self.blind_inv:
            m = (m * self.blind_inv) % self.n
        return m

    def rsasp1(self, m):
        if not (0 <= m <= self.n-1):
            raise exceptions.MessageRepresentativeOutOfRange
        return self.rsadp(m)
