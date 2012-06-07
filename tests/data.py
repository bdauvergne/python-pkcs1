import os.path

import pkcs1

class SimpleObject(object):
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class TestVectors(object):
    '''Helper class to implement parser for the test vector files provided by
       RSA laboratories.
    '''
    def __init__(self):
        txt = file(self.path).read()
        iterator = iter(txt.splitlines())
        self.parse(iterator)

    def jump_to(self, iterator, token):
        while True:
            s = next(iterator)
            if token in s:
                break

    def read_hex_string(self, iterator):
        s = []
        while True:
            l = next(iterator).strip()
            if not l:
                break
            s.append(l)
        s = ''.join(s)
        s = s.replace(' ', '')
        return s

    def read_hex_number(self, iterator):
        return int(self.read_hex_string(iterator), 16)

    def read_hex_octet_string(self, iterator):
        return self.read_hex_string(iterator).decode('hex')

    def jtrx(self, iterator, token):
        self.jump_to(iterator, token)
        return self.read_hex_number(iterator)

    def jtrs(self, iterator, token):
        self.jump_to(iterator, token)
        return self.read_hex_octet_string(iterator)

class PssIntData(TestVectors):
    path = os.path.join(os.path.dirname(__file__), 'data',
            'pss-int.txt')

    def parse(self, iterator):
        grammar = (
                ('modulus', 'Modulus', 1),
                ('public_exponent', 'Public exponent', 1),
                ('exponent', 'Exponent', 1),
                ('message', 'Message to be signed', 0),
                ('m_hash', 'Message hash', 0),
                ('salt', 'salt', 0),
                ('encoded', 'EM =', 0),
                ('signature', 'Signature', 0))
        for name, token, is_long in grammar:
            if is_long:
                setattr(self, name, self.jtrx(iterator, token))
            else:
                setattr(self, name, self.jtrs(iterator, token))

        self.public_key = pkcs1.keys.RsaPublicKey(self.modulus, self.public_exponent)
        self.private_key = pkcs1.keys.RsaPrivateKey(self.modulus, self.exponent)

class RsaesPkcs1V15VectorsData(TestVectors):
    path = os.path.join(os.path.dirname(__file__), 'data',
            'pkcs1v15crypt-vectors.txt')

    def parse(self, iterator):
        self.examples = []
        for j in range(15):
            self.parse_example(iterator)
            self.examples.append(SimpleObject(
                    public_key=self.public_key,
                    private_key=self.private_key,
                    samples=self.samples))

    def parse_example(self, iterator):
        grammar = (
                ('modulus', 'Modulus:'),
                ('public_exponent', 'Public exponent:'),
                ('exponent', 'Exponent:'))
        for name, token in grammar:
            setattr(self, name, self.jtrx(iterator, token))
        self.public_key = pkcs1.keys.RsaPublicKey(self.modulus, self.public_exponent)
        self.private_key = pkcs1.keys.RsaPrivateKey(self.modulus, self.exponent)
        assert self.public_key.n == self.private_key.n
        self.samples = []

        for j in range(20):
            self.parse_sample(iterator)
            self.samples.append(SimpleObject(**self.sample))

    def parse_sample(self, iterator):
        grammar = (
                ('message', 'Message:'),
                ('seed', 'Seed:'),
                ('encryption', 'Encryption:'))
        self.sample = {}
        for name, token in grammar:
            self.sample[name] = self.jtrs(iterator, token)

class RsassaPkcs1V15VectorsData(TestVectors):
    path = os.path.join(os.path.dirname(__file__), 'data',
            'pkcs1v15sign-vectors.txt')

    def parse(self, iterator):
        self.examples = []
        for j in range(15):
            self.parse_example(iterator)
            self.examples.append(SimpleObject(
                    public_key=self.public_key,
                    private_key=self.private_key,
                    samples=self.samples))

    def parse_example(self, iterator):
        grammar = (
                ('modulus', 'Modulus:'),
                ('public_exponent', 'Public exponent:'),
                ('exponent', 'Exponent:'))
        for name, token in grammar:
            setattr(self, name, self.jtrx(iterator, token))
        self.public_key = pkcs1.keys.RsaPublicKey(self.modulus, self.public_exponent)
        self.private_key = pkcs1.keys.RsaPrivateKey(self.modulus, self.exponent)
        assert self.public_key.n == self.private_key.n
        self.samples = []

        for j in range(20):
            self.parse_sample(iterator)
            self.samples.append(SimpleObject(**self.sample))

    def parse_sample(self, iterator):
        grammar = (
                ('message', 'Message to be signed:'),
                ('signature', 'Signature:'))
        self.sample = {}
        for name, token in grammar:
            self.sample[name] = self.jtrs(iterator, token)

class OaepIntData(TestVectors):
    path = os.path.join(os.path.dirname(__file__), 'data',
            'oaep-int.txt')

    def parse(self, iterator):
        grammar = (
                ('modulus', 'Modulus', 1),
                ('public_exponent', 'Public exponent', 1),
                ('exponent', 'Private exponent', 1),
                ('message', 'Message to be encrypted', 0),
                ('seed', 'seed:', 0),
                ('encoded', 'EM =', 0),
                ('encrypted', 'Ciphertext, the RSA encryption', 0))
        for name, token, is_long in grammar:
            if is_long:
                setattr(self, name, self.jtrx(iterator, token))
            else:
                setattr(self, name, self.jtrs(iterator, token))

        self.public_key = pkcs1.keys.RsaPublicKey(self.modulus, self.public_exponent)
        self.private_key = pkcs1.keys.RsaPrivateKey(self.modulus, self.exponent)

class OaepVectData(TestVectors):
    path = os.path.join(os.path.dirname(__file__), 'data',
            'oaep-vect.txt')

    def parse(self, iterator):
        self.examples = []
        for j in range(10):
            self.parse_example(iterator)
            self.examples.append(SimpleObject(
                    public_key=self.public_key,
                    private_key=self.private_key,
                    samples=self.samples))

    def parse_example(self, iterator):
        grammar = (
                ('modulus', 'RSA modulus'),
                ('public_exponent', 'RSA public exponent'),
                ('exponent', 'RSA private exponent'))
        for name, token in grammar:
            setattr(self, name, self.jtrx(iterator, token))
        self.public_key = pkcs1.keys.RsaPublicKey(self.modulus, self.public_exponent)
        self.private_key = pkcs1.keys.RsaPrivateKey(self.modulus, self.exponent)
        assert self.public_key.n == self.private_key.n
        self.samples = []

        for j in range(6):
            self.parse_sample(iterator)
            self.samples.append(SimpleObject(**self.sample))

    def parse_sample(self, iterator):
        grammar = (
                ('message', 'Message to be encrypted'),
                ('seed', 'Seed:'),
                ('encrypted', 'Encryption:'))
        self.sample = {}
        for name, token in grammar:
            self.sample[name] = self.jtrs(iterator, token)

class PssVectData(TestVectors):
    path = os.path.join(os.path.dirname(__file__), 'data',
            'pss-vect.txt')

    def parse(self, iterator):
        self.examples = []
        for j in range(10):
            self.parse_example(iterator)
            self.examples.append(SimpleObject(
                    public_key=self.public_key,
                    private_key=self.private_key,
                    samples=self.samples))

    def parse_example(self, iterator):
        grammar = (
                ('modulus', 'RSA modulus'),
                ('public_exponent', 'RSA public exponent'),
                ('exponent', 'RSA private exponent'))
        for name, token in grammar:
            setattr(self, name, self.jtrx(iterator, token))
        self.public_key = pkcs1.keys.RsaPublicKey(self.modulus, self.public_exponent)
        self.private_key = pkcs1.keys.RsaPrivateKey(self.modulus, self.exponent)
        assert self.public_key.n == self.private_key.n
        self.samples = []

        for j in range(6):
            self.parse_sample(iterator)
            self.samples.append(SimpleObject(**self.sample))

    def parse_sample(self, iterator):
        grammar = (
                ('message', 'Message to be signed'),
                ('salt', 'Salt:'),
                ('signature', 'Signature:'))
        self.sample = {}
        for name, token in grammar:
            self.sample[name] = self.jtrs(iterator, token)
