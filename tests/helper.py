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

