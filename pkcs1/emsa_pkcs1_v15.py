import hashlib

import exceptions

DIGEST_INFO_PREFIXES = {
      hashlib.md5: '\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10',
      hashlib.sha1:  '\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14',
      hashlib.sha256: '\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20',
      hashlib.sha384: '\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30',
      hashlib.sha512: '\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40',
}

def encode(message, em_len, ps=None, hash_class=hashlib.sha1):
    halgo = hash_class(message)
    h = halgo.digest()
    try:
        t = '%s%s' % (DIGEST_INFO_PREFIXES[hash_class], h)
    except KeyError:
        raise NotImplementedError('hash algorithm is unsupported', hash_class)
    if em_len < len(t) + 11:
        raise exceptions.MessageTooShort
    ps_len = em_len - len(t) - 3
    ps = '\xff' * ps_len
    return '\x00\x01%s\x00%s' % (ps, t)
