import random
import hashlib
from primitives import get_nonzero_random_bytes

def pkcs1v15_encode(message, k, ps=None, rnd=random.SystemRandom):
    '''Take a message of length inferior to k - 11 and return
       the concatenation of length k:

        0x00 || 0x02 || PS || 0x00 || message

       where PS is a random string containing no zero byte of length
       k - len(message) - 3.
    '''
    m_len = len(message)
    if m_len > k - 11:
        raise ValueError('message too long')
    ps_len = k - len(message) - 3
    if ps:
        if len(ps) != ps_len:
            raise ValueError('given pseudorandom string length is wrong', len(ps), ps_len)
    else:
        ps = get_nonzero_random_bytes(ps_len, rnd=rnd)
    return '\x00\x02%s\x00%s' % (ps, message)

def pkcs1v15_decode(message):
    if message[0:2] != '\x00\x02':
        raise ValueError('decryption error')
    i = message.find('\x00', 2)
    if i == -1:
        raise ValueError('decryption error')
    if i < 10:
        raise ValueError('decryption error')
    return message[i+1:]

DIGEST_INFO_PREFIXES = {
      hashlib.md5: '\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10',
      hashlib.sha1:  '\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14',
      hashlib.sha256: '\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20',
      hashlib.sha384: '\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30',
      hashlib.sha512: '\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40',
}

def emsa_pkcs1v15_encode(message, em_len, ps=None, hash_class=hashlib.sha1):
    halgo = hash_class(message)
    h = halgo.digest()
    try:
        t = '%s%s' % (DIGEST_INFO_PREFIXES[hash_class], h)
    except KeyError:
        raise NotImplemented('hash algorithm is unsupported', hash_class)
    if em_len < len(t) + 11:
        raise ValueError("intended encoded message length too short")
    ps_len = em_len - len(t) - 3
    ps = '\xff' * ps_len
    return '\x00\x01%s\x00%s' % (ps, t)
