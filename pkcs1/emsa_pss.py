import hashlib

import primitives
import mgf
import exceptions
from defaults import default_crypto_random

def encode(m, embits, hash_class=hashlib.sha1,
        mgf=mgf.mgf1, salt=None, s_len=None, rnd=default_crypto_random):
    '''Encode a message using the PKCS v2 PSS padding.

       m - the message to encode
       embits - the length of the padded message
       mgf - a masg generating function, default is mgf1 the mask generating
       function proposed in the PKCS#1 v2 standard.
       hash_class - the hash algorithm to use to compute the digest of the
       message, must conform to the hashlib class interface.
       salt - a fixed salt string to use, if None, a random string of length
       s_len is used instead, necessary for tests,
       s_len - the length of the salt string when using a random generator to
       create it, if None the length of the digest is used.
       rnd - the random generator used to compute the salt string

       Return value: the padded message
    '''
    m_hash = hash_class(m).digest()
    h_len = len(m_hash)
    if salt is not None:
        s_len = len(salt)
    else:
        if s_len is None:
            s_len = h_len
        salt = primitives.i2osp(rnd.getrandbits(s_len*8), s_len)
    em_len = primitives.integer_ceil(embits, 8)
    if em_len < len(m_hash) + s_len + 2:
        raise exceptions.EncodingError
    m_prime = ('\x00' * 8) + m_hash + salt
    h = hash_class(m_prime).digest()
    ps = '\x00' * (em_len - s_len - h_len - 2)
    db = ps + '\x01' + salt
    db_mask = mgf(h, em_len - h_len - 1)
    masked_db = primitives.string_xor(db, db_mask)
    octets, bits = (8 * em_len - embits) / 8, (8*em_len-embits) % 8
    # replace first `octets' bytes
    masked_db = ('\x00' * octets) + masked_db[octets:]
    new_byte = chr(ord(masked_db[octets]) & (255 >> bits))
    masked_db = masked_db[:octets] + new_byte + masked_db[octets+1:]
    return masked_db + h + '\xbc'

def verify(m, em, embits, hash_class=hashlib.sha1, mgf=mgf.mgf1, s_len=None):
    '''
       Verify that a message padded using the PKCS#1 v2 PSS algorithm matched a
       given message string.

       m - the message to match
       em - the padded message
       embits - the length in bits of the padded message
       hash_class - the hash algorithm used to compute the digest of the message
       mgf - the mask generation function
       s_len - the length of the salt string, if None the length of the digest is used.

       Return: True if the message matches, False otherwise.
    '''
    # 1. cannot verify, does not know the max input length of hash_class
    # 2.
    m_hash = hash_class(m).digest()
    h_len = len(m_hash)
    if s_len is None:
        s_len = h_len
    em_len = primitives.integer_ceil(embits, 8)
    # 3.
    if em_len < len(m_hash) + s_len + 2:
        return False
    # 4.
    if em[-1] != '\xbc':
        return False
    # 5.
    masked_db, h = em[:em_len-h_len-1], em[em_len-h_len-1:-1]
    # 6.
    octets, bits = (8 * em_len - embits) / 8, (8*em_len-embits) % 8
    zero = masked_db[:octets] + chr(ord(masked_db[octets]) & ~(255 >>bits))
    for c in zero:
        if c != '\x00':
            return False
    # 7.
    db_mask = mgf(h, em_len - h_len - 1)
    # 8.
    db = primitives.string_xor(masked_db, db_mask)
    # 9.
    new_byte = chr(ord(db[octets]) & (255 >> bits))
    db = ('\x00' * octets) + new_byte + db[octets+1:]
    # 10.
    for c in db[:em_len-h_len-s_len-2]:
        if c != '\x00':
            return False
    if db[em_len-h_len-s_len-2] != '\x01':
        return False
    # 11.
    salt = db[-s_len:]
    # 12.
    m_prime = ('\x00' * 8) + m_hash + salt
    # 13.
    h_prime = hash_class(m_prime).digest()
    # 14.
    return primitives.constant_time_cmp(h_prime, h)
