import hashlib
import random
import math

from primitives import (integer_ceil, i2osp, os2ip, string_xor, rsaep, rsadp)

def mgf1(mgf_seed, mask_len, hash_class=hashlib.sha1):
    h_len = hash_class().digest_size
    if mask_len > 0x10000:
        raise ValueError('mask too long')
    T = ''
    for i in xrange(0, integer_ceil(mask_len, h_len) - 1):
        C = i2osp(i, 4)
        T = T + hash_class(mgf_seed + C).digest()
    print 'mask_len', repr(mask_len)
    return T[:mask_len]


def rsaes_oaep_encrypt(public_key, message, label='', hash_class=hashlib.sha1,
        mgf=mgf1, random=random.SystemRandom):
    hash = hash_class()
    h_len = hash.digest_size
    k = public_key.k
    # FIXME: we should check that the label does not exceed the hash algorith
    # max input size, but we do not have this information
    max_message_length = k - 2 * h_len - 2
    if len(message) > max_message_length:
        raise ValueError('message too long')
    hash.update(label)
    label_hash = hash.digest()
    ps = '\0' * int(max_message_length - len(message))
    db = ''.join((label_hash, ps, '\x01', message))
    seed = i2osp(random().getrandbits(h_len*8), h_len)
    print 'h_len', repr(h_len)
    db_mask = mgf(seed, k - h_len - 1, hash_class=hash_class)
    masked_db = string_xor(db, db_mask)
    seed_mask = mgf(masked_db, h_len, hash_class=hash_class)
    masked_seed = string_xor(seed, seed_mask)
    em = ''.join(('\x00', masked_seed, masked_db))
    m = os2ip(em)
    c = rsaep(public_key, m)
    print 'log2', math.log(c, 2)
    output = i2osp(c, k)
    return output

def rsaes_oaep_decrypt(private_key, message, label='', hash_class=hashlib.sha1,
        mgf=mgf1, random=random.SystemRandom):
    hash = hash_class()
    h_len = hash.digest_size
    k = private_key.k
    # 1. check length
    if len(message) != private_key.k or k < 2 * h_len + 2:
        raise ValueError('decryption error')
    # 2. RSA decryption
    c = os2ip(message)
    m = rsadp(private_key, c)
    em = i2osp(m, k)
    # 4. EME-OAEP decoding
    hash.update(label)
    label_hash = hash.digest()
    y, masked_seed, masked_db = em[0], em[1:h_len], em[1+h_len:]
    if y != '\x00':
        raise ValueError('decryption error')
    seed_mask = mgf(masked_db, h_len)
    seed = string_xor(masked_seed, seed_mask)
    db_mask = mgf(seed, k - h_len - 1)
    db = string_xor(masked_db, db_mask)
    label_hash_prime, rest = db[:h_len], db[h_len:]
    i = rest.find('\x01')
    if i == -1:
        raise ValueError('decryption error')
    if rest[:i].strip('\x00') != '':
        raise ValueError('decryption error')
    m = rest[i+1:]
    if label_hash_prime != label_hash:
        raise ValueError('decryption error')
    return m

