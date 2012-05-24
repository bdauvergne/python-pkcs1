import hashlib
import random

from primitives import (i2osp, os2ip, string_xor, rsaep, rsadp)
import exceptions
from mgf import mgf1

def rsaes_oaep_encrypt(public_key, message, label='', hash_class=hashlib.sha1,
        mgf=mgf1, seed=None, random=random.SystemRandom):
    '''Encrypt a byte message using a RSA public key and the OAEP wrapping
       algorithm,

       Parameters:
       public_key - an RSA public key
       message - a byte string
       label - a label a per-se PKCS#1 standard
       hash_class - a Python class for a message digest algorithme respecting
         the hashlib interface
       mgf1 - a mask generation function
       seed - a seed to use instead of generating it using a random generator
       random - a random generator class, respecting the random generator
       interface from the random module, if seed is None, it is used to
       generate it.

       Return value:
       the encrypted string of the same length as the public key
    '''

    hash = hash_class()
    h_len = hash.digest_size
    k = public_key.k
    max_message_length = k - 2 * h_len - 2
    if len(message) > max_message_length:
        raise exceptions.MessageTooLong
    hash.update(label)
    label_hash = hash.digest()
    ps = '\0' * int(max_message_length - len(message))
    db = ''.join((label_hash, ps, '\x01', message))
    if not seed:
        seed = i2osp(random().getrandbits(h_len*8), h_len)
    db_mask = mgf(seed, k - h_len - 1, hash_class=hash_class)
    masked_db = string_xor(db, db_mask)
    seed_mask = mgf(masked_db, h_len, hash_class=hash_class)
    masked_seed = string_xor(seed, seed_mask)
    em = ''.join(('\x00', masked_seed, masked_db))
    m = os2ip(em)
    c = rsaep(public_key, m)
    output = i2osp(c, k)
    return output

def rsaes_oaep_decrypt(private_key, message, label='', hash_class=hashlib.sha1,
        mgf=mgf1):
    '''Decrypt a byte message using a RSA private key and the OAEP wrapping algorithm,

       Parameters:
       public_key - an RSA public key
       message - a byte string
       label - a label a per-se PKCS#1 standard
       hash_class - a Python class for a message digest algorithme respecting
         the hashlib interface
       mgf1 - a mask generation function

       Return value:
       the string before encryption (decrypted)
    '''
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
        raise exceptions.DecryptionError
    if rest[:i].strip('\x00') != '':
        raise exceptions.DecryptionError
    m = rest[i+1:]
    if label_hash_prime != label_hash:
        raise exceptions.DecryptionError
    return m

