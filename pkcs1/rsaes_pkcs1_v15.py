import random

from primitives import os2ip, i2osp
import eme_pkcs1_v15
import exceptions

def encrypt(public_key, message, ps=None, rnd=random.SystemRandom):
    '''Encrypt message using public_key applying PKCS#1 v1.5 padding

       If ps is not None it is used as the pseudo-random padding bytes,
       otherwise random is used to generate them
    '''
    k = public_key.k
    m_len = len(message)
    if m_len > k - 11:
        raise exceptions.MessageTooLong
    em = eme_pkcs1_v15.encode(message, k, ps=ps, rnd=rnd)
    m = os2ip(em)
    c = public_key.rsaep(m)
    return i2osp(c, k)

def decrypt(private_key, encryption):
    '''Decrypt encryption of a message using private_key and using PKCS#1 v1.5
       padding scheme.
    '''
    k = private_key.k
    if len(encryption) != k:
        raise exceptions.DecryptionError
    c = os2ip(encryption)
    m = private_key.rsadp(c)
    em = i2osp(m, k)
    return eme_pkcs1_v15.decode(em)
