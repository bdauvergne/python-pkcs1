from codec_v15 import emsa_pkcs1v15_encode
from primitives import os2ip, rsasp1, i2osp, rsavp1

def rsassa_pkcs1_v15_sign(private_key, message):
    em = emsa_pkcs1v15_encode(message, private_key.k)
    m = os2ip(em)
    s = rsasp1(private_key, m)
    return i2osp(s, private_key.k)

def rsassa_pkcs1_v15_verify(public_key, message, signature):
    if len(signature) != public_key.k:
        raise ValueError("invalid signature")
    s = os2ip(signature)
    try:
        m = rsavp1(public_key, s)
    except ValueError:
        raise ValueError("invalid signature")
    try:
        em = i2osp(m, public_key.k)
    except ValueError:
        raise ValueError("invalid signature")
    try:
        em_prime = emsa_pkcs1v15_encode(message, public_key.k)
    except ValueError:
        raise ValueError("RSA modulus too short")
    return em == em_prime
