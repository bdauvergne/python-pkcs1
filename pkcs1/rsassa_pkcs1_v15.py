import emsa_pkcs1_v15
import primitives
import exceptions
import hashlib

def sign(private_key, message, hash_class=hashlib.sha1):
    '''Produce a signature of string using a RSA private key and PKCS#1.5
       padding.

       Parameters:

       private_key - a RSA private key
       message - a string to sign

       Result:
       the signature string
    '''

    em = emsa_pkcs1_v15.encode(message, private_key.byte_size,
            hash_class=hash_class)
    m = primitives.os2ip(em)
    s = private_key.rsasp1(m)
    return primitives.i2osp(s, private_key.byte_size)

def verify(public_key, message, signature, hash_class=hashlib.sha1):
    '''Verify a signature of a message using a RSA public key and PKCS#1.5
       padding.

       Parameters:

       public_key - a RSA public key
       message - the signed string
       signature - the signature string

       Result:
       True if the signature matches the message, False otherwise.
    '''
    if len(signature) != public_key.byte_size:
        raise exceptions.InvalidSignature
    s = primitives.os2ip(signature)
    try:
        m = public_key.rsavp1(s)
    except ValueError:
        raise exceptions.InvalidSignature
    try:
        em = primitives.i2osp(m, public_key.byte_size)
    except ValueError:
        raise exceptions.InvalidSignature
    try:
        em_prime = emsa_pkcs1_v15.encode(message, public_key.byte_size,
                hash_class=hash_class)
    except ValueError:
        raise exceptions.RSAModulusTooShort
    return primitives.constant_time_cmp(em, em_prime)
