import hashlib

import emsa_pss
import primitives
import mgf
from defaults import default_crypto_random

def sign(private_key, message,
        emsa_pss_encode=emsa_pss.encode,
        hash_class=hashlib.sha1,
        mgf1=mgf.mgf1,
        rnd=default_crypto_random):
    '''Sign message using private_key and the PKCS#1 2.0 RSASSA-PSS
       algorithm.

       private_key - the private key to use
       message - the byte string to sign
       emsa_pss_encode - the encoding to use, default to EMSA-PSS encoding
       hash_class - the hash algorithme to use, default to SHA-1 from the
         Python hashlib package.
       mgf1 - the mask generating function to use, default to MGF1
       rnd - a random number generator to use for the PSS encoding,
       default to a Python SystemRandom instance.
    '''
    mod_bits = private_key.bit_size
    embits = mod_bits - 1
    em = emsa_pss_encode(message, embits, hash_class=hash_class,
            mgf=mgf1, rnd=rnd)
    m = primitives.os2ip(em)
    s = private_key.rsasp1(m)
    return primitives.i2osp(s, private_key.byte_size)

def verify(public_key, message, signature,
        emsa_pss_verify=emsa_pss.verify,
        hash_class=hashlib.sha1,
        mgf1=mgf.mgf1):
    '''Verify the signature of message signed using private_key and the
       PKCS#1 2.0 RSASSA-PSS algorithm.

       private_key - the private key to use
       message - the signed byte string
       signature - the byte string of the signature of the message
       emsa_pss_verify - the verify function for the used encoding,
         default to EMSA-PSS verification function
       hash_class - the hash algorithme to use, default to SHA-1 from the
         Python hashlib package.
       mgf1 - the mask generating function to use, default to MGF1
    '''
    mod_bits = public_key.bit_size
    s = primitives.os2ip(signature)
    m = public_key.rsavp1(s)
    embits = mod_bits - 1
    em_len = primitives.integer_ceil(embits, 8)
    em = primitives.i2osp(m, em_len)
    return emsa_pss_verify(message, em, embits, hash_class=hash_class,
            mgf=mgf1)
