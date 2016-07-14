from . import primitives
from . import exceptions
from .defaults import default_crypto_random

def encode(message, k, ps=None, rnd=default_crypto_random):
    '''Take a message of length inferior to k - 11 and return
       the concatenation of length k:

        0x00 || 0x02 || PS || 0x00 || message

       where PS is a random string containing no zero byte of length
       k - len(message) - 3.

       message - the message to encode, a byte string
       k - the length of the padded byte string
       ps - a fixed string to use instead of generating a random one, it's
       necessary for testing using test vectors,
       rnd - the random generator to use, it must conform to the interface of
       the random.Random class.
    '''
    m_len = len(message)
    if m_len > k - 11:
        raise exceptions.MessageTooLong
    ps_len = k - len(message) - 3
    if ps:
        if len(ps) != ps_len:
            raise exceptions.WrongLength(
                    'given pseudorandom string length is wrong',
                    len(ps), ps_len)
    else:
        ps = primitives.get_nonzero_random_bytes(ps_len, rnd=rnd)
    return b'\x00\x02' + ps + b'\x00' + message

def decode(message):
    '''
       Verify that a padded message conform to the PKCSv1 1.5 encoding and
       return the unpadded message.
    '''
    if message[:2] != b'\x00\x02':
        raise exceptions.DecryptionError
    i = message.find(b'\x00', 2)
    if i == -1:
        raise exceptions.DecryptionError
    if i < 10:
        raise exceptions.DecryptionError
    return message[i+1:]

