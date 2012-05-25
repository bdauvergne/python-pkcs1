import random

from primitives import get_nonzero_random_bytes
import exceptions

def encode(message, k, ps=None, rnd=random.SystemRandom):
    '''Take a message of length inferior to k - 11 and return
       the concatenation of length k:

        0x00 || 0x02 || PS || 0x00 || message

       where PS is a random string containing no zero byte of length
       k - len(message) - 3.
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
        ps = get_nonzero_random_bytes(ps_len, rnd=rnd)
    return '\x00\x02%s\x00%s' % (ps, message)

def decode(message):
    if message[0:2] != '\x00\x02':
        raise exceptions.DecryptionError
    i = message.find('\x00', 2)
    if i == -1:
        raise exceptions.DecryptionError
    if i < 10:
        raise exceptions.DecryptionError
    return message[i+1:]

