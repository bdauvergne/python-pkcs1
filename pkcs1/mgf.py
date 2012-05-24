import hashlib

from primitives import integer_ceil, i2osp

def mgf1(mgf_seed, mask_len, hash_class=hashlib.sha1):
    '''Mask Generation Function v1'''
    h_len = hash_class().digest_size
    if mask_len > 0x10000:
        raise ValueError('mask too long')
    T = ''
    for i in xrange(0, integer_ceil(mask_len, h_len)):
        C = i2osp(i, 4)
        T = T + hash_class(mgf_seed + C).digest()
    return T[:mask_len]


