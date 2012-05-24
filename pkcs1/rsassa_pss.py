import emsa_pss
import primitives

def rsassa_pss_sign(private_key, message,
        emsa_pss_encode=emsa_pss.emsa_pss_encode):
    mod_bits = private_key.k * 8
    embits = mod_bits - 1
    em = emsa_pss_encode(message, embits)
    m = primitives.os2ip(em)
    s = primitives.rsasp1(private_key, m)
    return primitives.i2osp(s, private_key.k)

def rsassa_pss_verify(public_key, message, signature,
        emsa_pss_verify=emsa_pss.emsa_pss_verify):
    s = primitives.os2ip(signature)
    m = primitives.rsavp1(public_key, s)
    mod_bits = public_key.k * 8
    embits = mod_bits - 1
    em_len = primitives.integer_ceil(embits, 8)
    em = primitives.i2osp(m, em_len)
    return emsa_pss.emsa_pss_verify(message, em, embits)
