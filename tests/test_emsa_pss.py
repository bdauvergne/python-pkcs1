from pkcs1 import emsa_pss

from data import PssIntData


int_data = PssIntData()


def test_emsa_pss_int():
    # specialize the generic encoding function for the test vector salt
    embits = int_data.public_key.byte_size * 8 - 1
    em = emsa_pss.encode(int_data.message, embits, salt=int_data.salt)
    assert em == int_data.encoded
    assert emsa_pss.verify(int_data.message, em, embits, s_len=len(int_data.salt))
