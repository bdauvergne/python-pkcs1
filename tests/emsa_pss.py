import unittest

from pkcs1 import emsa_pss

from data import PssIntData

class EmsaPssTests(unittest.TestCase):
    int_data = PssIntData()

    def test_emsa_pss_int(self):
        # specialize the generic encoding function for the test vector salt
        embits = self.int_data.public_key.byte_size*8-1
        em = emsa_pss.encode(self.int_data.message, embits,
                salt=self.int_data.salt)
        self.assertEqual(em, self.int_data.encoded)
        self.assertTrue(emsa_pss.verify(self.int_data.message,
            em, embits, s_len=len(self.int_data.salt)))
