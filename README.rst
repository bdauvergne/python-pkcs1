python-pkcs1
------------

This package implements the PKCS #1 v2.0 standard from RSA Laboratories. It
aims at a full and tested coverage of the standard, maximum portability by
using only pure python and external dependencies only for performance gains.

Performance are improved by using the gmpy package to compute modular
exponentiation if it is present.

The package contains the following modules:

  - pkcs1.primitives - integer<->byte string conversion
  - pkcs1.keys - RSA keys classes, naive RSA encryption
  - pkcs1.primes - prime number generation
  - pkcs1.eme_pkcs1_v15 - PKCS#1 v1.5 encoding for encryption
  - pkcs1.emsa_pkcs1_v15 - PKCS#1 v1.5 encoding for signature
  - pkcs1.mgf - mask generation function number one
  - pkcs1.exceptions - specialized exceptions
  - pkcs1.rsaes_pkcs1_v15 - RSA encryption using PKCS#1 v1.5 padding
  - pkcs1.rsaes_oaep - RSA encryption using non-deterministic OAEP padding
  - pkcs1.rsassa_pkcs1_v15 - RSA signature using PKCS#1 v1.5 encoding
  - pkcs1.rsassa_pss - RSA signature using non-deterministic encoding
