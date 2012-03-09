python-pkcs1
------------

This package implements the PKCS #1 v2.0 standard from RSA Laboratories. It
aims at a full and tested coverage of the standard, maximum portability by
using only pure python and external dependencies only for performance gains.

Performance are improved by using the gmpy package to compute modular
exponentiation if it is present.

The package contains the following modules::

  - pkcs1.primitives
  - pkcs1.oaep
  - pkcs1.codec_v15
  - pkcs1.primes
  - pkcs1.encryption
  - pkcs1.signature
