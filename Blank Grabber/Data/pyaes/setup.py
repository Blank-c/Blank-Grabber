#!/usr/bin/env python
try:
  from setuptools import setup
except ImportError:
  from distutils.core import setup

LONG_DESCRIPTION = '''A pure-Python implementation of the AES (FIPS-197)
block-cipher algorithm and common modes of operation (CBC, CFB, CTR, ECB,
OFB) with no dependencies beyond standard Python libraries.'''

setup(name = 'pyaes',
      version = '1.6.2',
      description = 'Pure-Python Implementation of the AES block-cipher and common modes of operation',
      long_description = LONG_DESCRIPTION,
      author = 'Richard Moore',
      author_email = 'pyaes@ricmoo.com',
      url = 'https://github.com/ricmoo/pyaes',
      packages = ['pyaes'],
      classifiers = [
          'Topic :: Security :: Cryptography',
          'License :: OSI Approved :: MIT License',
      ],
      license = "License :: OSI Approved :: MIT License",
     )
