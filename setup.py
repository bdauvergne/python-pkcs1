#!/usr/bin/python
from setuptools import setup, find_packages
import os

setup(name='pkcs1',
      version='0.9.7',
      license='MIT',
      description='Python implementation of the RFC3447 or PKCS #1 version 2.0',
      url='https://github.com/bdauvergne/python-pkcs1',
      author='Benjamin Dauvergne',
      author_email='bdauvergne@entrouvert.com',
      packages=find_packages(os.path.dirname(__file__) or '.'))
