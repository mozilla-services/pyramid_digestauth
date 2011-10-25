
import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.txt')) as f:
    README = f.read()

with open(os.path.join(here, 'CHANGES.txt')) as f:
    CHANGES = f.read()

requires = ['pyramid', 'unittest2']

setup(name='pyramid_digestauth',
      version='0.1',
      description='pyramid plugin for HTTP-Digest-Auth',
      long_description=README + '\n\n' + CHANGES,
      classifiers=[
        "Programming Language :: Python",
        ],
      author='',
      author_email='',
      url='',
      keywords='authentication pyramid digest',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=requires,
      test_suite="pyramid_digestauth")
