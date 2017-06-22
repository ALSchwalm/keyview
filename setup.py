#!/usr/bin/env python
import os
from setuptools import setup, find_packages


long_description = open(
    os.path.join(
        os.path.dirname(__file__),
        'README.md'
    )
).read()


setup(
    name='keyview',
    author='Adam Schwalm',
    version='0.1',
    license='LICENSE',
    url='https://github.com/ALSchwalm/keyview',
    download_url='https://github.com/ALSchwalm/keyview/tarball/0.1',
    description='A python utility for viewing information about cryptographic keys and certificates',
    long_description=long_description,
    packages=find_packages('.', exclude=["*.tests", "*.tests.*", "tests.*", "tests"]),
    install_requires=[
        "cryptography",
        "pyopenssl",
        "docopt"
    ],
    include_package_data=True,
    package_data={
        'keyview': ["objects.txt"]
    },
    entry_points={
        'console_scripts': [
            'keyview = keyview.keyview:main',
        ]
    },
    keywords=['certificates', 'cryptography']
)
