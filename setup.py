# -*- coding:utf-8 -*-
from setuptools import find_packages, setup

VERSION = '2.4.38.0'

setup(
    name="osc-sdk",
    version='0.1',
    packages=find_packages(),
    author='Outscale SAS',
    author_email='contact@outscale.com',
    description="Outscale ",
    url="http://www.outscale.com/",
    entry_points={
        'console_scripts': [
            'osc-cli = osc_sdk.sdk:main',
        ]
    },
    install_requires=[
        'setuptools',
        'fire==0.1.3',
        'requests==2.5.1',
        'xmltodict==0.11.0',
    ],
)
