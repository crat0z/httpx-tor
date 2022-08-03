#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name='httpx-tor',
    version='0.0.1',
    packages=find_packages(),
    install_requires=[
        'httpx',
        'socksio',
        'brotli',
        'h2',
    ]
)