#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
    name='uncurl',
    version='0.0.15',
    description='A library to convert curl requests to python-requests.',
    author='ErebusST',
    author_email='situbin@foxmail.com',
    url='https://github.com/ErebusST/uncurl',
    entry_points={
        'console_scripts': [
            'uncurl = uncurl.bin:main',
        ],
    },
    install_requires=['pyperclip', 'six'],
    packages=find_packages(exclude=("tests", "tests.*")),
)
