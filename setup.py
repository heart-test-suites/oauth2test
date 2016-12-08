#!/usr/bin/python
#
# Copyright (C) 2016 Catalogix, Sweden
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import re

from setuptools import setup, find_packages

__author__ = 'roland'

version = ''
with open('src/oauth2test/__init__.py', 'r') as fd:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fd.read(), re.MULTILINE).group(1)

setup(
    version=version,
    name="oauth2test",
    description="Test framework for testing OAuth2 Authorization server and "
                "relaying party implementations in a HEART context",
    author="Roland Hedberg",
    author_email="roland.hedberg@catalogix.se",
    license="Apache 2.0",
    packages=find_packages('src'),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.5",
        "Topic :: Software Development :: Libraries :: Python Modules"],
    install_requires=[
        "argparse",
        "requests >= 2.0.0",
        'pyYAML',
        'pycryptodomex',
        'oic',
        'pyjwkest',
        'future',
        'entropy'
    ],
    zip_safe=False,
    scripts=['script/astest.py', 'script/oauth2_setup.py']
)
