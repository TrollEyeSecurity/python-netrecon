#!/usr/bin/python
from setuptools import setup, find_packages

setup(
    # Application name:
    name="netrecon",

    # Version number (initial):
    version="0.1",

    # Application author details:
    author="Avery Rozar",
    author_email="avery.rozar@insecure-it.com",

    # Packages
    packages=find_packages(exclude=('tests', 'docs')),

    # Include additional files into the package
    include_package_data=True,

    # Details
    url="https://www.critical-sec.com",

    #
    license="LICENSE.txt",
    description="",

    long_description=open("README.rst").read(),

    # Dependent packages (distributions)
    install_requires=['pexpect',
                      'redis',
                      ])
