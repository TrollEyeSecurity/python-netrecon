#!/usr/bin/python
from setuptools import setup, find_packages

setup(
    # Application name:
    name="netrecon",

    # Version number:
    version="0.8",

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
    description="Netrecon is a tool used to pull useful data from network infrastructure devices. "
                "The currently supported device types are - Cisco IOS, Cisco ASAOS, Cisco NX-OX, and PANOS",

    long_description=open("README.rst").read(),

    # Dependent packages (distributions)
    install_requires=['pexpect==4.3.1',
                      'netaddr==0.7.19'
                      ])
