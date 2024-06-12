#!/bin/env python

from setuptools import setup, find_packages

push_receiver_classifiers = [
    "Programming Language :: Python :: 2",
    "Programming Language :: Python :: 3",
    "Intended Audience :: Developers",
    "License :: Public Domain",
    "Topic :: Software Development :: Libraries"
]

with open("README.rst", "r") as f:
    push_receiver_readme = f.read()

setup(
    name="rustPlusPushReceiver",
    version="0.6.0",
    author="Franc[e]sco & olijeffers0n",
    url="https://github.com/olijeffers0n/push_receiver",
    packages=find_packages("."),
    description="Subscribe to GCM/FCM and receive notifications",
    long_description=push_receiver_readme,
    license="Unlicense",
    classifiers=push_receiver_classifiers,
    keywords="fcm gcm push notification firebase google",
    install_requires=["oscrypto", "protobuf", "http-ece", "cryptography", "betterproto", "requests"],
    extras_require={
        "example": ["appdirs"]
    }
)
