"""OLYMPUS - Decentralized Identity Framework for Metaverse Environments."""
from setuptools import setup, find_packages

setup(
    name="olympus-identity",
    version="2.0.0",
    description="OLYMPUS: Decentralized Identity Framework with Quaternary World Model",
    author="BlockchainLab Research",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "cryptography>=41.0.0",
        "ecdsa>=0.18.0",
        "py_ecc>=7.0.0",
        "tabulate>=0.9.0",
    ],
)
