"""Test utilities.

.. warning:: This module is not part of the public API.

"""
import importlib.resources
import os
from typing import Callable

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import josepy as jose
from josepy.util import ComparableECKey
from OpenSSL import crypto


def load_vector(*names):
    """Load contents of a test vector."""
    # luckily, resource_string opens file in binary mode
    vector_ref = importlib.resources.files(__package__).joinpath('testdata', *names)
    return vector_ref.read_bytes()


def _guess_loader(filename: str, loader_pem: Callable, loader_der: Callable) -> Callable:
    _, ext = os.path.splitext(filename)
    if ext.lower() == ".pem":
        return loader_pem
    elif ext.lower() == ".der":
        return loader_der
    else:  # pragma: no cover
        raise ValueError("Loader could not be recognized based on extension")


def _guess_pyopenssl_loader(filename: str, loader_pem: int, loader_der: int) -> int:
    _, ext = os.path.splitext(filename)
    if ext.lower() == ".pem":
        return loader_pem
    elif ext.lower() == ".der":
        return loader_der
    else:  # pragma: no cover
        raise ValueError("Loader could not be recognized based on extension")


def load_pyopenssl_cert(*names) -> crypto.X509:
    """Load certificate."""
    loader = _guess_pyopenssl_loader(
        names[-1], crypto.FILETYPE_PEM, crypto.FILETYPE_ASN1)
    return crypto.load_certificate(loader, load_vector(*names))


def load_pyopenssl_csr(*names) -> crypto.X509Req:
    """Load certificate request."""
    loader = _guess_pyopenssl_loader(
        names[-1], crypto.FILETYPE_PEM, crypto.FILETYPE_ASN1)
    return crypto.load_certificate_request(loader, load_vector(*names))

def load_cert(*names: str) -> x509.Certificate:
    """Load certificate."""
    loader = _guess_loader(
        names[-1], x509.load_pem_x509_certificate, x509.load_der_x509_certificate
    )
    return loader(load_vector(*names))


def load_csr(*names: str) -> x509.CertificateSigningRequest:
    """Load certificate request."""
    loader = _guess_loader(names[-1], x509.load_pem_x509_csr, x509.load_der_x509_csr)
    return loader(load_vector(*names))


def load_rsa_private_key(*names):
    """Load RSA private key."""
    loader = _guess_loader(names[-1], serialization.load_pem_private_key,
                           serialization.load_der_private_key)
    return jose.ComparableRSAKey(loader(
        load_vector(*names), password=None, backend=default_backend()))


def load_ecdsa_private_key(*names):
    """Load ECDSA private key."""
    loader = _guess_loader(names[-1], serialization.load_pem_private_key,
                           serialization.load_der_private_key)
    return ComparableECKey(loader(
        load_vector(*names), password=None, backend=default_backend()))


def load_pyopenssl_private_key(*names):
    """Load pyOpenSSL private key."""
    loader = _guess_pyopenssl_loader(
        names[-1], crypto.FILETYPE_PEM, crypto.FILETYPE_ASN1)
    return crypto.load_privatekey(loader, load_vector(*names))
