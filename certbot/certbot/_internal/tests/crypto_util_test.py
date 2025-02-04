"""Tests for certbot.crypto_util."""
import binascii
import logging
import re
import sys
import unittest
from unittest import mock

import OpenSSL
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from certbot import errors
from certbot import util
from certbot.compat import filesystem
from certbot.compat import os
import certbot.tests.util as test_util

RSA256_KEY = test_util.load_vector('rsa256_key.pem')
RSA256_KEY_PATH = test_util.vector_path('rsa256_key.pem')
RSA512_KEY = test_util.load_vector('rsa512_key.pem')
RSA2048_KEY_PATH = test_util.vector_path('rsa2048_key.pem')
CERT_PATH = test_util.vector_path('cert_512.pem')
CERT = test_util.load_vector('cert_512.pem')
SS_CERT_PATH = test_util.vector_path('cert_2048.pem')
SS_CERT = test_util.load_vector('cert_2048.pem')
P256_KEY = test_util.load_vector('nistp256_key.pem')
P256_CERT_PATH = test_util.vector_path('cert-nosans_nistp256.pem')
P256_CERT = test_util.load_vector('cert-nosans_nistp256.pem')
# CERT_LEAF is signed by CERT_ISSUER. CERT_ALT_ISSUER is a cross-sign of CERT_ISSUER.
CERT_LEAF = test_util.load_vector('cert_leaf.pem')
CERT_ISSUER = test_util.load_vector('cert_intermediate_1.pem')
CERT_ALT_ISSUER = test_util.load_vector('cert_intermediate_2.pem')


class GenerateKeyTest(test_util.TempDirTestCase):
    """Tests for certbot.crypto_util.generate_key."""
    def setUp(self):
        super().setUp()

        self.workdir = os.path.join(self.tempdir, 'workdir')
        filesystem.mkdir(self.workdir, mode=0o700)

        logging.disable(logging.CRITICAL)

    def tearDown(self):
        super().tearDown()

        logging.disable(logging.NOTSET)

    @classmethod
    def _call(cls, key_size, key_dir):
        from certbot.crypto_util import generate_key
        return generate_key(key_size, key_dir, 'key-certbot.pem', strict_permissions=True)

    @mock.patch('certbot.crypto_util.make_key')
    def test_success(self, mock_make):
        mock_make.return_value = b'key_pem'
        key = self._call(1024, self.workdir)
        assert key.pem == b'key_pem'
        assert 'key-certbot.pem' in key.file
        assert os.path.exists(os.path.join(self.workdir, key.file))

    @mock.patch('certbot.crypto_util.make_key')
    def test_key_failure(self, mock_make):
        mock_make.side_effect = ValueError
        with pytest.raises(ValueError):
            self._call(431, self.workdir)


class GenerateCSRTest(test_util.TempDirTestCase):
    """Tests for certbot.crypto_util.generate_csr."""
    @mock.patch('acme.crypto_util.make_csr')
    @mock.patch('certbot.crypto_util.util.make_or_verify_dir')
    def test_it(self, unused_mock_verify, mock_csr):
        from certbot.crypto_util import generate_csr

        mock_csr.return_value = b'csr_pem'

        csr = generate_csr(
            mock.Mock(pem='dummy_key'), 'example.com', self.tempdir, strict_permissions=True)

        assert csr.data == b'csr_pem'
        assert 'csr-certbot.pem' in csr.file


class ValidCSRTest(unittest.TestCase):
    """Tests for certbot.crypto_util.valid_csr."""

    @classmethod
    def _call(cls, csr):
        from certbot.crypto_util import valid_csr
        return valid_csr(csr)

    def test_valid_pem_true(self):
        assert self._call(test_util.load_vector('csr_512.pem'))

    def test_valid_pem_san_true(self):
        assert self._call(test_util.load_vector('csr-san_512.pem'))

    def test_valid_der_false(self):
        assert not self._call(test_util.load_vector('csr_512.der'))

    def test_empty_false(self):
        assert not self._call('')

    def test_random_false(self):
        assert not self._call('foo bar')


class CSRMatchesPubkeyTest(unittest.TestCase):
    """Tests for certbot.crypto_util.csr_matches_pubkey."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.crypto_util import csr_matches_pubkey
        return csr_matches_pubkey(*args, **kwargs)

    def test_valid_true(self):
        assert self._call(
            test_util.load_vector('csr_512.pem'), RSA512_KEY)

    def test_invalid_false(self):
        assert not self._call(
            test_util.load_vector('csr_512.pem'), RSA256_KEY)


class ImportCSRFileTest(unittest.TestCase):
    """Tests for certbot.certbot_util.import_csr_file."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.crypto_util import import_csr_file
        return import_csr_file(*args, **kwargs)

    def test_der_csr(self):
        csrfile = test_util.vector_path('csr_512.der')
        data = test_util.load_vector('csr_512.der')
        data_pem = test_util.load_vector('csr_512.pem')

        assert (OpenSSL.crypto.FILETYPE_PEM,
             util.CSR(file=csrfile,
                      data=data_pem,
                      form="pem"),
             ["Example.com"]) == \
            self._call(csrfile, data)

    def test_pem_csr(self):
        csrfile = test_util.vector_path('csr_512.pem')
        data = test_util.load_vector('csr_512.pem')

        assert (OpenSSL.crypto.FILETYPE_PEM,
             util.CSR(file=csrfile,
                      data=data,
                      form="pem"),
             ["Example.com"],) == \
            self._call(csrfile, data)

    def test_bad_csr(self):
        with pytest.raises(errors.Error):
            self._call(test_util.vector_path('cert_512.pem'),
                          test_util.load_vector('cert_512.pem'))


class MakeKeyTest(unittest.TestCase):
    """Tests for certbot.crypto_util.make_key."""

    def test_rsa(self):  # pylint: disable=no-self-use
        # RSA Key Type Test
        from certbot.crypto_util import make_key

        # Do not test larger keys as it takes too long.
        serialization.load_pem_private_key(make_key(2048), password=None)

    def test_ec(self):  # pylint: disable=no-self-use
        # ECDSA Key Type Tests
        from certbot.crypto_util import make_key

        for (name, bits) in [('secp256r1', 256), ('secp384r1', 384), ('secp521r1', 521)]:
            pkey = serialization.load_pem_private_key(
                make_key(elliptic_curve=name, key_type='ecdsa'),
                password=None
            )
            assert isinstance(pkey, ec.EllipticCurvePrivateKey)
            assert pkey.curve.key_size == bits

    def test_bad_key_sizes(self):
        from certbot.crypto_util import make_key

        # Try a bad key size for RSA and ECDSA
        with pytest.raises(errors.Error, match='Unsupported RSA key length: 1024'):
            make_key(bits=1024, key_type='rsa')

    def test_bad_elliptic_curve_name(self):
        from certbot.crypto_util import make_key
        with pytest.raises(errors.Error, match='Unsupported elliptic curve: nothere'):
            make_key(elliptic_curve="nothere", key_type='ecdsa')

    def test_bad_key_type(self):
        from certbot.crypto_util import make_key

        # Try a bad --key-type
        with pytest.raises(errors.Error,
                           match=re.escape('Invalid key_type specified: unf.  Use [rsa|ecdsa]')):
            make_key(2048, key_type='unf')

    def test_for_pkcs8_format(self):
        from certbot.crypto_util import make_key

        # PKCS#1 format will instead have text like "BEGIN RSA PRIVATE KEY" or "BEGIN EC PRIVATE
        # KEY"
        assert b"BEGIN PRIVATE KEY" in make_key(2048)
        assert b"BEGIN PRIVATE KEY" in make_key(elliptic_curve='secp256r1', key_type='ecdsa')


class VerifyCertSetup(unittest.TestCase):
    """Refactoring for verification tests."""

    def setUp(self):
        self.renewable_cert = mock.MagicMock()
        self.renewable_cert.cert_path = SS_CERT_PATH
        self.renewable_cert.chain_path = SS_CERT_PATH
        self.renewable_cert.key_path = RSA2048_KEY_PATH
        self.renewable_cert.fullchain_path = test_util.vector_path('cert_fullchain_2048.pem')

        self.bad_renewable_cert = mock.MagicMock()
        self.bad_renewable_cert.chain_path = SS_CERT_PATH
        self.bad_renewable_cert.cert_path = SS_CERT_PATH
        self.bad_renewable_cert.fullchain_path = SS_CERT_PATH


class VerifyRenewableCertTest(VerifyCertSetup):
    """Tests for certbot.crypto_util.verify_renewable_cert."""

    def _call(self, renewable_cert):
        from certbot.crypto_util import verify_renewable_cert
        return verify_renewable_cert(renewable_cert)

    def test_verify_renewable_cert(self):
        assert self._call(self.renewable_cert) is None

    @mock.patch('certbot.crypto_util.verify_renewable_cert_sig', side_effect=errors.Error(""))
    def test_verify_renewable_cert_failure(self, unused_verify_renewable_cert_sign):
        with pytest.raises(errors.Error):
            self._call(self.bad_renewable_cert)


class VerifyRenewableCertSigTest(VerifyCertSetup):
    """Tests for certbot.crypto_util.verify_renewable_cert."""

    def _call(self, renewable_cert):
        from certbot.crypto_util import verify_renewable_cert_sig
        return verify_renewable_cert_sig(renewable_cert)

    def test_cert_sig_match(self):
        assert self._call(self.renewable_cert) is None

    def test_cert_sig_match_ec(self):
        renewable_cert = mock.MagicMock()
        renewable_cert.cert_path = P256_CERT_PATH
        renewable_cert.chain_path = P256_CERT_PATH
        renewable_cert.key_path = P256_KEY
        assert self._call(renewable_cert) is None

    def test_cert_sig_mismatch(self):
        self.bad_renewable_cert.cert_path = test_util.vector_path('cert_512_bad.pem')
        with pytest.raises(errors.Error):
            self._call(self.bad_renewable_cert)


class VerifyFullchainTest(VerifyCertSetup):
    """Tests for certbot.crypto_util.verify_fullchain."""

    def _call(self, renewable_cert):
        from certbot.crypto_util import verify_fullchain
        return verify_fullchain(renewable_cert)

    def test_fullchain_matches(self):
        assert self._call(self.renewable_cert) is None

    def test_fullchain_mismatch(self):
        with pytest.raises(errors.Error):
            self._call(self.bad_renewable_cert)

    def test_fullchain_ioerror(self):
        self.bad_renewable_cert.chain = "dog"
        with pytest.raises(errors.Error):
            self._call(self.bad_renewable_cert)


class VerifyCertMatchesPrivKeyTest(VerifyCertSetup):
    """Tests for certbot.crypto_util.verify_cert_matches_priv_key."""

    def _call(self, renewable_cert):
        from certbot.crypto_util import verify_cert_matches_priv_key
        return verify_cert_matches_priv_key(renewable_cert.cert, renewable_cert.privkey)

    def test_cert_priv_key_match(self):
        self.renewable_cert.cert = SS_CERT_PATH
        self.renewable_cert.privkey = RSA2048_KEY_PATH
        assert self._call(self.renewable_cert) is None

    def test_cert_priv_key_mismatch(self):
        self.bad_renewable_cert.privkey = RSA256_KEY_PATH
        self.bad_renewable_cert.cert = SS_CERT_PATH

        with pytest.raises(errors.Error):
            self._call(self.bad_renewable_cert)


class ValidPrivkeyTest(unittest.TestCase):
    """Tests for certbot.crypto_util.valid_privkey."""

    @classmethod
    def _call(cls, privkey):
        from certbot.crypto_util import valid_privkey
        return valid_privkey(privkey)

    def test_valid_true(self):
        assert self._call(RSA512_KEY)

    def test_empty_false(self):
        assert not self._call('')

    def test_random_false(self):
        assert not self._call('foo bar')


class GetSANsFromCertTest(unittest.TestCase):
    """Tests for certbot.crypto_util.get_sans_from_cert."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.crypto_util import get_sans_from_cert
        return get_sans_from_cert(*args, **kwargs)

    def test_single(self):
        assert [] == self._call(test_util.load_vector('cert_512.pem'))

    def test_san(self):
        assert ['example.com', 'www.example.com'] == \
            self._call(test_util.load_vector('cert-san_512.pem'))


class GetNamesFromCertTest(unittest.TestCase):
    """Tests for certbot.crypto_util.get_names_from_cert."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.crypto_util import get_names_from_cert
        return get_names_from_cert(*args, **kwargs)

    def test_single(self):
        assert ['example.com'] == \
            self._call(test_util.load_vector('cert_512.pem'))

    def test_san(self):
        assert ['example.com', 'www.example.com'] == \
            self._call(test_util.load_vector('cert-san_512.pem'))

    def test_common_name_sans_order(self):
        # Tests that the common name comes first
        # followed by the SANS in alphabetical order
        assert ['example.com'] + ['{0}.example.com'.format(c) for c in 'abcd'] == \
            self._call(test_util.load_vector('cert-5sans_512.pem'))

    def test_parse_non_cert(self):
        with pytest.raises(ValueError):
            self._call(b"hello there")


class GetNamesFromReqTest(unittest.TestCase):
    """Tests for certbot.crypto_util.get_names_from_req."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.crypto_util import get_names_from_req
        return get_names_from_req(*args, **kwargs)

    def test_nonames(self):
        assert [] == \
            self._call(test_util.load_vector('csr-nonames_512.pem'))

    def test_nosans(self):
        assert ['example.com'] == \
            self._call(test_util.load_vector('csr-nosans_512.pem'))

    def test_sans(self):
        assert ['example.com', 'example.org', 'example.net', 'example.info',
             'subdomain.example.com', 'other.subdomain.example.com'] == \
            self._call(test_util.load_vector('csr-6sans_512.pem'))

    def test_der(self):
        from OpenSSL.crypto import FILETYPE_ASN1
        assert ['Example.com'] == \
            self._call(test_util.load_vector('csr_512.der'), typ=FILETYPE_ASN1)


class CertLoaderTest(unittest.TestCase):
    """Tests for certbot.crypto_util.pyopenssl_load_certificate"""

    def test_load_valid_cert(self):
        from certbot.crypto_util import pyopenssl_load_certificate

        cert, file_type = pyopenssl_load_certificate(CERT)
        assert file_type == OpenSSL.crypto.FILETYPE_PEM
        assert binascii.unhexlify(
            cert.digest("sha256").replace(b":", b"")
        ) == x509.load_pem_x509_certificate(CERT).fingerprint(hashes.SHA256())

    def test_load_invalid_cert(self):
        from certbot.crypto_util import pyopenssl_load_certificate
        bad_cert_data = CERT.replace(b"BEGIN CERTIFICATE", b"ASDFASDFASDF!!!")
        with pytest.raises(errors.Error):
            pyopenssl_load_certificate(bad_cert_data)


class NotBeforeTest(unittest.TestCase):
    """Tests for certbot.crypto_util.notBefore"""

    def test_notBefore(self):
        from certbot.crypto_util import notBefore
        assert notBefore(CERT_PATH).isoformat() == \
                         '2014-12-11T22:34:45+00:00'


class NotAfterTest(unittest.TestCase):
    """Tests for certbot.crypto_util.notAfter"""

    def test_notAfter(self):
        from certbot.crypto_util import notAfter
        assert notAfter(CERT_PATH).isoformat() == \
                         '2014-12-18T22:34:45+00:00'
        
class GetAriSuffixTest(unittest.TestCase):
    def test_getAriSuffix(self):
        from certbot.crypto_util import ariCertIdent
        assert ariCertIdent(SS_CERT_PATH) == \
        'nSfvjNtwFty5BQ-yyobB-4C-v9o.AIYLtIQHBBG0'


class Sha256sumTest(unittest.TestCase):
    """Tests for certbot.crypto_util.notAfter"""
    def test_sha256sum(self):
        from certbot.crypto_util import sha256sum
        assert sha256sum(CERT_PATH) == \
            '914ffed8daf9e2c99d90ac95c77d54f32cbd556672facac380f0c063498df84e'


class CertAndChainFromFullchainTest(unittest.TestCase):
    """Tests for certbot.crypto_util.cert_and_chain_from_fullchain"""

    def _parse_and_reencode_pem(self, cert_pem):
        from OpenSSL import crypto
        return crypto.dump_certificate(crypto.FILETYPE_PEM,
            crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)).decode()

    def test_cert_and_chain_from_fullchain(self):
        cert_pem = CERT.decode()
        chain_pem = cert_pem + SS_CERT.decode()
        fullchain_pem = cert_pem + chain_pem
        spacey_fullchain_pem = cert_pem + u'\n' + chain_pem
        crlf_fullchain_pem = fullchain_pem.replace(u'\n', u'\r\n')

        # In the ACME v1 code path, the fullchain is constructed by loading cert+chain DERs
        # and using OpenSSL to dump them, so here we confirm that OpenSSL is producing certs
        # that will be parseable by cert_and_chain_from_fullchain.
        acmev1_fullchain_pem = self._parse_and_reencode_pem(cert_pem) + \
            self._parse_and_reencode_pem(cert_pem) + self._parse_and_reencode_pem(SS_CERT.decode())

        from certbot.crypto_util import cert_and_chain_from_fullchain
        for fullchain in (fullchain_pem, spacey_fullchain_pem, crlf_fullchain_pem,
                          acmev1_fullchain_pem):
            cert_out, chain_out = cert_and_chain_from_fullchain(fullchain)
            assert cert_out == cert_pem
            assert chain_out == chain_pem

        with pytest.raises(errors.Error):
            cert_and_chain_from_fullchain(cert_pem)


class FindChainWithIssuerTest(unittest.TestCase):
    """Tests for certbot.crypto_util.find_chain_with_issuer"""

    @classmethod
    def _call(cls, fullchains, issuer_cn, **kwargs):
        from certbot.crypto_util import find_chain_with_issuer
        return find_chain_with_issuer(fullchains, issuer_cn, kwargs)

    def _all_fullchains(self):
        return [CERT_LEAF.decode() + CERT_ISSUER.decode(),
                CERT_LEAF.decode() + CERT_ALT_ISSUER.decode()]

    def test_positive_match(self):
        """Correctly pick the chain based on the root's CN"""
        fullchains = self._all_fullchains()
        matched = self._call(fullchains, "Pebble Root CA 0cc6f0")
        assert matched == fullchains[1]

    @mock.patch('certbot.crypto_util.logger.info')
    def test_intermediate_match(self, mock_info):
        """Don't pick a chain where only an intermediate matches"""
        fullchains = self._all_fullchains()
        # Make the second chain actually only contain "Pebble Root CA 0cc6f0"
        # as an intermediate, not as the root. This wouldn't be a valid chain
        # (the CERT_ISSUER cert didn't issue the CERT_ALT_ISSUER cert), but the
        # function under test here doesn't care about that.
        fullchains[1] = fullchains[1] + CERT_ISSUER.decode()
        matched = self._call(fullchains, "Pebble Root CA 0cc6f0")
        assert matched == fullchains[0]
        mock_info.assert_not_called()

    @mock.patch('certbot.crypto_util.logger.info')
    def test_no_match(self, mock_info):
        fullchains = self._all_fullchains()
        matched = self._call(fullchains, "non-existent issuer")
        assert matched == fullchains[0]
        mock_info.assert_not_called()

    @mock.patch('certbot.crypto_util.logger.warning')
    def test_warning_on_no_match(self, mock_warning):
        fullchains = self._all_fullchains()
        matched = self._call(fullchains, "non-existent issuer",
                             warn_on_no_match=True)
        assert matched == fullchains[0]
        mock_warning.assert_called_once_with("Certbot has been configured to prefer "
            "certificate chains with issuer '%s', but no chain from the CA matched "
            "this issuer. Using the default certificate chain instead.",
            "non-existent issuer")


if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
