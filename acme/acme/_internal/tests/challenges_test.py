"""Tests for acme.challenges."""
import sys
import unittest
from unittest import mock
import urllib.parse as urllib_parse

import josepy as jose
from josepy.jwk import JWKEC
import OpenSSL
import pytest
import requests

from acme import errors
from acme._internal.tests import test_util

CERT = test_util.load_cert('cert.pem')
KEY = jose.JWKRSA(key=test_util.load_rsa_private_key('rsa512_key.pem'))


class ChallengeTest(unittest.TestCase):

    def test_from_json_unrecognized(self):
        from acme.challenges import Challenge
        from acme.challenges import UnrecognizedChallenge
        chall = UnrecognizedChallenge({"type": "foo"})
        assert chall == Challenge.from_json(chall.jobj)


class UnrecognizedChallengeTest(unittest.TestCase):

    def setUp(self):
        from acme.challenges import UnrecognizedChallenge
        self.jobj = {"type": "foo"}
        self.chall = UnrecognizedChallenge(self.jobj)

    def test_to_partial_json(self):
        assert self.jobj == self.chall.to_partial_json()

    def test_from_json(self):
        from acme.challenges import UnrecognizedChallenge
        assert self.chall == UnrecognizedChallenge.from_json(self.jobj)


class KeyAuthorizationChallengeResponseTest(unittest.TestCase):

    def setUp(self):
        def _encode(name):
            assert name == "token"
            return "foo"
        self.chall = mock.Mock()
        self.chall.encode.side_effect = _encode

    def test_verify_ok(self):
        from acme.challenges import KeyAuthorizationChallengeResponse
        response = KeyAuthorizationChallengeResponse(
            key_authorization='foo.oKGqedy-b-acd5eoybm2f-NVFxvyOoET5CNy3xnv8WY')
        assert response.verify(self.chall, KEY.public_key())

    def test_verify_wrong_token(self):
        from acme.challenges import KeyAuthorizationChallengeResponse
        response = KeyAuthorizationChallengeResponse(
            key_authorization='bar.oKGqedy-b-acd5eoybm2f-NVFxvyOoET5CNy3xnv8WY')
        assert not response.verify(self.chall, KEY.public_key())

    def test_verify_wrong_thumbprint(self):
        from acme.challenges import KeyAuthorizationChallengeResponse
        response = KeyAuthorizationChallengeResponse(
            key_authorization='foo.oKGqedy-b-acd5eoybm2f-NVFxv')
        assert not response.verify(self.chall, KEY.public_key())

    def test_verify_wrong_form(self):
        from acme.challenges import KeyAuthorizationChallengeResponse
        response = KeyAuthorizationChallengeResponse(
            key_authorization='.foo.oKGqedy-b-acd5eoybm2f-'
            'NVFxvyOoET5CNy3xnv8WY')
        assert not response.verify(self.chall, KEY.public_key())


class DNS01ResponseTest(unittest.TestCase):

    def setUp(self):
        from acme.challenges import DNS01Response
        self.msg = DNS01Response(key_authorization=u'foo')
        self.jmsg = {
            'resource': 'challenge',
            'type': 'dns-01',
            'keyAuthorization': u'foo',
        }

        from acme.challenges import DNS01
        self.chall = DNS01(token=(b'x' * 16))
        self.response = self.chall.response(KEY)

    def test_to_partial_json(self):
        assert {} == self.msg.to_partial_json()

    def test_from_json(self):
        from acme.challenges import DNS01Response
        assert self.msg == DNS01Response.from_json(self.jmsg)

    def test_from_json_hashable(self):
        from acme.challenges import DNS01Response
        hash(DNS01Response.from_json(self.jmsg))

    def test_simple_verify_failure(self):
        key2 = jose.JWKRSA.load(test_util.load_vector('rsa256_key.pem'))
        public_key = key2.public_key()
        verified = self.response.simple_verify(self.chall, "local", public_key)
        assert not verified

    def test_simple_verify_success(self):
        public_key = KEY.public_key()
        verified = self.response.simple_verify(self.chall, "local", public_key)
        assert verified


class DNS01Test(unittest.TestCase):

    def setUp(self):
        from acme.challenges import DNS01
        self.msg = DNS01(token=jose.decode_b64jose(
            'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ+PCt92wr+oA'))
        self.jmsg = {
            'type': 'dns-01',
            'token': 'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA',
        }

    def test_validation_domain_name(self):
        assert '_acme-challenge.www.example.com' == \
                         self.msg.validation_domain_name('www.example.com')

    def test_validation(self):
        assert "rAa7iIg4K2y63fvUhCfy8dP1Xl7wEhmQq0oChTcE3Zk" == \
            self.msg.validation(KEY)

    def test_to_partial_json(self):
        assert self.jmsg == self.msg.to_partial_json()

    def test_from_json(self):
        from acme.challenges import DNS01
        assert self.msg == DNS01.from_json(self.jmsg)

    def test_from_json_hashable(self):
        from acme.challenges import DNS01
        hash(DNS01.from_json(self.jmsg))


class HTTP01ResponseTest(unittest.TestCase):

    def setUp(self):
        from acme.challenges import HTTP01Response
        self.msg = HTTP01Response(key_authorization=u'foo')
        self.jmsg = {
            'resource': 'challenge',
            'type': 'http-01',
            'keyAuthorization': u'foo',
        }

        from acme.challenges import HTTP01
        self.chall = HTTP01(token=(b'x' * 16))
        self.response = self.chall.response(KEY)

    def test_to_partial_json(self):
        assert {} == self.msg.to_partial_json()

    def test_from_json(self):
        from acme.challenges import HTTP01Response
        assert self.msg == HTTP01Response.from_json(self.jmsg)

    def test_from_json_hashable(self):
        from acme.challenges import HTTP01Response
        hash(HTTP01Response.from_json(self.jmsg))

    def test_simple_verify_bad_key_authorization(self):
        key2 = jose.JWKRSA.load(test_util.load_vector('rsa256_key.pem'))
        self.response.simple_verify(self.chall, "local", key2.public_key())

    @mock.patch("acme.challenges.requests.get")
    def test_simple_verify_good_validation(self, mock_get):
        validation = self.chall.validation(KEY)
        mock_get.return_value = mock.MagicMock(text=validation)
        assert self.response.simple_verify(
            self.chall, "local", KEY.public_key())
        mock_get.assert_called_once_with(self.chall.uri("local"), verify=False,
                                         timeout=mock.ANY)

    @mock.patch("acme.challenges.requests.get")
    def test_simple_verify_bad_validation(self, mock_get):
        mock_get.return_value = mock.MagicMock(text="!")
        assert not self.response.simple_verify(
            self.chall, "local", KEY.public_key())

    @mock.patch("acme.challenges.requests.get")
    def test_simple_verify_whitespace_validation(self, mock_get):
        from acme.challenges import HTTP01Response
        mock_get.return_value = mock.MagicMock(
            text=(self.chall.validation(KEY) +
                  HTTP01Response.WHITESPACE_CUTSET))
        assert self.response.simple_verify(
            self.chall, "local", KEY.public_key())
        mock_get.assert_called_once_with(self.chall.uri("local"), verify=False,
                                         timeout=mock.ANY)

    @mock.patch("acme.challenges.requests.get")
    def test_simple_verify_connection_error(self, mock_get):
        mock_get.side_effect = requests.exceptions.RequestException
        assert not self.response.simple_verify(
            self.chall, "local", KEY.public_key())

    @mock.patch("acme.challenges.requests.get")
    def test_simple_verify_port(self, mock_get):
        self.response.simple_verify(
            self.chall, domain="local",
            account_public_key=KEY.public_key(), port=8080)
        assert "local:8080" == urllib_parse.urlparse(
            mock_get.mock_calls[0][1][0]).netloc

    @mock.patch("acme.challenges.requests.get")
    def test_simple_verify_timeout(self, mock_get):
        self.response.simple_verify(self.chall, "local", KEY.public_key())
        mock_get.assert_called_once_with(self.chall.uri("local"), verify=False,
                                         timeout=30)
        mock_get.reset_mock()
        self.response.simple_verify(self.chall, "local", KEY.public_key(), timeout=1234)
        mock_get.assert_called_once_with(self.chall.uri("local"), verify=False,
                                         timeout=1234)


class HTTP01Test(unittest.TestCase):

    def setUp(self):
        from acme.challenges import HTTP01
        self.msg = HTTP01(
            token=jose.decode_b64jose(
                'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ+PCt92wr+oA'))
        self.jmsg = {
            'type': 'http-01',
            'token': 'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA',
        }

    def test_path(self):
        assert self.msg.path == '/.well-known/acme-challenge/' \
                         'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA'

    def test_uri(self):
        assert 'http://example.com/.well-known/acme-challenge/' \
            'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA' == \
            self.msg.uri('example.com')

    def test_to_partial_json(self):
        assert self.jmsg == self.msg.to_partial_json()

    def test_from_json(self):
        from acme.challenges import HTTP01
        assert self.msg == HTTP01.from_json(self.jmsg)

    def test_from_json_hashable(self):
        from acme.challenges import HTTP01
        hash(HTTP01.from_json(self.jmsg))

    def test_good_token(self):
        assert self.msg.good_token
        assert not self.msg.update(token=b'..').good_token


class TLSALPN01ResponseTest(unittest.TestCase):

    def setUp(self):
        from acme.challenges import TLSALPN01
        self.chall = TLSALPN01(
            token=jose.b64decode(b'a82d5ff8ef740d12881f6d3c2277ab2e'))
        self.domain = u'example.com'
        self.domain2 = u'example2.com'

        self.response = self.chall.response(KEY)
        self.jmsg = {
            'resource': 'challenge',
            'type': 'tls-alpn-01',
            'keyAuthorization': self.response.key_authorization,
        }

    def test_to_partial_json(self):
        assert {} == self.response.to_partial_json()

    def test_from_json(self):
        from acme.challenges import TLSALPN01Response
        assert self.response == TLSALPN01Response.from_json(self.jmsg)

    def test_from_json_hashable(self):
        from acme.challenges import TLSALPN01Response
        hash(TLSALPN01Response.from_json(self.jmsg))

    def test_gen_verify_cert(self):
        key1 = test_util.load_pyopenssl_private_key('rsa512_key.pem')
        cert, key2 = self.response.gen_cert(self.domain, key1)
        assert key1 == key2
        assert self.response.verify_cert(self.domain, cert)

    def test_gen_verify_cert_gen_key(self):
        cert, key = self.response.gen_cert(self.domain)
        assert isinstance(key, OpenSSL.crypto.PKey)
        assert self.response.verify_cert(self.domain, cert)

    def test_verify_bad_cert(self):
        assert not self.response.verify_cert(self.domain,
            test_util.load_cert('cert.pem'))

    def test_verify_bad_domain(self):
        key1 = test_util.load_pyopenssl_private_key('rsa512_key.pem')
        cert, key2 = self.response.gen_cert(self.domain, key1)
        assert key1 == key2
        assert not self.response.verify_cert(self.domain2, cert)

    def test_simple_verify_bad_key_authorization(self):
        key2 = jose.JWKRSA.load(test_util.load_vector('rsa256_key.pem'))
        self.response.simple_verify(self.chall, "local", key2.public_key())

    @mock.patch('acme.challenges.TLSALPN01Response.verify_cert', autospec=True)
    def test_simple_verify(self, mock_verify_cert):
        mock_verify_cert.return_value = mock.sentinel.verification
        assert mock.sentinel.verification == self.response.simple_verify(
                self.chall, self.domain, KEY.public_key(),
                cert=mock.sentinel.cert)
        mock_verify_cert.assert_called_once_with(
            self.response, self.domain, mock.sentinel.cert)

    @mock.patch('acme.challenges.socket.gethostbyname')
    @mock.patch('acme.challenges.crypto_util.probe_sni')
    def test_probe_cert(self, mock_probe_sni, mock_gethostbyname):
        mock_gethostbyname.return_value = '127.0.0.1'
        self.response.probe_cert('foo.com')
        mock_gethostbyname.assert_called_once_with('foo.com')
        mock_probe_sni.assert_called_once_with(
            host=b'127.0.0.1', port=self.response.PORT, name=b'foo.com',
            alpn_protocols=[b'acme-tls/1'])

        self.response.probe_cert('foo.com', host='8.8.8.8')
        mock_probe_sni.assert_called_with(
            host=b'8.8.8.8', port=mock.ANY, name=b'foo.com',
            alpn_protocols=[b'acme-tls/1'])

    @mock.patch('acme.challenges.TLSALPN01Response.probe_cert')
    def test_simple_verify_false_on_probe_error(self, mock_probe_cert):
        mock_probe_cert.side_effect = errors.Error
        assert not self.response.simple_verify(
            self.chall, self.domain, KEY.public_key())


class TLSALPN01Test(unittest.TestCase):

    def setUp(self):
        from acme.challenges import TLSALPN01
        self.msg = TLSALPN01(
            token=jose.b64decode('a82d5ff8ef740d12881f6d3c2277ab2e'))
        self.jmsg = {
            'type': 'tls-alpn-01',
            'token': 'a82d5ff8ef740d12881f6d3c2277ab2e',
        }

    def test_to_partial_json(self):
        assert self.jmsg == self.msg.to_partial_json()

    def test_from_json(self):
        from acme.challenges import TLSALPN01
        assert self.msg == TLSALPN01.from_json(self.jmsg)

    def test_from_json_hashable(self):
        from acme.challenges import TLSALPN01
        hash(TLSALPN01.from_json(self.jmsg))

    def test_from_json_invalid_token_length(self):
        from acme.challenges import TLSALPN01
        self.jmsg['token'] = jose.encode_b64jose(b'abcd')
        with pytest.raises(jose.DeserializationError):
            TLSALPN01.from_json(self.jmsg)

    @mock.patch('acme.challenges.TLSALPN01Response.gen_cert')
    def test_validation(self, mock_gen_cert):
        mock_gen_cert.return_value = ('cert', 'key')
        assert ('cert', 'key') == self.msg.validation(
            KEY, cert_key=mock.sentinel.cert_key, domain=mock.sentinel.domain)
        mock_gen_cert.assert_called_once_with(key=mock.sentinel.cert_key,
                                              domain=mock.sentinel.domain)


class DNSTest(unittest.TestCase):

    def setUp(self):
        from acme.challenges import DNS
        self.msg = DNS(token=jose.b64decode(
            b'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA'))
        self.jmsg = {
            'type': 'dns',
            'token': 'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA',
        }

    def test_to_partial_json(self):
        assert self.jmsg == self.msg.to_partial_json()

    def test_from_json(self):
        from acme.challenges import DNS
        assert self.msg == DNS.from_json(self.jmsg)

    def test_from_json_hashable(self):
        from acme.challenges import DNS
        hash(DNS.from_json(self.jmsg))

    def test_gen_check_validation(self):
        ec_key_secp384r1 = JWKEC(key=test_util.load_ecdsa_private_key('ec_secp384r1_key.pem'))
        for key, alg in [(KEY, jose.RS256), (ec_key_secp384r1, jose.ES384)]:
            with self.subTest(key=key, alg=alg):
                assert self.msg.check_validation(
                    self.msg.gen_validation(key, alg=alg), key.public_key())

    def test_gen_check_validation_wrong_key(self):
        key2 = jose.JWKRSA.load(test_util.load_vector('rsa1024_key.pem'))
        assert not self.msg.check_validation(
            self.msg.gen_validation(KEY), key2.public_key())

    def test_check_validation_wrong_payload(self):
        validations = tuple(
            jose.JWS.sign(payload=payload, alg=jose.RS256, key=KEY)
            for payload in (b'', b'{}')
        )
        for validation in validations:
            assert not self.msg.check_validation(
                validation, KEY.public_key())

    def test_check_validation_wrong_fields(self):
        bad_validation = jose.JWS.sign(
            payload=self.msg.update(
                token=b'x' * 20).json_dumps().encode('utf-8'),
            alg=jose.RS256, key=KEY)
        assert not self.msg.check_validation(bad_validation, KEY.public_key())

    def test_gen_response(self):
        with mock.patch('acme.challenges.DNS.gen_validation') as mock_gen:
            mock_gen.return_value = mock.sentinel.validation
            response = self.msg.gen_response(KEY)
        from acme.challenges import DNSResponse
        assert isinstance(response, DNSResponse)
        assert response.validation == mock.sentinel.validation

    def test_validation_domain_name(self):
        assert '_acme-challenge.le.wtf' == self.msg.validation_domain_name('le.wtf')

    def test_validation_domain_name_ecdsa(self):
        ec_key_secp384r1 = JWKEC(key=test_util.load_ecdsa_private_key('ec_secp384r1_key.pem'))
        assert self.msg.check_validation(
            self.msg.gen_validation(ec_key_secp384r1, alg=jose.ES384),
            ec_key_secp384r1.public_key()) is True


class DNSResponseTest(unittest.TestCase):

    def setUp(self):
        from acme.challenges import DNS
        self.chall = DNS(token=jose.b64decode(
            b"evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"))
        self.validation = jose.JWS.sign(
            payload=self.chall.json_dumps(sort_keys=True).encode(),
            key=KEY, alg=jose.RS256)

        from acme.challenges import DNSResponse
        self.msg = DNSResponse(validation=self.validation)
        self.jmsg_to = {
            'validation': self.validation,
        }
        self.jmsg_from = {
            'resource': 'challenge',
            'type': 'dns',
            'validation': self.validation.to_json(),
        }

    def test_to_partial_json(self):
        assert self.jmsg_to == self.msg.to_partial_json()

    def test_from_json(self):
        from acme.challenges import DNSResponse
        assert self.msg == DNSResponse.from_json(self.jmsg_from)

    def test_from_json_hashable(self):
        from acme.challenges import DNSResponse
        hash(DNSResponse.from_json(self.jmsg_from))

    def test_check_validation(self):
        assert self.msg.check_validation(self.chall, KEY.public_key())


class JWSPayloadRFC8555Compliant(unittest.TestCase):
    """Test for RFC8555 compliance of JWS generated from resources/challenges"""
    def test_challenge_payload(self):
        from acme.challenges import HTTP01Response

        challenge_body = HTTP01Response()

        jobj = challenge_body.json_dumps(indent=2).encode()
        # RFC8555 states that challenge responses must have an empty payload.
        assert jobj == b'{}'


if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
