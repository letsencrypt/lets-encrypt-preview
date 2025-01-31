"""Tests for acme.messages."""
import sys
from typing import Dict
import unittest
from unittest import mock

import josepy as jose
import pytest

from acme import challenges
from acme._internal.tests import test_util

CERT = test_util.load_comparable_cert('cert.der')
CSR = test_util.load_comparable_csr('csr.der')
KEY = test_util.load_rsa_private_key('rsa512_key.pem')


class ErrorTest(unittest.TestCase):
    """Tests for acme.messages.Error."""

    def setUp(self):
        from acme.messages import Error
        from acme.messages import ERROR_PREFIX
        from acme.messages import Identifier
        from acme.messages import IDENTIFIER_FQDN
        self.error = Error.with_code('malformed', detail='foo', title='title')
        self.jobj = {
            'detail': 'foo',
            'title': 'some title',
            'type': ERROR_PREFIX + 'malformed',
        }
        self.error_custom = Error(typ='custom', detail='bar')
        self.identifier = Identifier(typ=IDENTIFIER_FQDN, value='example.com')
        self.subproblem = Error.with_code('caa', detail='bar', title='title', identifier=self.identifier)
        self.error_with_subproblems = Error.with_code('malformed', detail='foo', title='title', subproblems=[self.subproblem])
        self.empty_error = Error()

    def test_default_typ(self):
        from acme.messages import Error
        assert Error().typ == 'about:blank'

    def test_from_json_empty(self):
        from acme.messages import Error
        assert Error() == Error.from_json('{}')

    def test_from_json_hashable(self):
        from acme.messages import Error
        hash(Error.from_json(self.error.to_json()))

    def test_from_json_with_subproblems(self):
        from acme.messages import Error

        parsed_error = Error.from_json(self.error_with_subproblems.to_json())

        assert 1 == len(parsed_error.subproblems)
        assert self.subproblem == parsed_error.subproblems[0]

    def test_description(self):
        assert 'The request message was malformed' == self.error.description
        assert self.error_custom.description is None

    def test_code(self):
        from acme.messages import Error
        assert 'malformed' == self.error.code
        assert self.error_custom.code is None
        assert Error().code is None

    def test_is_acme_error(self):
        from acme.messages import Error
        from acme.messages import is_acme_error
        assert is_acme_error(self.error)
        assert not is_acme_error(self.error_custom)
        assert not is_acme_error(Error())
        assert not is_acme_error(self.empty_error)
        assert not is_acme_error("must pet all the {dogs|rabbits}")

    def test_unicode_error(self):
        from acme.messages import Error
        from acme.messages import is_acme_error
        arabic_error = Error.with_code(
            'malformed', detail=u'\u0639\u062f\u0627\u0644\u0629', title='title')
        assert is_acme_error(arabic_error)

    def test_with_code(self):
        from acme.messages import Error
        from acme.messages import is_acme_error
        assert is_acme_error(Error.with_code('badCSR'))
        with pytest.raises(ValueError):
            Error.with_code('not an ACME error code')

    def test_str(self):
        assert str(self.error) == \
            u"{0.typ} :: {0.description} :: {0.detail} :: {0.title}" \
            .format(self.error)
        assert str(self.error_with_subproblems) == \
            (u"{0.typ} :: {0.description} :: {0.detail} :: {0.title}\n"+
            u"Problem for {1.identifier.value}: {1.typ} :: {1.description} :: {1.detail} :: {1.title}").format(
        self.error_with_subproblems, self.subproblem)

    # this test is based on a minimal reproduction of a contextmanager/immutable
    # exception related error: https://github.com/python/cpython/issues/99856
    def test_setting_traceback(self):
        assert self.error_custom.__traceback__ is None

        try:
            1/0
        except ZeroDivisionError as e:
            self.error_custom.__traceback__ = e.__traceback__

        assert self.error_custom.__traceback__ is not None


class ConstantTest(unittest.TestCase):
    """Tests for acme.messages._Constant."""

    def setUp(self):
        from acme.messages import _Constant

        class MockConstant(_Constant):  # pylint: disable=missing-docstring
            POSSIBLE_NAMES: Dict = {}

        self.MockConstant = MockConstant  # pylint: disable=invalid-name
        self.const_a = MockConstant('a')
        self.const_b = MockConstant('b')

    def test_to_partial_json(self):
        assert 'a' == self.const_a.to_partial_json()
        assert 'b' == self.const_b.to_partial_json()

    def test_from_json(self):
        assert self.const_a == self.MockConstant.from_json('a')
        with pytest.raises(jose.DeserializationError):
            self.MockConstant.from_json('c')

    def test_from_json_hashable(self):
        hash(self.MockConstant.from_json('a'))

    def test_repr(self):
        assert 'MockConstant(a)' == repr(self.const_a)
        assert 'MockConstant(b)' == repr(self.const_b)

    def test_equality(self):
        const_a_prime = self.MockConstant('a')
        assert self.const_a != self.const_b
        assert self.const_a == const_a_prime

        assert self.const_a != self.const_b
        assert self.const_a == const_a_prime


class DirectoryTest(unittest.TestCase):
    """Tests for acme.messages.Directory."""

    def setUp(self):
        from acme.messages import Directory
        self.dir = Directory({
            'newReg': 'reg',
            'newCert': 'cert',
            'meta': Directory.Meta(
                terms_of_service='https://example.com/acme/terms',
                website='https://www.example.com/',
                caa_identities=['example.com'],
            ),
        })

    def test_init_wrong_key_value_success(self):  # pylint: disable=no-self-use
        from acme.messages import Directory
        Directory({'foo': 'bar'})

    def test_getitem(self):
        assert 'reg' == self.dir['newReg']

    def test_getitem_fails_with_key_error(self):
        with pytest.raises(KeyError):
            self.dir.__getitem__('foo')

    def test_getattr(self):
        assert 'reg' == self.dir.newReg

    def test_getattr_fails_with_attribute_error(self):
        with pytest.raises(AttributeError):
            self.dir.__getattr__('foo')

    def test_to_json(self):
        assert self.dir.to_json() == {
            'newReg': 'reg',
            'newCert': 'cert',
            'meta': {
                'termsOfService': 'https://example.com/acme/terms',
                'website': 'https://www.example.com/',
                'caaIdentities': ['example.com'],
            },
        }

    def test_from_json_deserialization_unknown_key_success(self):  # pylint: disable=no-self-use
        from acme.messages import Directory
        Directory.from_json({'foo': 'bar'})

    def test_iter_meta(self):
        result = False
        for k in self.dir.meta:
            if k == 'terms_of_service':
                result = self.dir.meta[k] == 'https://example.com/acme/terms'
        assert result


class ExternalAccountBindingTest(unittest.TestCase):
    def setUp(self):
        from acme.messages import Directory
        self.key = jose.jwk.JWKRSA(key=KEY.public_key())
        self.kid = "kid-for-testing"
        self.hmac_key = "hmac-key-for-testing"
        self.dir = Directory({
            'newAccount': 'http://url/acme/new-account',
        })

    def test_from_data(self):
        from acme.messages import ExternalAccountBinding
        eab = ExternalAccountBinding.from_data(self.key, self.kid, self.hmac_key, self.dir)

        assert len(eab) == 3
        assert sorted(eab.keys()) == sorted(['protected', 'payload', 'signature'])


class RegistrationTest(unittest.TestCase):
    """Tests for acme.messages.Registration."""

    def setUp(self):
        key = jose.jwk.JWKRSA(key=KEY.public_key())
        contact = (
            'mailto:admin@foo.com',
            'tel:1234',
        )
        agreement = 'https://letsencrypt.org/terms'

        from acme.messages import Registration
        self.reg = Registration(key=key, contact=contact, agreement=agreement)
        self.reg_none = Registration()

        self.jobj_to = {
            'contact': contact,
            'agreement': agreement,
            'key': key,
        }
        self.jobj_from = self.jobj_to.copy()
        self.jobj_from['key'] = key.to_json()

    def test_from_data(self):
        from acme.messages import Registration
        reg = Registration.from_data(phone='1234', email='admin@foo.com')
        assert reg.contact == (
            'tel:1234',
            'mailto:admin@foo.com',
        )

    def test_new_registration_from_data_with_eab(self):
        from acme.messages import Directory
        from acme.messages import ExternalAccountBinding
        from acme.messages import NewRegistration
        key = jose.jwk.JWKRSA(key=KEY.public_key())
        kid = "kid-for-testing"
        hmac_key = "hmac-key-for-testing"
        directory = Directory({
            'newAccount': 'http://url/acme/new-account',
        })
        eab = ExternalAccountBinding.from_data(key, kid, hmac_key, directory)
        reg = NewRegistration.from_data(email='admin@foo.com', external_account_binding=eab)
        assert reg.contact == (
            'mailto:admin@foo.com',
        )
        assert sorted(reg.external_account_binding.keys()) == \
                         sorted(['protected', 'payload', 'signature'])

    def test_phones(self):
        assert ('1234',) == self.reg.phones

    def test_emails(self):
        assert ('admin@foo.com',) == self.reg.emails

    def test_to_partial_json(self):
        assert self.jobj_to == self.reg.to_partial_json()

    def test_from_json(self):
        from acme.messages import Registration
        assert self.reg == Registration.from_json(self.jobj_from)

    def test_from_json_hashable(self):
        from acme.messages import Registration
        hash(Registration.from_json(self.jobj_from))

    def test_default_not_transmitted(self):
        from acme.messages import NewRegistration
        empty_new_reg = NewRegistration()
        new_reg_with_contact = NewRegistration(contact=())

        assert empty_new_reg.contact == ()
        assert new_reg_with_contact.contact == ()

        assert 'contact' not in empty_new_reg.to_partial_json()
        assert 'contact' not in empty_new_reg.fields_to_partial_json()
        assert 'contact' in new_reg_with_contact.to_partial_json()
        assert 'contact' in new_reg_with_contact.fields_to_partial_json()


class UpdateRegistrationTest(unittest.TestCase):
    """Tests for acme.messages.UpdateRegistration."""

    def test_empty(self):
        from acme.messages import UpdateRegistration
        jstring = '{"resource": "reg"}'
        assert '{}' == UpdateRegistration().json_dumps()
        assert UpdateRegistration() == UpdateRegistration.json_loads(jstring)


class RegistrationResourceTest(unittest.TestCase):
    """Tests for acme.messages.RegistrationResource."""

    def setUp(self):
        from acme.messages import RegistrationResource
        self.regr = RegistrationResource(
            body=mock.sentinel.body, uri=mock.sentinel.uri,
            terms_of_service=mock.sentinel.terms_of_service)

    def test_to_partial_json(self):
        assert self.regr.to_json() == {
            'body': mock.sentinel.body,
            'uri': mock.sentinel.uri,
            'terms_of_service': mock.sentinel.terms_of_service,
        }


class ChallengeResourceTest(unittest.TestCase):
    """Tests for acme.messages.ChallengeResource."""

    def test_uri(self):
        from acme.messages import ChallengeResource
        assert 'http://challb' == ChallengeResource(body=mock.MagicMock(
            uri='http://challb'), authzr_uri='http://authz').uri


class ChallengeBodyTest(unittest.TestCase):
    """Tests for acme.messages.ChallengeBody."""

    def setUp(self):
        self.chall = challenges.DNS(token=jose.b64decode(
            'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA'))

        from acme.messages import ChallengeBody
        from acme.messages import Error
        from acme.messages import STATUS_INVALID
        self.status = STATUS_INVALID
        error = Error.with_code('serverInternal', detail='Unable to communicate with DNS server')
        self.challb = ChallengeBody(
            uri='http://challb', chall=self.chall, status=self.status,
            error=error)

        self.jobj_to = {
            'url': 'http://challb',
            'status': self.status,
            'type': 'dns',
            'token': 'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA',
            'error': error,
        }
        self.jobj_from = self.jobj_to.copy()
        self.jobj_from['status'] = 'invalid'
        self.jobj_from['error'] = {
            'type': 'urn:ietf:params:acme:error:serverInternal',
            'detail': 'Unable to communicate with DNS server',
        }

    def test_encode(self):
        assert self.challb.encode('uri') == self.challb.uri

    def test_to_partial_json(self):
        assert self.jobj_to == self.challb.to_partial_json()

    def test_from_json(self):
        from acme.messages import ChallengeBody
        assert self.challb == ChallengeBody.from_json(self.jobj_from)

    def test_from_json_hashable(self):
        from acme.messages import ChallengeBody
        hash(ChallengeBody.from_json(self.jobj_from))

    def test_proxy(self):
        assert jose.b64decode(
            'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA') == self.challb.token


class AuthorizationTest(unittest.TestCase):
    """Tests for acme.messages.Authorization."""

    def setUp(self):
        from acme.messages import ChallengeBody
        from acme.messages import STATUS_VALID

        self.challbs = (
            ChallengeBody(
                uri='http://challb1', status=STATUS_VALID,
                chall=challenges.HTTP01(token=b'IlirfxKKXAsHtmzK29Pj8A')),
            ChallengeBody(uri='http://challb2', status=STATUS_VALID,
                          chall=challenges.DNS(
                              token=b'DGyRejmCefe7v4NfDGDKfA')),
        )

        from acme.messages import Authorization
        from acme.messages import Identifier
        from acme.messages import IDENTIFIER_FQDN
        identifier = Identifier(typ=IDENTIFIER_FQDN, value='example.com')
        self.authz = Authorization(
            identifier=identifier, challenges=self.challbs)

        self.jobj_from = {
            'identifier': identifier.to_json(),
            'challenges': [challb.to_json() for challb in self.challbs],
        }

    def test_from_json(self):
        from acme.messages import Authorization
        Authorization.from_json(self.jobj_from)

    def test_from_json_hashable(self):
        from acme.messages import Authorization
        hash(Authorization.from_json(self.jobj_from))


class AuthorizationResourceTest(unittest.TestCase):
    """Tests for acme.messages.AuthorizationResource."""

    def test_json_de_serializable(self):
        from acme.messages import AuthorizationResource
        authzr = AuthorizationResource(
            uri=mock.sentinel.uri,
            body=mock.sentinel.body)
        assert isinstance(authzr, jose.JSONDeSerializable)


class CertificateRequestTest(unittest.TestCase):
    """Tests for acme.messages.CertificateRequest."""

    def setUp(self):
        from acme.messages import CertificateRequest
        self.req = CertificateRequest(csr=CSR)

    def test_json_de_serializable(self):
        assert isinstance(self.req, jose.JSONDeSerializable)
        from acme.messages import CertificateRequest
        assert self.req == CertificateRequest.from_json(self.req.to_json())


class CertificateResourceTest(unittest.TestCase):
    """Tests for acme.messages.CertificateResourceTest."""

    def setUp(self):
        from acme.messages import CertificateResource
        self.certr = CertificateResource(
            body=CERT, uri=mock.sentinel.uri, authzrs=(),
            cert_chain_uri=mock.sentinel.cert_chain_uri)

    def test_json_de_serializable(self):
        assert isinstance(self.certr, jose.JSONDeSerializable)
        from acme.messages import CertificateResource
        assert self.certr == CertificateResource.from_json(self.certr.to_json())


class RevocationTest(unittest.TestCase):
    """Tests for acme.messages.RevocationTest."""

    def setUp(self):
        from acme.messages import Revocation
        self.rev = Revocation(certificate=CERT)

    def test_from_json_hashable(self):
        from acme.messages import Revocation
        hash(Revocation.from_json(self.rev.to_json()))


class OrderResourceTest(unittest.TestCase):
    """Tests for acme.messages.OrderResource."""

    def setUp(self):
        from acme.messages import OrderResource
        self.regr = OrderResource(
            body=mock.sentinel.body, uri=mock.sentinel.uri)

    def test_to_partial_json(self):
        assert self.regr.to_json() == {
            'body': mock.sentinel.body,
            'uri': mock.sentinel.uri,
            'authorizations': None,
        }

    def test_json_de_serializable(self):
        from acme.messages import ChallengeBody
        from acme.messages import STATUS_PENDING
        challbs = (
            ChallengeBody(
                uri='http://challb1', status=STATUS_PENDING,
                chall=challenges.HTTP01(token=b'IlirfxKKXAsHtmzK29Pj8A')),
            ChallengeBody(uri='http://challb2', status=STATUS_PENDING,
                          chall=challenges.DNS(
                              token=b'DGyRejmCefe7v4NfDGDKfA')),
        )

        from acme.messages import Authorization
        from acme.messages import AuthorizationResource
        from acme.messages import Identifier
        from acme.messages import IDENTIFIER_FQDN
        identifier = Identifier(typ=IDENTIFIER_FQDN, value='example.com')
        authz = AuthorizationResource(uri="http://authz1",
                                      body=Authorization(
                                          identifier=identifier,
                                          challenges=challbs))
        from acme.messages import Order
        body = Order(identifiers=(identifier,), status=STATUS_PENDING,
                     authorizations=tuple(challb.uri for challb in challbs))
        from acme.messages import OrderResource
        orderr = OrderResource(uri="http://order1", body=body,
                               csr_pem=b'test blob',
                               authorizations=(authz,))
        self.assertEqual(orderr,
                         OrderResource.from_json(orderr.to_json()))

class NewOrderTest(unittest.TestCase):
    """Tests for acme.messages.NewOrder."""

    def setUp(self):
        from acme.messages import NewOrder
        self.reg = NewOrder(
            identifiers=mock.sentinel.identifiers)

    def test_to_partial_json(self):
        assert self.reg.to_json() == {
            'identifiers': mock.sentinel.identifiers,
        }


class JWSPayloadRFC8555Compliant(unittest.TestCase):
    """Test for RFC8555 compliance of JWS generated from resources/challenges"""
    def test_message_payload(self):
        from acme.messages import NewAuthorization

        new_order = NewAuthorization()

        jobj = new_order.json_dumps(indent=2).encode()
        # RFC8555 states that JWS bodies must not have a resource field.
        assert jobj == b'{}'


if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
