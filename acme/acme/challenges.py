"""ACME Identifier Validation Challenges."""
import abc
import functools
import hashlib
import logging
import socket
from typing import Any
from typing import cast
from typing import Dict
from typing import Mapping
from typing import Optional
from typing import Tuple
from typing import Type
from typing import TypeVar
from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes
import josepy as jose
from OpenSSL import crypto
from OpenSSL import SSL
import requests

from acme import crypto_util
from acme import errors

logger = logging.getLogger(__name__)

GenericChallenge = TypeVar('GenericChallenge', bound='Challenge')


class Challenge(jose.TypedJSONObjectWithFields):
    # _fields_to_partial_json
    """ACME challenge."""
    TYPES: Dict[str, Type['Challenge']] = {}

    @classmethod
    def from_json(cls: Type[GenericChallenge],
                  jobj: Mapping[str, Any]) -> Union[GenericChallenge, 'UnrecognizedChallenge']:
        try:
            return cast(GenericChallenge, super().from_json(jobj))
        except jose.UnrecognizedTypeError as error:
            logger.debug(error)
            return UnrecognizedChallenge.from_json(jobj)


class ChallengeResponse(jose.TypedJSONObjectWithFields):
    # _fields_to_partial_json
    """ACME challenge response."""
    TYPES: Dict[str, Type['ChallengeResponse']] = {}

    def to_partial_json(self) -> Dict[str, Any]:
        # Removes the `type` field which is inserted by TypedJSONObjectWithFields.to_partial_json.
        # This field breaks RFC8555 compliance.
        jobj = super().to_partial_json()
        jobj.pop(self.type_field_name, None)
        return jobj


class UnrecognizedChallenge(Challenge):
    """Unrecognized challenge.

    ACME specification defines a generic framework for challenges and
    defines some standard challenges that are implemented in this
    module. However, other implementations (including peers) might
    define additional challenge types, which should be ignored if
    unrecognized.

    :ivar jobj: Original JSON decoded object.

    """
    jobj: Dict[str, Any]

    def __init__(self, jobj: Mapping[str, Any]) -> None:
        super().__init__()
        object.__setattr__(self, "jobj", jobj)

    def to_partial_json(self) -> Dict[str, Any]:
        return self.jobj  # pylint: disable=no-member

    @classmethod
    def from_json(cls, jobj: Mapping[str, Any]) -> 'UnrecognizedChallenge':
        return cls(jobj)


class _TokenChallenge(Challenge):
    """Challenge with token.

    :ivar bytes token:

    """
    TOKEN_SIZE = 128 // 8  # Based on the entropy value from the spec
    """Minimum size of the :attr:`token` in bytes."""

    # TODO: acme-spec doesn't specify token as base64-encoded value
    token: bytes = jose.field(
        "token", encoder=jose.encode_b64jose, decoder=functools.partial(
            jose.decode_b64jose, size=TOKEN_SIZE, minimum=True))

    # XXX: rename to ~token_good_for_url
    @property
    def good_token(self) -> bool:  # XXX: @token.decoder
        """Is `token` good?

        .. todo:: acme-spec wants "It MUST NOT contain any non-ASCII
           characters", but it should also warrant that it doesn't
           contain ".." or "/"...

        """
        # TODO: check that path combined with uri does not go above
        # URI_ROOT_PATH!
        # pylint: disable=unsupported-membership-test
        return b'..' not in self.token and b'/' not in self.token


class KeyAuthorizationChallengeResponse(ChallengeResponse):
    """Response to Challenges based on Key Authorization.

    :param str key_authorization:

    """
    key_authorization: str = jose.field("keyAuthorization")
    thumbprint_hash_function = hashes.SHA256

    def verify(self, chall: 'KeyAuthorizationChallenge', account_public_key: jose.JWK) -> bool:
        """Verify the key authorization.

        :param KeyAuthorization chall: Challenge that corresponds to
            this response.
        :param JWK account_public_key:

        :return: ``True`` iff verification of the key authorization was
            successful.
        :rtype: bool

        """
        parts = self.key_authorization.split('.')  # pylint: disable=no-member
        if len(parts) != 2:
            logger.debug("Key authorization (%r) is not well formed",
                         self.key_authorization)
            return False

        if parts[0] != chall.encode("token"):
            logger.debug("Mismatching token in key authorization: "
                         "%r instead of %r", parts[0], chall.encode("token"))
            return False

        thumbprint = jose.b64encode(account_public_key.thumbprint(
            hash_function=self.thumbprint_hash_function)).decode()
        if parts[1] != thumbprint:
            logger.debug("Mismatching thumbprint in key authorization: "
                         "%r instead of %r", parts[0], thumbprint)
            return False

        return True

    def to_partial_json(self) -> Dict[str, Any]:
        jobj = super().to_partial_json()
        jobj.pop('keyAuthorization', None)
        return jobj


# TODO: Make this method a generic of K (bound=KeyAuthorizationChallenge), response_cls of type
#  Type[K] and use it in response/response_and_validation return types once Python 3.6 support is
#  dropped (do not support generic ABC classes, see https://github.com/python/typing/issues/449).
class KeyAuthorizationChallenge(_TokenChallenge, metaclass=abc.ABCMeta):
    """Challenge based on Key Authorization.

    :param response_cls: Subclass of `KeyAuthorizationChallengeResponse`
        that will be used to generate ``response``.
    :param str typ: type of the challenge
    """
    typ: str = NotImplemented
    response_cls: Type[KeyAuthorizationChallengeResponse] = NotImplemented
    thumbprint_hash_function = (
        KeyAuthorizationChallengeResponse.thumbprint_hash_function)

    def key_authorization(self, account_key: jose.JWK) -> str:
        """Generate Key Authorization.

        :param JWK account_key:
        :rtype str:

        """
        return self.encode("token") + "." + jose.b64encode(
            account_key.thumbprint(
                hash_function=self.thumbprint_hash_function)).decode()

    def response(self, account_key: jose.JWK) -> KeyAuthorizationChallengeResponse:
        """Generate response to the challenge.

        :param JWK account_key:

        :returns: Response (initialized `response_cls`) to the challenge.
        :rtype: KeyAuthorizationChallengeResponse

        """
        return self.response_cls(  # pylint: disable=not-callable
            key_authorization=self.key_authorization(account_key))

    @abc.abstractmethod
    def validation(self, account_key: jose.JWK, **kwargs: Any) -> Any:
        """Generate validation for the challenge.

        Subclasses must implement this method, but they are likely to
        return completely different data structures, depending on what's
        necessary to complete the challenge. Interpretation of that
        return value must be known to the caller.

        :param JWK account_key:
        :returns: Challenge-specific validation.

        """
        raise NotImplementedError()  # pragma: no cover

    def response_and_validation(self, account_key: jose.JWK, *args: Any, **kwargs: Any
                                ) -> Tuple[KeyAuthorizationChallengeResponse, Any]:
        """Generate response and validation.

        Convenience function that return results of `response` and
        `validation`.

        :param JWK account_key:
        :rtype: tuple

        """
        return (self.response(account_key),
                self.validation(account_key, *args, **kwargs))


@ChallengeResponse.register
class DNS01Response(KeyAuthorizationChallengeResponse):
    """ACME dns-01 challenge response."""
    typ = "dns-01"

    def simple_verify(self, chall: 'DNS01', domain: str, account_public_key: jose.JWK) -> bool:  # pylint: disable=unused-argument
        """Simple verify.

        This method no longer checks DNS records and is a simple wrapper
        around `KeyAuthorizationChallengeResponse.verify`.

        :param challenges.DNS01 chall: Corresponding challenge.
        :param str domain: Domain name being verified.
        :param JWK account_public_key: Public key for the key pair
            being authorized.

        :return: ``True`` iff verification of the key authorization was
            successful.
        :rtype: bool

        """
        verified = self.verify(chall, account_public_key)
        if not verified:
            logger.debug("Verification of key authorization in response failed")
        return verified


@Challenge.register
class DNS01(KeyAuthorizationChallenge):
    """ACME dns-01 challenge."""
    response_cls = DNS01Response
    typ = response_cls.typ

    LABEL = "_acme-challenge"
    """Label clients prepend to the domain name being validated."""

    def validation(self, account_key: jose.JWK, **unused_kwargs: Any) -> str:
        """Generate validation.

        :param JWK account_key:
        :rtype: str

        """
        return jose.b64encode(hashlib.sha256(self.key_authorization(
            account_key).encode("utf-8")).digest()).decode()

    def validation_domain_name(self, name: str) -> str:
        """Domain name for TXT validation record.

        :param str name: Domain name being validated.
        :rtype: str

        """
        return f"{self.LABEL}.{name}"


@ChallengeResponse.register
class HTTP01Response(KeyAuthorizationChallengeResponse):
    """ACME http-01 challenge response."""
    typ = "http-01"

    PORT = 80
    """Verification port as defined by the protocol.

    You can override it (e.g. for testing) by passing ``port`` to
    `simple_verify`.

    """

    WHITESPACE_CUTSET = "\n\r\t "
    """Whitespace characters which should be ignored at the end of the body."""

    def simple_verify(self, chall: 'HTTP01', domain: str, account_public_key: jose.JWK,
                      port: Optional[int] = None, timeout: int = 30) -> bool:
        """Simple verify.

        :param challenges.SimpleHTTP chall: Corresponding challenge.
        :param str domain: Domain name being verified.
        :param JWK account_public_key: Public key for the key pair
            being authorized.
        :param int port: Port used in the validation.
        :param int timeout: Timeout in seconds.

        :returns: ``True`` iff validation with the files currently served by the
            HTTP server is successful.
        :rtype: bool

        """
        if not self.verify(chall, account_public_key):
            logger.debug("Verification of key authorization in response failed")
            return False

        # TODO: ACME specification defines URI template that doesn't
        # allow to use a custom port... Make sure port is not in the
        # request URI, if it's standard.
        if port is not None and port != self.PORT:
            logger.warning(
                "Using non-standard port for http-01 verification: %s", port)
            domain += ":{0}".format(port)

        uri = chall.uri(domain)
        logger.debug("Verifying %s at %s...", chall.typ, uri)
        try:
            http_response = requests.get(uri, verify=False, timeout=timeout)
        except requests.exceptions.RequestException as error:
            logger.error("Unable to reach %s: %s", uri, error)
            return False
        # By default, http_response.text will try to guess the encoding to use
        # when decoding the response to Python unicode strings. This guesswork
        # is error prone. RFC 8555 specifies that HTTP-01 responses should be
        # key authorizations with possible trailing whitespace. Since key
        # authorizations must be composed entirely of the base64url alphabet
        # plus ".", we tell requests that the response should be ASCII. See
        # https://datatracker.ietf.org/doc/html/rfc8555#section-8.3 for more
        # info.
        http_response.encoding = "ascii"
        logger.debug("Received %s: %s. Headers: %s", http_response,
                     http_response.text, http_response.headers)

        challenge_response = http_response.text.rstrip(self.WHITESPACE_CUTSET)
        if self.key_authorization != challenge_response:
            logger.debug("Key authorization from response (%r) doesn't match "
                         "HTTP response (%r)", self.key_authorization,
                         challenge_response)
            return False

        return True


@Challenge.register
class HTTP01(KeyAuthorizationChallenge):
    """ACME http-01 challenge."""
    response_cls = HTTP01Response
    typ = response_cls.typ

    URI_ROOT_PATH = ".well-known/acme-challenge"
    """URI root path for the server provisioned resource."""

    @property
    def path(self) -> str:
        """Path (starting with '/') for provisioned resource.

        :rtype: str

        """
        return '/' + self.URI_ROOT_PATH + '/' + self.encode('token')

    def uri(self, domain: str) -> str:
        """Create an URI to the provisioned resource.

        Forms an URI to the HTTPS server provisioned resource
        (containing :attr:`~SimpleHTTP.token`).

        :param str domain: Domain name being verified.
        :rtype: str

        """
        return "http://" + domain + self.path

    def validation(self, account_key: jose.JWK, **unused_kwargs: Any) -> str:
        """Generate validation.

        :param JWK account_key:
        :rtype: str

        """
        return self.key_authorization(account_key)


@ChallengeResponse.register
class TLSALPN01Response(KeyAuthorizationChallengeResponse):
    """ACME tls-alpn-01 challenge response."""
    typ = "tls-alpn-01"

    PORT = 443
    """Verification port as defined by the protocol.

    You can override it (e.g. for testing) by passing ``port`` to
    `simple_verify`.

    """

    ID_PE_ACME_IDENTIFIER_V1 = b"1.3.6.1.5.5.7.1.30.1"
    ACME_TLS_1_PROTOCOL = b"acme-tls/1"

    @property
    def h(self) -> bytes:
        """Hash value stored in challenge certificate"""
        return hashlib.sha256(self.key_authorization.encode('utf-8')).digest()

    def gen_cert(self, domain: str, key: Optional[crypto.PKey] = None, bits: int = 2048
                 ) -> Tuple[x509.Certificate, crypto.PKey]:
        """Generate tls-alpn-01 certificate.

        :param str domain: Domain verified by the challenge.
        :param OpenSSL.crypto.PKey key: Optional private key used in
            certificate generation. If not provided (``None``), then
            fresh key will be generated.
        :param int bits: Number of bits for newly generated key.

        :rtype: `tuple` of `x509.Certificate` and `OpenSSL.crypto.PKey`

        """
        if key is None:
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, bits)

        oid = x509.ObjectIdentifier(self.ID_PE_ACME_IDENTIFIER_V1.decode())
        acme_extension = x509.Extension(
            oid,
            critical=True,
            value=x509.UnrecognizedExtension(oid, self.h)
        )

        cryptography_key = key.to_cryptography_key()
        assert isinstance(cryptography_key, crypto_util.CertificateIssuerPrivateKeyTypesTpl)
        cert = crypto_util.make_self_signed_cert(
            cryptography_key,
            [domain],
            force_san=True,
            extensions=[acme_extension]
        )
        return cert, key

    def probe_cert(self, domain: str, host: Optional[str] = None,
                   port: Optional[int] = None) -> x509.Certificate:
        """Probe tls-alpn-01 challenge certificate.

        :param str domain: domain being validated, required.
        :param str host: IP address used to probe the certificate.
        :param int port: Port used to probe the certificate.

        """
        if host is None:
            host = socket.gethostbyname(domain)
            logger.debug('%s resolved to %s', domain, host)
        if port is None:
            port = self.PORT

        return crypto_util.probe_sni(host=host.encode(), port=port, name=domain.encode(),
                                     alpn_protocols=[self.ACME_TLS_1_PROTOCOL])

    def verify_cert(self, domain: str, cert: x509.Certificate, ) -> bool:
        """Verify tls-alpn-01 challenge certificate.

        :param str domain: Domain name being validated.
        :param cert: Challenge certificate.
        :type cert: `cryptography.x509.Certificate`

        :returns: Whether the certificate was successfully verified.
        :rtype: bool

        """
        names = crypto_util.get_names_from_subject_and_extensions(
            cert.subject, cert.extensions
        )
        logger.debug(
            "Certificate %s. SANs: %s", cert.fingerprint(hashes.SHA256()), names
        )
        if len(names) != 1 or names[0].lower() != domain.lower():
            return False

        try:
            ext = cert.extensions.get_extension_for_oid(
                x509.ObjectIdentifier(self.ID_PE_ACME_IDENTIFIER_V1.decode())
            )
        except x509.ExtensionNotFound:
            return False

        # This is for the type checker.
        assert isinstance(ext.value, x509.UnrecognizedExtension)
        return ext.value.value == self.h

    # pylint: disable=too-many-arguments
    def simple_verify(self, chall: 'TLSALPN01', domain: str, account_public_key: jose.JWK,
                      cert: Optional[x509.Certificate] = None, host: Optional[str] = None,
                      port: Optional[int] = None) -> bool:
        """Simple verify.

        Verify ``validation`` using ``account_public_key``, optionally
        probe tls-alpn-01 certificate and check using `verify_cert`.

        :param .challenges.TLSALPN01 chall: Corresponding challenge.
        :param str domain: Domain name being validated.
        :param JWK account_public_key:
        :param x509.Certificate cert: Optional certificate. If not
            provided (``None``) certificate will be retrieved using
            `probe_cert`.
        :param string host: IP address used to probe the certificate.
        :param int port: Port used to probe the certificate.


        :returns: ``True`` if and only if client's control of the domain has been verified.
        :rtype: bool

        """
        if not self.verify(chall, account_public_key):
            logger.debug("Verification of key authorization in response failed")
            return False

        if cert is None:
            try:
                cert = self.probe_cert(domain=domain, host=host, port=port)
            except errors.Error as error:
                logger.debug(str(error), exc_info=True)
                return False

        return self.verify_cert(domain, cert)


@Challenge.register  # pylint: disable=too-many-ancestors
class TLSALPN01(KeyAuthorizationChallenge):
    """ACME tls-alpn-01 challenge."""
    response_cls = TLSALPN01Response
    typ = response_cls.typ

    def validation(self, account_key: jose.JWK, **kwargs: Any) -> Tuple[x509.Certificate, crypto.PKey]:
        """Generate validation.

        :param JWK account_key:
        :param str domain: Domain verified by the challenge.
        :param OpenSSL.crypto.PKey cert_key: Optional private key used
            in certificate generation. If not provided (``None``), then
            fresh key will be generated.

        :rtype: `tuple` of `x509.Certificate` and `OpenSSL.crypto.PKey`

        """
        # TODO: Remove cast when response() is generic.
        return cast(TLSALPN01Response, self.response(account_key)).gen_cert(
            key=kwargs.get('cert_key'),
            domain=cast(str, kwargs.get('domain')))

    @staticmethod
    def is_supported() -> bool:
        """
        Check if TLS-ALPN-01 challenge is supported on this machine.
        This implies that a recent version of OpenSSL is installed (>= 1.0.2),
        or a recent cryptography version shipped with the OpenSSL library is installed.

        :returns: ``True`` if TLS-ALPN-01 is supported on this machine, ``False`` otherwise.
        :rtype: bool

        """
        return (hasattr(SSL.Connection, "set_alpn_protos")
                and hasattr(SSL.Context, "set_alpn_select_callback"))


@Challenge.register
class DNS(_TokenChallenge):
    """ACME "dns" challenge."""
    typ = "dns"

    LABEL = "_acme-challenge"
    """Label clients prepend to the domain name being validated."""

    def gen_validation(self, account_key: jose.JWK, alg: jose.JWASignature = jose.RS256,
                       **kwargs: Any) -> jose.JWS:
        """Generate validation.

        :param .JWK account_key: Private account key.
        :param .JWA alg:

        :returns: This challenge wrapped in `.JWS`
        :rtype: .JWS

        """
        return jose.JWS.sign(
            payload=self.json_dumps(sort_keys=True).encode('utf-8'),
            key=account_key, alg=alg, **kwargs)

    def check_validation(self, validation: jose.JWS, account_public_key: jose.JWK) -> bool:
        """Check validation.

        :param JWS validation:
        :param JWK account_public_key:
        :rtype: bool

        """
        if not validation.verify(key=account_public_key):
            return False
        try:
            return self == self.json_loads(
                validation.payload.decode('utf-8'))
        except jose.DeserializationError as error:
            logger.debug("Checking validation for DNS failed: %s", error)
            return False

    def gen_response(self, account_key: jose.JWK, **kwargs: Any) -> 'DNSResponse':
        """Generate response.

        :param .JWK account_key: Private account key.
        :param .JWA alg:

        :rtype: DNSResponse

        """
        return DNSResponse(validation=self.gen_validation(account_key, **kwargs))

    def validation_domain_name(self, name: str) -> str:
        """Domain name for TXT validation record.

        :param str name: Domain name being validated.

        """
        return "{0}.{1}".format(self.LABEL, name)


@ChallengeResponse.register
class DNSResponse(ChallengeResponse):
    """ACME "dns" challenge response.

    :param JWS validation:

    """
    typ = "dns"

    validation: jose.JWS = jose.field("validation", decoder=jose.JWS.from_json)

    def check_validation(self, chall: 'DNS', account_public_key: jose.JWK) -> bool:
        """Check validation.

        :param challenges.DNS chall:
        :param JWK account_public_key:

        :rtype: bool

        """
        return chall.check_validation(self.validation, account_public_key)
