"""ACME protocol messages."""
from collections.abc import Hashable
import datetime
import json
from typing import Any
from typing import Dict
from typing import Iterator
from typing import List
from typing import Mapping
from typing import MutableMapping
from typing import Optional
from typing import Tuple
from typing import Type
from typing import TypeVar

import josepy as jose

from acme import challenges
from acme import errors
from acme import fields
from acme import jws
from acme import util

ERROR_PREFIX = "urn:ietf:params:acme:error:"

ERROR_CODES = {
    'accountDoesNotExist': 'The request specified an account that does not exist',
    'alreadyRevoked': 'The request specified a certificate to be revoked that has' \
    ' already been revoked',
    'alreadyReplaced': 'The request specified a predecessor certificate which has' \
    ' already been marked as replaced',
    'badCSR': 'The CSR is unacceptable (e.g., due to a short key)',
    'badNonce': 'The client sent an unacceptable anti-replay nonce',
    'badPublicKey': 'The JWS was signed by a public key the server does not support',
    'badRevocationReason': 'The revocation reason provided is not allowed by the server',
    'badSignatureAlgorithm': 'The JWS was signed with an algorithm the server does not support',
    'caa': 'Certification Authority Authorization (CAA) records forbid the CA from issuing' \
    ' a certificate',
    'compound': 'Specific error conditions are indicated in the "subproblems" array',
    'connection': ('The server could not connect to the client to verify the'
                   ' domain'),
    'dns': 'There was a problem with a DNS query during identifier validation',
    'dnssec': 'The server could not validate a DNSSEC signed domain',
    'incorrectResponse': 'Response received didn\'t match the challenge\'s requirements',
    # deprecate invalidEmail
    'invalidEmail': 'The provided email for a registration was invalid',
    'invalidContact': 'The provided contact URI was invalid',
    'malformed': 'The request message was malformed',
    'rejectedIdentifier': 'The server will not issue certificates for the identifier',
    'orderNotReady': 'The request attempted to finalize an order that is not ready to be finalized',
    'rateLimited': 'There were too many requests of a given type',
    'serverInternal': 'The server experienced an internal error',
    'tls': 'The server experienced a TLS error during domain verification',
    'unauthorized': 'The client lacks sufficient authorization',
    'unsupportedContact': 'A contact URL for an account used an unsupported protocol scheme',
    'unknownHost': 'The server could not resolve a domain name',
    'unsupportedIdentifier': 'An identifier is of an unsupported type',
    'externalAccountRequired': 'The server requires external account binding',
}

ERROR_TYPE_DESCRIPTIONS = {**{
    ERROR_PREFIX + name: desc for name, desc in ERROR_CODES.items()
}}


def is_acme_error(err: BaseException) -> bool:
    """Check if argument is an ACME error."""
    if isinstance(err, Error) and (err.typ is not None):
        return ERROR_PREFIX in err.typ
    return False


class _Constant(jose.JSONDeSerializable, Hashable):
    """ACME constant."""
    __slots__ = ('name',)
    POSSIBLE_NAMES: Dict[str, '_Constant'] = NotImplemented

    def __init__(self, name: str) -> None:
        super().__init__()
        self.POSSIBLE_NAMES[name] = self  # pylint: disable=unsupported-assignment-operation
        self.name = name

    def to_partial_json(self) -> str:
        return self.name

    @classmethod
    def from_json(cls, jobj: str) -> '_Constant':
        if jobj not in cls.POSSIBLE_NAMES:  # pylint: disable=unsupported-membership-test
            raise jose.DeserializationError(f'{cls.__name__} not recognized')
        return cls.POSSIBLE_NAMES[jobj]

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.name})'

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, type(self)) and other.name == self.name

    def __hash__(self) -> int:
        return hash((self.__class__, self.name))


class IdentifierType(_Constant):
    """ACME identifier type."""
    POSSIBLE_NAMES: Dict[str, _Constant] = {}


IDENTIFIER_FQDN = IdentifierType('dns')  # IdentifierDNS in Boulder
IDENTIFIER_IP = IdentifierType('ip') # IdentifierIP in pebble - not in Boulder yet


class Identifier(jose.JSONObjectWithFields):
    """ACME identifier.

    :ivar IdentifierType typ:
    :ivar str value:

    """
    typ: IdentifierType = jose.field('type', decoder=IdentifierType.from_json)
    value: str = jose.field('value')


class Error(jose.JSONObjectWithFields, errors.Error):
    """ACME error.

    https://datatracker.ietf.org/doc/html/rfc7807

    Note: Although Error inherits from JSONObjectWithFields, which is immutable,
    we add mutability for Error to comply with the Python exception API.

    :ivar str typ:
    :ivar str title:
    :ivar str detail:
    :ivar Identifier identifier:
    :ivar tuple subproblems: An array of ACME Errors which may be present when the CA
            returns multiple errors related to the same request, `tuple` of `Error`.

    """
    typ: str = jose.field('type', omitempty=True, default='about:blank')
    title: str = jose.field('title', omitempty=True)
    detail: str = jose.field('detail', omitempty=True)
    identifier: Optional['Identifier'] = jose.field(
        'identifier', decoder=Identifier.from_json, omitempty=True)
    subproblems: Optional[Tuple['Error', ...]] = jose.field('subproblems', omitempty=True)

    # Mypy does not understand the josepy magic happening here, and falsely claims
    # that subproblems is redefined. Let's ignore the type check here.
    @subproblems.decoder  # type: ignore
    def subproblems(value: List[Dict[str, Any]]) -> Tuple['Error', ...]:  # pylint: disable=no-self-argument,missing-function-docstring
        return tuple(Error.from_json(subproblem) for subproblem in value)

    @classmethod
    def with_code(cls, code: str, **kwargs: Any) -> 'Error':
        """Create an Error instance with an ACME Error code.

        :str code: An ACME error code, like 'dnssec'.
        :kwargs: kwargs to pass to Error.

        """
        if code not in ERROR_CODES:
            raise ValueError("The supplied code: %s is not a known ACME error"
                             " code" % code)
        typ = ERROR_PREFIX + code
        # Mypy will not understand that the Error constructor accepts a named argument
        # "typ" because of josepy magic. Let's ignore the type check here.
        return cls(typ=typ, **kwargs)

    @property
    def description(self) -> Optional[str]:
        """Hardcoded error description based on its type.

        :returns: Description if standard ACME error or ``None``.
        :rtype: str

        """
        return ERROR_TYPE_DESCRIPTIONS.get(self.typ)

    @property
    def code(self) -> Optional[str]:
        """ACME error code.

        Basically self.typ without the ERROR_PREFIX.

        :returns: error code if standard ACME code or ``None``.
        :rtype: str

        """
        code = str(self.typ).rsplit(':', maxsplit=1)[-1]
        if code in ERROR_CODES:
            return code
        return None

    # Hack to allow mutability on Errors (see GH #9539)
    def __setattr__(self, name: str, value: Any) -> None:
        return object.__setattr__(self, name, value)

    def __str__(self) -> str:
        result = b' :: '.join(
            part.encode('ascii', 'backslashreplace') for part in
            (self.typ, self.description, self.detail, self.title)
            if part is not None).decode()
        if self.identifier:
            result = f'Problem for {self.identifier.value}: ' + result # pylint: disable=no-member
        if self.subproblems and len(self.subproblems) > 0:
            for subproblem in self.subproblems:
                result += f'\n{subproblem}'
        return result


class Status(_Constant):
    """ACME "status" field."""
    POSSIBLE_NAMES: Dict[str, _Constant] = {}


STATUS_UNKNOWN = Status('unknown')
STATUS_PENDING = Status('pending')
STATUS_PROCESSING = Status('processing')
STATUS_VALID = Status('valid')
STATUS_INVALID = Status('invalid')
STATUS_REVOKED = Status('revoked')
STATUS_READY = Status('ready')
STATUS_DEACTIVATED = Status('deactivated')


class Directory(jose.JSONDeSerializable):
    """Directory.

    Directory resources must be accessed by the exact field name in RFC8555 (section 9.7.5).
    """

    class Meta(jose.JSONObjectWithFields):
        """Directory Meta."""
        _terms_of_service: str = jose.field('termsOfService', omitempty=True)
        website: str = jose.field('website', omitempty=True)
        caa_identities: List[str] = jose.field('caaIdentities', omitempty=True)
        external_account_required: bool = jose.field('externalAccountRequired', omitempty=True)

        def __init__(self, **kwargs: Any) -> None:
            kwargs = {self._internal_name(k): v for k, v in kwargs.items()}
            super().__init__(**kwargs)

        @property
        def terms_of_service(self) -> str:
            """URL for the CA TOS"""
            return self._terms_of_service

        def __iter__(self) -> Iterator[str]:
            # When iterating over fields, use the external name 'terms_of_service' instead of
            # the internal '_terms_of_service'.
            for name in super().__iter__():
                yield name[1:] if name == '_terms_of_service' else name

        def _internal_name(self, name: str) -> str:
            return '_' + name if name == 'terms_of_service' else name

    def __init__(self, jobj: Mapping[str, Any]) -> None:
        self._jobj = jobj

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as error:
            raise AttributeError(str(error))

    def __getitem__(self, name: str) -> Any:
        try:
            return self._jobj[name]
        except KeyError:
            raise KeyError(f'Directory field "{name}" not found')

    def to_partial_json(self) -> Dict[str, Any]:
        return util.map_keys(self._jobj, lambda k: k)

    @classmethod
    def from_json(cls, jobj: MutableMapping[str, Any]) -> 'Directory':
        jobj['meta'] = cls.Meta.from_json(jobj.pop('meta', {}))
        return cls(jobj)


class Resource(jose.JSONObjectWithFields):
    """ACME Resource.

    :ivar acme.messages.ResourceBody body: Resource body.

    """
    body: "ResourceBody" = jose.field('body')


class ResourceWithURI(Resource):
    """ACME Resource with URI.

    :ivar str uri: Location of the resource.

    """
    uri: str = jose.field('uri')  # no ChallengeResource.uri


class ResourceBody(jose.JSONObjectWithFields):
    """ACME Resource Body."""


class ExternalAccountBinding:
    """ACME External Account Binding"""

    @classmethod
    def from_data(cls, account_public_key: jose.JWK, kid: str, hmac_key: str,
                  directory: Directory) -> Dict[str, Any]:
        """Create External Account Binding Resource from contact details, kid and hmac."""

        key_json = json.dumps(account_public_key.to_partial_json()).encode()
        decoded_hmac_key = jose.b64.b64decode(hmac_key)
        url = directory["newAccount"]

        eab = jws.JWS.sign(key_json, jose.jwk.JWKOct(key=decoded_hmac_key),
                           jose.jwa.HS256, None,
                           url, kid)

        return eab.to_partial_json()


GenericRegistration = TypeVar('GenericRegistration', bound='Registration')


class Registration(ResourceBody):
    """Registration Resource Body.

    :ivar jose.JWK key: Public key.
    :ivar tuple contact: Contact information following ACME spec,
        `tuple` of `str`.
    :ivar str agreement:

    """
    # on new-reg key server ignores 'key' and populates it based on
    # JWS.signature.combined.jwk
    key: jose.JWK = jose.field('key', omitempty=True, decoder=jose.JWK.from_json)
    # Contact field implements special behavior to allow messages that clear existing
    # contacts while not expecting the `contact` field when loading from json.
    # This is implemented in the constructor and *_json methods.
    contact: Tuple[str, ...] = jose.field('contact', omitempty=True, default=())
    agreement: str = jose.field('agreement', omitempty=True)
    status: Status = jose.field('status', omitempty=True)
    terms_of_service_agreed: bool = jose.field('termsOfServiceAgreed', omitempty=True)
    only_return_existing: bool = jose.field('onlyReturnExisting', omitempty=True)
    external_account_binding: Dict[str, Any] = jose.field('externalAccountBinding',
                                                          omitempty=True)

    phone_prefix = 'tel:'
    email_prefix = 'mailto:'

    @classmethod
    def from_data(cls: Type[GenericRegistration], phone: Optional[str] = None,
                  email: Optional[str] = None,
                  external_account_binding: Optional[Dict[str, Any]] = None,
                  **kwargs: Any) -> GenericRegistration:
        """
        Create registration resource from contact details.

        The `contact` keyword being passed to a Registration object is meaningful, so
        this function represents empty iterables in its kwargs by passing on an empty
        `tuple`.
        """

        # Note if `contact` was in kwargs.
        contact_provided = 'contact' in kwargs

        # Pop `contact` from kwargs and add formatted email or phone numbers
        details = list(kwargs.pop('contact', ()))
        if phone is not None:
            details.append(cls.phone_prefix + phone)
        if email is not None:
            details.extend([cls.email_prefix + mail for mail in email.split(',')])

        # Insert formatted contact information back into kwargs
        # or insert an empty tuple if `contact` provided.
        if details or contact_provided:
            kwargs['contact'] = tuple(details)

        if external_account_binding:
            kwargs['external_account_binding'] = external_account_binding

        return cls(**kwargs)

    def __init__(self, **kwargs: Any) -> None:
        """Note if the user provides a value for the `contact` member."""
        if 'contact' in kwargs and kwargs['contact'] is not None:
            # Avoid the __setattr__ used by jose.TypedJSONObjectWithFields
            object.__setattr__(self, '_add_contact', True)
        super().__init__(**kwargs)

    def _filter_contact(self, prefix: str) -> Tuple[str, ...]:
        return tuple(
            detail[len(prefix):] for detail in self.contact  # pylint: disable=not-an-iterable
            if detail.startswith(prefix))

    def _add_contact_if_appropriate(self, jobj: Dict[str, Any]) -> Dict[str, Any]:
        """
        The `contact` member of Registration objects should not be required when
        de-serializing (as it would be if the Fields' `omitempty` flag were `False`), but
        it should be included in serializations if it was provided.

        :param jobj: Dictionary containing this Registrations' data
        :type jobj: dict

        :returns: Dictionary containing Registrations data to transmit to the server
        :rtype: dict
        """
        if getattr(self, '_add_contact', False):
            jobj['contact'] = self.encode('contact')

        return jobj

    def to_partial_json(self) -> Dict[str, Any]:
        """Modify josepy.JSONDeserializable.to_partial_json()"""
        jobj = super().to_partial_json()
        return self._add_contact_if_appropriate(jobj)

    def fields_to_partial_json(self) -> Dict[str, Any]:
        """Modify josepy.JSONObjectWithFields.fields_to_partial_json()"""
        jobj = super().fields_to_partial_json()
        return self._add_contact_if_appropriate(jobj)

    @property
    def phones(self) -> Tuple[str, ...]:
        """All phones found in the ``contact`` field."""
        return self._filter_contact(self.phone_prefix)

    @property
    def emails(self) -> Tuple[str, ...]:
        """All emails found in the ``contact`` field."""
        return self._filter_contact(self.email_prefix)


class NewRegistration(Registration):
    """New registration."""


class UpdateRegistration(Registration):
    """Update registration."""


class RegistrationResource(ResourceWithURI):
    """Registration Resource.

    :ivar acme.messages.Registration body:
    :ivar str new_authzr_uri: Deprecated. Do not use.
    :ivar str terms_of_service: URL for the CA TOS.

    """
    body: Registration = jose.field('body', decoder=Registration.from_json)
    new_authzr_uri: str = jose.field('new_authzr_uri', omitempty=True)
    terms_of_service: str = jose.field('terms_of_service', omitempty=True)


class ChallengeBody(ResourceBody):
    """Challenge Resource Body.

    .. todo::
       Confusingly, this has a similar name to `.challenges.Challenge`,
       as well as `.achallenges.AnnotatedChallenge`. Please use names
       such as ``challb`` to distinguish instances of this class from
       ``achall``.

    :ivar acme.challenges.Challenge: Wrapped challenge.
        Conveniently, all challenge fields are proxied, i.e. you can
        call ``challb.x`` to get ``challb.chall.x`` contents.
    :ivar acme.messages.Status status:
    :ivar datetime.datetime validated:
    :ivar messages.Error error:

    """
    __slots__ = ('chall',)
    # ACMEv1 has a "uri" field in challenges. ACMEv2 has a "url" field. This
    # challenge object supports either one, but should be accessed through the
    # name "uri". In Client.answer_challenge, whichever one is set will be
    # used.
    _url: str = jose.field('url', omitempty=True, default=None)
    status: Status = jose.field('status', decoder=Status.from_json,
                        omitempty=True, default=STATUS_PENDING)
    validated: datetime.datetime = fields.rfc3339('validated', omitempty=True)
    error: Error = jose.field('error', decoder=Error.from_json,
                       omitempty=True, default=None)

    def __init__(self, **kwargs: Any) -> None:
        kwargs = {self._internal_name(k): v for k, v in kwargs.items()}
        super().__init__(**kwargs)

    def encode(self, name: str) -> Any:
        return super().encode(self._internal_name(name))

    def to_partial_json(self) -> Dict[str, Any]:
        jobj = super().to_partial_json()
        jobj.update(self.chall.to_partial_json())
        return jobj

    @classmethod
    def fields_from_json(cls, jobj: Mapping[str, Any]) -> Dict[str, Any]:
        jobj_fields = super().fields_from_json(jobj)
        jobj_fields['chall'] = challenges.Challenge.from_json(jobj)
        return jobj_fields

    @property
    def uri(self) -> str:
        """The URL of this challenge."""
        return self._url

    def __getattr__(self, name: str) -> Any:
        return getattr(self.chall, name)

    def __iter__(self) -> Iterator[str]:
        # When iterating over fields, use the external name 'uri' instead of
        # the internal '_uri'.
        for name in super().__iter__():
            yield 'uri' if name == '_url' else name

    def _internal_name(self, name: str) -> str:
        return '_url' if name == 'uri' else name


class ChallengeResource(Resource):
    """Challenge Resource.

    :ivar acme.messages.ChallengeBody body:
    :ivar str authzr_uri: URI found in the 'up' ``Link`` header.

    """
    body: ChallengeBody = jose.field('body', decoder=ChallengeBody.from_json)
    authzr_uri: str = jose.field('authzr_uri')

    @property
    def uri(self) -> str:
        """The URL of the challenge body."""
        return self.body.uri  # pylint: disable=no-member


class Authorization(ResourceBody):
    """Authorization Resource Body.

    :ivar acme.messages.Identifier identifier:
    :ivar list challenges: `list` of `.ChallengeBody`
    :ivar acme.messages.Status status:
    :ivar datetime.datetime expires:

    """
    identifier: Identifier = jose.field('identifier', decoder=Identifier.from_json, omitempty=True)
    challenges: List[ChallengeBody] = jose.field('challenges', omitempty=True)

    status: Status = jose.field('status', omitempty=True, decoder=Status.from_json)
    # TODO: 'expires' is allowed for Authorization Resources in
    # general, but for Key Authorization '[t]he "expires" field MUST
    # be absent'... then acme-spec gives example with 'expires'
    # present... That's confusing!
    expires: datetime.datetime = fields.rfc3339('expires', omitempty=True)
    wildcard: bool = jose.field('wildcard', omitempty=True)

    # Mypy does not understand the josepy magic happening here, and falsely claims
    # that challenge is redefined. Let's ignore the type check here.
    @challenges.decoder  # type: ignore
    def challenges(value: List[Dict[str, Any]]) -> Tuple[ChallengeBody, ...]:  # pylint: disable=no-self-argument,missing-function-docstring
        return tuple(ChallengeBody.from_json(chall) for chall in value)


class NewAuthorization(Authorization):
    """New authorization."""


class UpdateAuthorization(Authorization):
    """Update authorization."""


class AuthorizationResource(ResourceWithURI):
    """Authorization Resource.

    :ivar acme.messages.Authorization body:
    :ivar str new_cert_uri: Deprecated. Do not use.

    """
    body: Authorization = jose.field('body', decoder=Authorization.from_json)
    new_cert_uri: str = jose.field('new_cert_uri', omitempty=True)


class CertificateRequest(jose.JSONObjectWithFields):
    """ACME newOrder request.

    :ivar jose.ComparableX509 csr:
        `OpenSSL.crypto.X509Req` wrapped in `.ComparableX509`

    """
    csr: jose.ComparableX509 = jose.field('csr', decoder=jose.decode_csr, encoder=jose.encode_csr)


class CertificateResource(ResourceWithURI):
    """Certificate Resource.

    :ivar josepy.util.ComparableX509 body:
        `OpenSSL.crypto.X509` wrapped in `.ComparableX509`
    :ivar str cert_chain_uri: URI found in the 'up' ``Link`` header
    :ivar tuple authzrs: `tuple` of `AuthorizationResource`.

    """
    cert_chain_uri: str = jose.field('cert_chain_uri')
    authzrs: Tuple[AuthorizationResource, ...] = jose.field('authzrs')


class Revocation(jose.JSONObjectWithFields):
    """Revocation message.

    :ivar jose.ComparableX509 certificate: `OpenSSL.crypto.X509` wrapped in
        `jose.ComparableX509`

    """
    certificate: jose.ComparableX509 = jose.field(
        'certificate', decoder=jose.decode_cert, encoder=jose.encode_cert)
    reason: int = jose.field('reason')


class Order(ResourceBody):
    """Order Resource Body.

    :ivar identifiers: List of identifiers for the certificate.
    :vartype identifiers: `list` of `.Identifier`
    :ivar acme.messages.Status status:
    :ivar authorizations: URLs of authorizations.
    :vartype authorizations: `list` of `str`
    :ivar str certificate: URL to download certificate as a fullchain PEM.
    :ivar str finalize: URL to POST to to request issuance once all
        authorizations have "valid" status.
    :ivar datetime.datetime expires: When the order expires.
    :ivar ~.Error error: Any error that occurred during finalization, if applicable.
    """
    identifiers: List[Identifier] = jose.field('identifiers', omitempty=True)
    status: Status = jose.field('status', decoder=Status.from_json, omitempty=True)
    authorizations: List[str] = jose.field('authorizations', omitempty=True)
    certificate: str = jose.field('certificate', omitempty=True)
    finalize: str = jose.field('finalize', omitempty=True)
    expires: datetime.datetime = fields.rfc3339('expires', omitempty=True)
    error: Error = jose.field('error', omitempty=True, decoder=Error.from_json)

    # Mypy does not understand the josepy magic happening here, and falsely claims
    # that identifiers is redefined. Let's ignore the type check here.
    @identifiers.decoder  # type: ignore
    def identifiers(value: List[Dict[str, Any]]) -> Tuple[Identifier, ...]:  # pylint: disable=no-self-argument,missing-function-docstring
        return tuple(Identifier.from_json(identifier) for identifier in value)


class OrderResource(ResourceWithURI):
    """Order Resource.

    :ivar acme.messages.Order body:
    :ivar bytes csr_pem: The CSR this Order will be finalized with.
    :ivar authorizations: Fully-fetched AuthorizationResource objects.
    :vartype authorizations: `list` of `acme.messages.AuthorizationResource`
    :ivar str fullchain_pem: The fetched contents of the certificate URL
        produced once the order was finalized, if it's present.
    :ivar alternative_fullchains_pem: The fetched contents of alternative certificate
        chain URLs produced once the order was finalized, if present and requested during
        finalization.
    :vartype alternative_fullchains_pem: `list` of `str`
    """
    body: Order = jose.field('body', decoder=Order.from_json)
    csr_pem: bytes = jose.field('csr_pem', omitempty=True,
                                # This looks backwards, but it's not -
                                # we want the deserialized value to be
                                # `bytes`, but anything we put into
                                # JSON needs to be `str`, so we encode
                                # to decode and decode to
                                # encode. Otherwise we end up with an
                                # array of ints on serialization
                                decoder=lambda s: s.encode("utf-8"),
                                encoder=lambda b: b.decode("utf-8"))

    authorizations: List[AuthorizationResource] = jose.field('authorizations')
    fullchain_pem: str = jose.field('fullchain_pem', omitempty=True)
    alternative_fullchains_pem: List[str] = jose.field('alternative_fullchains_pem',
                                                       omitempty=True)

    # Mypy does not understand the josepy magic happening here, and falsely claims
    # that authorizations is redefined. Let's ignore the type check here.
    @authorizations.decoder  # type: ignore
    def authorizations(value: List[Dict[str, Any]]) -> Tuple[AuthorizationResource, ...]: # pylint: disable=no-self-argument,missing-function-docstring
        return tuple(AuthorizationResource.from_json(authz) for authz in value)


class NewOrder(Order):
    """New order.
    :ivar: replaces: draft-ietf-acme-ari certificate identifier string
    :vartype: str
    """
    replaces: str = jose.field("replaces", omitempty= True)
