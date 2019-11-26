"""ACME errors."""
from josepy import errors as jose_errors


class Error(Exception):
    """Generic ACME error."""


class DependencyError(Error):
    """Dependency error"""


class SchemaValidationError(jose_errors.DeserializationError):
    """JSON schema ACME object validation error."""


class ClientError(Error):
    """Network error."""


class UnexpectedUpdate(ClientError):
    """Unexpected update error."""


class NonceError(ClientError):
    """Server response nonce error."""


class BadNonce(NonceError):
    """Bad nonce error."""
    def __init__(self, nonce, error, *args, **kwargs):
        super(BadNonce, self).__init__(*args, **kwargs)
        self.nonce = nonce
        self.error = error

    def __str__(self):
        return 'Invalid nonce ({0!r}): {1}'.format(self.nonce, self.error)


class MissingNonce(NonceError):
    """Missing nonce error.

    According to the specification an "ACME server MUST include an
    Replay-Nonce header field in each successful response to a POST it
    provides to a client (...)".

    :ivar requests.Response response: HTTP Response

    """
    def __init__(self, response, *args, **kwargs):
        super(MissingNonce, self).__init__(*args, **kwargs)
        self.response = response

    def __str__(self):
        return ('Server {0} response did not include a replay '
                'nonce, headers: {1} (This may be a service outage)'.format(
                    self.response.request.method, self.response.headers))


class PollError(ClientError):
    """Generic error when polling for authorization fails.

    This might be caused by either timeout (`exhausted` will be non-empty)
    or by some authorization being invalid.

    :ivar exhausted: Set of `.AuthorizationResource` that didn't finish
        within max allowed attempts.
    :ivar updated: Mapping from original `.AuthorizationResource`
        to the most recently updated one

    """
    def __init__(self, exhausted, updated):
        self.exhausted = exhausted
        self.updated = updated
        super(PollError, self).__init__()

    @property
    def timeout(self):
        """Was the error caused by timeout?"""
        return bool(self.exhausted)

    def __repr__(self):
        return '{0}(exhausted={1!r}, updated={2!r})'.format(
            self.__class__.__name__, self.exhausted, self.updated)

class ValidationError(Error):
    """Error for authorization failures. Contains a list of authorization
    resources, each of which is invalid and should have an error field.
    """
    def __init__(self, failed_authzrs):
        self.failed_authzrs = failed_authzrs
        super(ValidationError, self).__init__()

    def __str__(self):
        msg = ''
        for authzr in self.failed_authzrs:
            msg += '\n Authorization for identifier %s failed.' % (
                authzr.body.identifier)
            msg += '\n Here are the challenges that were not fulfilled:'
            for challenge in authzr.body.challenges:
                msg += \
                    '\n Challenge Type: %s' \
                    '\n Error information: ' \
                    '\n Type: %s' \
                    '\n Details: %s \n\n' % (
                        challenge.chall.typ,
                        challenge.error.typ if challenge.error else '',
                        challenge.error.detail if challenge.error else '',
                    )
        return msg


class TimeoutError(Error):
    """Error for when polling an authorization or an order times out."""

class IssuanceError(Error):
    """Error sent by the server after requesting issuance of a certificate."""

    def __init__(self, error):
        """Initialize.

        :param messages.Error error: The error provided by the server.
        """
        self.error = error
        super(IssuanceError, self).__init__()

class ConflictError(ClientError):
    """Error for when the server returns a 409 (Conflict) HTTP status.

    In the version of ACME implemented by Boulder, this is used to find an
    account if you only have the private key, but don't know the account URL.

    Also used in V2 of the ACME client for the same purpose.
    """
    def __init__(self, location):
        self.location = location
        super(ConflictError, self).__init__()


class WildcardUnsupportedError(Error):
    """Error for when a wildcard is requested but is unsupported by ACME CA."""
