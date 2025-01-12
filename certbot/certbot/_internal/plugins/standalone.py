"""Standalone Authenticator."""
import collections
import errno
import logging
from typing import Any
from typing import Callable
from typing import DefaultDict
from typing import Dict
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Set
from typing import Tuple
from typing import Type
from typing import TYPE_CHECKING

from acme import challenges
from acme import crypto_util
from acme import standalone as acme_standalone
from certbot import achallenges
from certbot import errors
from certbot import interfaces
from certbot.display import util as display_util
from certbot.plugins import common

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    ServedType = DefaultDict[
        acme_standalone.BaseDualNetworkedServers,
        Set[achallenges.AnnotatedChallenge]
    ]


class ServerManager:
    """Standalone servers manager.

    Manager for `ACMEServer` and `ACMETLSServer` instances.

    `certs` and `http_01_resources` correspond to
    `acme.crypto_util.SSLSocket.certs` and
    `acme.crypto_util.SSLSocket.http_01_resources` respectively. All
    created servers share the same certificates and resources, so if
    you're running both TLS and non-TLS instances, HTTP01 handlers
    will serve the same URLs!

    """
    def __init__(self, certs: Mapping[bytes, crypto_util._KeyAndCert],
                 http_01_resources: Set[acme_standalone.HTTP01RequestHandler.HTTP01Resource]
                 ) -> None:
        self._instances: Dict[int, acme_standalone.HTTP01DualNetworkedServers] = {}
        self.certs = certs
        self.http_01_resources = http_01_resources

    def run(self, port: int, challenge_type: Type[challenges.Challenge],
            listenaddr: str = "") -> acme_standalone.HTTP01DualNetworkedServers:
        """Run ACME server on specified ``port``.

        This method is idempotent, i.e. all calls with the same pair of
        ``(port, challenge_type)`` will reuse the same server.

        :param int port: Port to run the server on.
        :param challenge_type: Subclass of `acme.challenges.Challenge`,
            currently only `acme.challenge.HTTP01`.
        :param str listenaddr: (optional) The address to listen on. Defaults to all addrs.

        :returns: DualNetworkedServers instance.
        :rtype: ACMEServerMixin

        """
        assert challenge_type == challenges.HTTP01
        if port in self._instances:
            return self._instances[port]

        address = (listenaddr, port)
        try:
            servers = acme_standalone.HTTP01DualNetworkedServers(
                address, self.http_01_resources)
        except OSError as error:
            raise errors.StandaloneBindError(error, port)

        servers.serve_forever()

        # if port == 0, then random free port on OS is taken
        # both servers, if they exist, have the same port
        real_port = servers.getsocknames()[0][1]
        self._instances[real_port] = servers
        return servers

    def stop(self, port: int) -> None:
        """Stop ACME server running on the specified ``port``.

        :param int port:

        """
        instance = self._instances[port]
        for sockname in instance.getsocknames():
            logger.debug("Stopping server at %s:%d...",
                         *sockname[:2])
        instance.shutdown_and_server_close()
        del self._instances[port]

    def running(self) -> Dict[int, acme_standalone.HTTP01DualNetworkedServers]:
        """Return all running instances.

        Once the server is stopped using `stop`, it will not be
        returned.

        :returns: Mapping from ``port`` to ``servers``.
        :rtype: tuple

        """
        return self._instances.copy()


class Authenticator(common.Plugin, interfaces.Authenticator):
    """Standalone Authenticator.

    This authenticator creates its own ephemeral TCP listener on the
    necessary port in order to respond to incoming http-01
    challenges from the certificate authority. Therefore, it does not
    rely on any existing server program.
    """

    description = """Runs an HTTP server locally which serves the necessary validation files \
under the /.well-known/acme-challenge/ request path. Suitable if there is no HTTP server already \
running. HTTP challenge only (wildcards not supported)."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        self.served: ServedType = collections.defaultdict(set)

        # Stuff below is shared across threads (i.e. servers read
        # values, main thread writes). Due to the nature of CPython's
        # GIL, the operations are safe, c.f.
        # https://docs.python.org/2/faq/library.html#what-kinds-of-global-value-mutation-are-thread-safe
        self.certs: Mapping[bytes, crypto_util._KeyAndCert] = {}
        self.http_01_resources: Set[acme_standalone.HTTP01RequestHandler.HTTP01Resource] = set()

        self.servers = ServerManager(self.certs, self.http_01_resources)

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None]) -> None:
        pass  # No additional argument for the standalone plugin parser

    def more_info(self) -> str:  # pylint: disable=missing-function-docstring
        return("This authenticator creates its own ephemeral TCP listener "
               "on the necessary port in order to respond to incoming "
               "http-01 challenges from the certificate authority. Therefore, "
               "it does not rely on any existing server program.")

    def prepare(self) -> None:  # pylint: disable=missing-function-docstring
        pass

    def get_chall_pref(self, domain: str) -> Iterable[Type[challenges.Challenge]]:
        # pylint: disable=unused-argument,missing-function-docstring
        return [challenges.HTTP01]

    def perform(self, achalls: Iterable[achallenges.AnnotatedChallenge]
                ) -> List[challenges.ChallengeResponse]:  # pylint: disable=missing-function-docstring
        return [self._try_perform_single(achall) for achall in achalls]

    def _try_perform_single(self,
                            achall: achallenges.AnnotatedChallenge) -> challenges.ChallengeResponse:
        while True:
            try:
                return self._perform_single(achall)
            except errors.StandaloneBindError as error:
                _handle_perform_error(error)

    def _perform_single(self,
                        achall: achallenges.AnnotatedChallenge) -> challenges.ChallengeResponse:
        servers, response = self._perform_http_01(achall)
        self.served[servers].add(achall)
        return response

    def _perform_http_01(self, achall: achallenges.AnnotatedChallenge
                         ) -> Tuple[acme_standalone.HTTP01DualNetworkedServers,
                                    challenges.ChallengeResponse]:
        port = self.config.http01_port
        addr = self.config.http01_address
        servers = self.servers.run(port, challenges.HTTP01, listenaddr=addr)
        response, validation = achall.response_and_validation()
        resource = acme_standalone.HTTP01RequestHandler.HTTP01Resource(
            chall=achall.chall, response=response, validation=validation)
        self.http_01_resources.add(resource)
        return servers, response

    def cleanup(self, achalls: Iterable[achallenges.AnnotatedChallenge]) -> None:  # pylint: disable=missing-function-docstring
        # reduce self.served and close servers if no challenges are served
        for unused_servers, server_achalls in self.served.items():
            for achall in achalls:
                if achall in server_achalls:
                    server_achalls.remove(achall)
        for port, servers in self.servers.running().items():
            if not self.served[servers]:
                self.servers.stop(port)

    def auth_hint(self, failed_achalls: List[achallenges.AnnotatedChallenge]) -> str:
        port, addr = self.config.http01_port, self.config.http01_address
        neat_addr = f"{addr}:{port}" if addr else f"port {port}"
        return ("The Certificate Authority failed to download the challenge files from "
                f"the temporary standalone webserver started by Certbot on {neat_addr}. "
                "Ensure that the listed domains point to this machine and that it can "
                "accept inbound connections from the internet.")


def _handle_perform_error(error: errors.StandaloneBindError) -> None:
    if error.socket_error.errno == errno.EACCES:
        raise errors.PluginError(
            "Could not bind TCP port {0} because you don't have "
            "the appropriate permissions (for example, you "
            "aren't running this program as "
            "root).".format(error.port))
    if error.socket_error.errno == errno.EADDRINUSE:
        msg = (
            "Could not bind TCP port {0} because it is already in "
            "use by another process on this system (such as a web "
            "server). Please stop the program in question and "
            "then try again.".format(error.port))
        should_retry = display_util.yesno(msg, "Retry", "Cancel", default=False)
        if not should_retry:
            raise errors.PluginError(msg)
    else:
        raise error
