"""Support for standalone client challenge solvers. """
import collections
import functools
import http.client as http_client
import http.server as BaseHTTPServer
import logging
import socket
import socketserver
import threading
from typing import Any
from typing import cast
from typing import List
from typing import Mapping
from typing import Optional
from typing import Set
from typing import Tuple
from typing import Type

from OpenSSL import SSL

from acme import challenges
from acme import crypto_util

logger = logging.getLogger(__name__)


class TLSServer(socketserver.TCPServer):
    """Generic TLS Server."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.ipv6 = kwargs.pop("ipv6", False)
        if self.ipv6:
            self.address_family = socket.AF_INET6
        else:
            self.address_family = socket.AF_INET
        self.certs = kwargs.pop("certs", {})
        self.method = kwargs.pop("method", crypto_util._DEFAULT_SSL_METHOD)
        self.allow_reuse_address = kwargs.pop("allow_reuse_address", True)
        super().__init__(*args, **kwargs)

    def _wrap_sock(self) -> None:
        self.socket = cast(socket.socket, crypto_util.SSLSocket(
            self.socket, cert_selection=self._cert_selection,
            alpn_selection=getattr(self, '_alpn_selection', None),
            method=self.method))

    def _cert_selection(self, connection: SSL.Connection
                        ) -> Optional[crypto_util._KeyAndCert]:  # pragma: no cover
        """Callback selecting certificate for connection."""
        server_name = connection.get_servername()
        if server_name:
            return self.certs.get(server_name, None)
        return None

    def server_bind(self) -> None:
        self._wrap_sock()
        return socketserver.TCPServer.server_bind(self)


class ACMEServerMixin:
    """ACME server common settings mixin."""
    # TODO: c.f. #858
    server_version = "ACME client standalone challenge solver"
    allow_reuse_address = True


class BaseDualNetworkedServers:
    """Base class for a pair of IPv6 and IPv4 servers that tries to do everything
       it's asked for both servers, but where failures in one server don't
       affect the other.

       If two servers are instantiated, they will serve on the same port.
       """

    def __init__(self, ServerClass: Type[socketserver.TCPServer], server_address: Tuple[str, int],
                 *remaining_args: Any, **kwargs: Any) -> None:
        port = server_address[1]
        self.threads: List[threading.Thread] = []
        self.servers: List[socketserver.BaseServer] = []

        # Preserve socket error for re-raising, if no servers can be started
        last_socket_err: Optional[socket.error] = None

        # Must try True first.
        # Ubuntu, for example, will fail to bind to IPv4 if we've already bound
        # to IPv6. But that's ok, since it will accept IPv4 connections on the IPv6
        # socket. On the other hand, FreeBSD will successfully bind to IPv4 on the
        # same port, which means that server will accept the IPv4 connections.
        # If Python is compiled without IPv6, we'll error out but (probably) successfully
        # create the IPv4 server.
        for ip_version in [True, False]:
            try:
                kwargs["ipv6"] = ip_version
                new_address = (server_address[0],) + (port,) + server_address[2:]
                new_args = (new_address,) + remaining_args
                server = ServerClass(*new_args, **kwargs)
                logger.debug(
                    "Successfully bound to %s:%s using %s", new_address[0],
                    new_address[1], "IPv6" if ip_version else "IPv4")
            except OSError as e:
                last_socket_err = e
                if self.servers:
                    # Already bound using IPv6.
                    logger.debug(
                        "Certbot wasn't able to bind to %s:%s using %s, this "
                        "is often expected due to the dual stack nature of "
                        "IPv6 socket implementations.",
                        new_address[0], new_address[1],
                        "IPv6" if ip_version else "IPv4")
                else:
                    logger.debug(
                        "Failed to bind to %s:%s using %s", new_address[0],
                        new_address[1], "IPv6" if ip_version else "IPv4")
            else:
                self.servers.append(server)
                # If two servers are set up and port 0 was passed in, ensure we always
                # bind to the same port for both servers.
                port = server.socket.getsockname()[1]
        if not self.servers:
            if last_socket_err:
                raise last_socket_err
            else: # pragma: no cover
                raise OSError("Could not bind to IPv4 or IPv6.")

    def serve_forever(self) -> None:
        """Wraps socketserver.TCPServer.serve_forever"""
        for server in self.servers:
            thread = threading.Thread(
                target=server.serve_forever)
            thread.start()
            self.threads.append(thread)

    def getsocknames(self) -> List[Tuple[str, int]]:
        """Wraps socketserver.TCPServer.socket.getsockname"""
        return [server.socket.getsockname() for server in self.servers]

    def shutdown_and_server_close(self) -> None:
        """Wraps socketserver.TCPServer.shutdown, socketserver.TCPServer.server_close, and
           threading.Thread.join"""
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join()
        self.threads = []


class TLSALPN01Server(TLSServer, ACMEServerMixin):
    """TLSALPN01 Server."""

    ACME_TLS_1_PROTOCOL = b"acme-tls/1"

    def __init__(self, server_address: Tuple[str, int],
                 certs: List[crypto_util._KeyAndCert],
                 challenge_certs: Mapping[bytes, crypto_util._KeyAndCert],
                 ipv6: bool = False) -> None:
        # We don't need to implement a request handler here because the work
        # (including logging) is being done by wrapped socket set up in the
        # parent TLSServer class.
        TLSServer.__init__(
            self, server_address, socketserver.BaseRequestHandler, certs=certs,
            ipv6=ipv6)
        self.challenge_certs = challenge_certs

    def _cert_selection(self, connection: SSL.Connection) -> Optional[crypto_util._KeyAndCert]:
        # TODO: We would like to serve challenge cert only if asked for it via
        # ALPN. To do this, we need to retrieve the list of protos from client
        # hello, but this is currently impossible with openssl [0], and ALPN
        # negotiation is done after cert selection.
        # Therefore, currently we always return challenge cert, and terminate
        # handshake in alpn_selection() if ALPN protos are not what we expect.
        # [0] https://github.com/openssl/openssl/issues/4952
        server_name = connection.get_servername()
        if server_name:
            logger.debug("Serving challenge cert for server name %s", server_name)
            return self.challenge_certs[server_name]
        return None # pragma: no cover

    def _alpn_selection(self, _connection: SSL.Connection, alpn_protos: List[bytes]) -> bytes:
        """Callback to select alpn protocol."""
        if len(alpn_protos) == 1 and alpn_protos[0] == self.ACME_TLS_1_PROTOCOL:
            logger.debug("Agreed on %s ALPN", self.ACME_TLS_1_PROTOCOL)
            return self.ACME_TLS_1_PROTOCOL
        logger.debug("Cannot agree on ALPN proto. Got: %s", str(alpn_protos))
        # Explicitly close the connection now, by returning an empty string.
        # See https://www.pyopenssl.org/en/stable/api/ssl.html#OpenSSL.SSL.Context.set_alpn_select_callback  # pylint: disable=line-too-long
        return b""


class HTTPServer(BaseHTTPServer.HTTPServer):
    """Generic HTTP Server."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.ipv6 = kwargs.pop("ipv6", False)
        if self.ipv6:
            self.address_family = socket.AF_INET6
        else:
            self.address_family = socket.AF_INET
        super().__init__(*args, **kwargs)


class HTTP01Server(HTTPServer, ACMEServerMixin):
    """HTTP01 Server."""

    def __init__(self, server_address: Tuple[str, int], resources: Set[challenges.HTTP01],
                 ipv6: bool = False, timeout: int = 30) -> None:
        super().__init__(
            server_address, HTTP01RequestHandler.partial_init(
                simple_http_resources=resources, timeout=timeout), ipv6=ipv6)


class HTTP01DualNetworkedServers(BaseDualNetworkedServers):
    """HTTP01Server Wrapper. Tries everything for both. Failures for one don't
       affect the other."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(HTTP01Server, *args, **kwargs)


class HTTP01RequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """HTTP01 challenge handler.

    Adheres to the stdlib's `socketserver.BaseRequestHandler` interface.

    :ivar set simple_http_resources: A set of `HTTP01Resource`
        objects. TODO: better name?

    """
    HTTP01Resource = collections.namedtuple(
        "HTTP01Resource", "chall response validation")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.simple_http_resources = kwargs.pop("simple_http_resources", set())
        self._timeout = kwargs.pop('timeout', 30)
        super().__init__(*args, **kwargs)
        self.server: HTTP01Server

    # In parent class BaseHTTPRequestHandler, 'timeout' is a class-level property but we
    # need to define its value during the initialization phase in HTTP01RequestHandler.
    # However MyPy does not appreciate that we dynamically shadow a class-level property
    # with an instance-level property (eg. self.timeout = ... in __init__()). So to make
    # everyone happy, we statically redefine 'timeout' as a method property, and set the
    # timeout value in a new internal instance-level property _timeout.
    @property
    def timeout(self) -> int:  # type: ignore[override]
        """
        The default timeout this server should apply to requests.
        :return: timeout to apply
        :rtype: int
        """
        return self._timeout

    def log_message(self, format: str, *args: Any) -> None:  # pylint: disable=redefined-builtin
        """Log arbitrary message."""
        logger.debug("%s - - %s", self.client_address[0], format % args)

    def handle(self) -> None:
        """Handle request."""
        self.log_message("Incoming request")
        BaseHTTPServer.BaseHTTPRequestHandler.handle(self)

    def do_GET(self) -> None:  # pylint: disable=invalid-name,missing-function-docstring
        if self.path == "/":
            self.handle_index()
        elif self.path.startswith("/" + challenges.HTTP01.URI_ROOT_PATH):
            self.handle_simple_http_resource()
        else:
            self.handle_404()

    def handle_index(self) -> None:
        """Handle index page."""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(self.server.server_version.encode())

    def handle_404(self) -> None:
        """Handler 404 Not Found errors."""
        self.send_response(http_client.NOT_FOUND, message="Not Found")
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"404")

    def handle_simple_http_resource(self) -> None:
        """Handle HTTP01 provisioned resources."""
        for resource in self.simple_http_resources:
            if resource.chall.path == self.path:
                self.log_message("Serving HTTP01 with token %r",
                                 resource.chall.encode("token"))
                self.send_response(http_client.OK)
                self.end_headers()
                self.wfile.write(resource.validation.encode())
                return
        else:  # pylint: disable=useless-else-on-loop
            self.log_message("No resources to serve")
        self.log_message("%s does not correspond to any resource. ignoring",
                         self.path)

    @classmethod
    def partial_init(cls, simple_http_resources: Set[challenges.HTTP01],
                     timeout: int) -> 'functools.partial[HTTP01RequestHandler]':
        """Partially initialize this handler.

        This is useful because `socketserver.BaseServer` takes
        uninitialized handler and initializes it with the current
        request.

        """
        return functools.partial(
            cls, simple_http_resources=simple_http_resources,
            timeout=timeout)
