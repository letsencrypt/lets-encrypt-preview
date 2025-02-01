"""Tests for acme.standalone."""
import http.client as http_client
import socket
import socketserver
import sys
import threading
from typing import Set
import unittest
from unittest import mock

import josepy as jose
import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from acme import challenges
from acme import crypto_util
from acme import errors
from acme._internal.tests import test_util


class TLSServerTest(unittest.TestCase):
    """Tests for acme.standalone.TLSServer."""


    def test_bind(self):  # pylint: disable=no-self-use
        from acme.standalone import TLSServer
        server = TLSServer(
            ('', 0), socketserver.BaseRequestHandler, bind_and_activate=True)
        server.server_close()

    def test_ipv6(self):
        if socket.has_ipv6:
            from acme.standalone import TLSServer
            server = TLSServer(
                ('', 0), socketserver.BaseRequestHandler, bind_and_activate=True, ipv6=True)
            server.server_close()


class HTTP01ServerTest(unittest.TestCase):
    """Tests for acme.standalone.HTTP01Server."""


    def setUp(self):
        self.account_key = jose.JWK.load(
            test_util.load_vector('rsa1024_key.pem'))
        self.resources: Set = set()

        from acme.standalone import HTTP01Server
        self.server = HTTP01Server(('', 0), resources=self.resources)

        self.port = self.server.socket.getsockname()[1]
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def test_index(self):
        response = requests.get(
            'http://localhost:{0}'.format(self.port), verify=False)
        assert response.text == 'ACME client standalone challenge solver'
        assert response.ok

    def test_404(self):
        response = requests.get(
            'http://localhost:{0}/foo'.format(self.port), verify=False)
        assert response.status_code == http_client.NOT_FOUND

    def _test_http01(self, add):
        chall = challenges.HTTP01(token=(b'x' * 16))
        response, validation = chall.response_and_validation(self.account_key)

        from acme.standalone import HTTP01RequestHandler
        resource = HTTP01RequestHandler.HTTP01Resource(
            chall=chall, response=response, validation=validation)
        if add:
            self.resources.add(resource)
        return resource.response.simple_verify(
            resource.chall, 'localhost', self.account_key.public_key(),
            port=self.port)

    def test_http01_found(self):
        assert self._test_http01(add=True)

    def test_http01_not_found(self):
        assert not self._test_http01(add=False)

    def test_timely_shutdown(self):
        from acme.standalone import HTTP01Server
        with HTTP01Server(('', 0), resources=set(), timeout=0.05) as server:
            server_thread = threading.Thread(target=server.serve_forever)
            server_thread.start()

            with socket.socket() as client:
                client.connect(('localhost', server.socket.getsockname()[1]))

                stop_thread = threading.Thread(target=server.shutdown)
                stop_thread.start()
                server_thread.join(5.)

                is_hung = server_thread.is_alive()
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except: # pragma: no cover, pylint: disable=bare-except
                    # may raise error because socket could already be closed
                    pass

                assert not is_hung, 'Server shutdown should not be hung'


@unittest.skipIf(not challenges.TLSALPN01.is_supported(), "pyOpenSSL too old")
class TLSALPN01ServerTest(unittest.TestCase):
    """Test for acme.standalone.TLSALPN01Server."""

    def setUp(self):
        self.certs = {b'localhost': (
            serialization.load_pem_private_key(test_util.load_vector('rsa2048_key.pem'), password=None),
            x509.load_pem_x509_certificate(test_util.load_vector('rsa2048_cert.pem')),
        )}
        # Use different certificate for challenge.
        self.challenge_certs = {b'localhost': (
            serialization.load_pem_private_key(test_util.load_vector('rsa4096_key.pem'), password=None),
            x509.load_pem_x509_certificate(test_util.load_vector('rsa4096_cert.pem')),
        )}
        from acme.standalone import TLSALPN01Server
        self.server = TLSALPN01Server(("localhost", 0), certs=self.certs,
                challenge_certs=self.challenge_certs)
        # pylint: disable=no-member
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()  # pylint: disable=no-member
        self.thread.join()
        self.server.server_close()

    # TODO: This is not implemented yet, see comments in standalone.py
    # def test_certs(self):
    #    host, port = self.server.socket.getsockname()[:2]
    #    cert = crypto_util.probe_sni(
    #        b'localhost', host=host, port=port, timeout=1)
    #    # Expect normal cert when connecting without ALPN.
    #    self.assertEqual(jose.ComparableX509(cert),
    #                     jose.ComparableX509(self.certs[b'localhost'][1]))

    def test_challenge_certs(self):
        host, port = self.server.socket.getsockname()[:2]
        cert = crypto_util.probe_sni(
            b'localhost', host=host, port=port, timeout=1,
            alpn_protocols=[b"acme-tls/1"])
        #  Expect challenge cert when connecting with ALPN.
        assert cert == self.challenge_certs[b'localhost'][1]

    def test_bad_alpn(self):
        host, port = self.server.socket.getsockname()[:2]
        with pytest.raises(errors.Error):
            crypto_util.probe_sni(
                b'localhost', host=host, port=port, timeout=1,
                alpn_protocols=[b"bad-alpn"])


class BaseDualNetworkedServersTest(unittest.TestCase):
    """Test for acme.standalone.BaseDualNetworkedServers."""

    class SingleProtocolServer(socketserver.TCPServer):
        """Server that only serves on a single protocol. FreeBSD has this behavior for AF_INET6."""
        def __init__(self, *args, **kwargs):
            ipv6 = kwargs.pop("ipv6", False)
            if ipv6:
                self.address_family = socket.AF_INET6
                kwargs["bind_and_activate"] = False
            else:
                self.address_family = socket.AF_INET
            super().__init__(*args, **kwargs)
            if ipv6:
                # NB: On Windows, socket.IPPROTO_IPV6 constant may be missing.
                # We use the corresponding value (41) instead.
                level = getattr(socket, "IPPROTO_IPV6", 41)
                self.socket.setsockopt(level, socket.IPV6_V6ONLY, 1)
                try:
                    self.server_bind()
                    self.server_activate()
                except:
                    self.server_close()
                    raise

    @mock.patch("socket.socket.bind")
    def test_fail_to_bind(self, mock_bind):
        from errno import EADDRINUSE

        from acme.standalone import BaseDualNetworkedServers

        mock_bind.side_effect = OSError(EADDRINUSE, "Fake addr in use error")

        with pytest.raises(socket.error) as exc_info:
            BaseDualNetworkedServers(
                BaseDualNetworkedServersTest.SingleProtocolServer,
                ('', 0), socketserver.BaseRequestHandler)

        assert exc_info.value.errno == EADDRINUSE

    def test_ports_equal(self):
        from acme.standalone import BaseDualNetworkedServers
        servers = BaseDualNetworkedServers(
            BaseDualNetworkedServersTest.SingleProtocolServer,
            ('', 0),
            socketserver.BaseRequestHandler)
        socknames = servers.getsocknames()
        prev_port = None
        # assert ports are equal
        for sockname in socknames:
            port = sockname[1]
            if prev_port:
                assert prev_port == port
            prev_port = port
        for server in servers.servers:
            server.server_close()


class HTTP01DualNetworkedServersTest(unittest.TestCase):
    """Tests for acme.standalone.HTTP01DualNetworkedServers."""

    def setUp(self):
        self.account_key = jose.JWK.load(
            test_util.load_vector('rsa1024_key.pem'))
        self.resources: Set = set()

        from acme.standalone import HTTP01DualNetworkedServers
        self.servers = HTTP01DualNetworkedServers(('', 0), resources=self.resources)

        self.port = self.servers.getsocknames()[0][1]
        self.servers.serve_forever()

    def tearDown(self):
        self.servers.shutdown_and_server_close()

    def test_index(self):
        response = requests.get(
            'http://localhost:{0}'.format(self.port), verify=False)
        assert response.text == 'ACME client standalone challenge solver'
        assert response.ok

    def test_404(self):
        response = requests.get(
            'http://localhost:{0}/foo'.format(self.port), verify=False)
        assert response.status_code == http_client.NOT_FOUND

    def _test_http01(self, add):
        chall = challenges.HTTP01(token=(b'x' * 16))
        response, validation = chall.response_and_validation(self.account_key)

        from acme.standalone import HTTP01RequestHandler
        resource = HTTP01RequestHandler.HTTP01Resource(
            chall=chall, response=response, validation=validation)
        if add:
            self.resources.add(resource)
        return resource.response.simple_verify(
            resource.chall, 'localhost', self.account_key.public_key(),
            port=self.port)

    def test_http01_found(self):
        assert self._test_http01(add=True)

    def test_http01_not_found(self):
        assert not self._test_http01(add=False)


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
