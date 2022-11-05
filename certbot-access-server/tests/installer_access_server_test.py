import tempfile
import sys
import socket
import xmlrpc.client


try:
    import mock
except ImportError:  # pragma: no cover
    from unittest import mock  # type: ignore

import pytest

from certbot import errors
from certbot.compat import os
from certbot_access_server._internal import installer_access_server
from certbot_access_server._internal.installer_access_server import Installer
from certbot_access_server._internal import asxmlrpcapi


# Backport of 3.8+ fspath support
class MagicMock(mock.MagicMock):
    def __fspath__(self):
        return f"{type(self).__name__}/{self._extract_mock_name()}/{id(self)}"


CERT_PATH = 'testdata/cert.txt'
CA_BUNDLE_PATH = 'testdata/ca_bundle.txt'
PRIV_KEY_PATH = 'testdata/priv_key.txt'


def _expand_path(path):
    return os.path.join(os.path.dirname(__file__), path)


RPC_HEAD = (
        b'POST /RPC2 HTTP/1.1\r\nHost: %%s\r\n'
        b'Accept-Encoding: gzip\r\nContent-Type: text/xml\r\nUser-Agent: Python-xmlrpc/%d.%d\r\n'
        b'Content-Length: %%d\r\n\r\n' % sys.version_info[:2]
)

RPC_GET_VERSION = (
    b"<?xml version='1.0'?>\n<methodCall>\n<methodName>GetASVersion</methodName>\n<params>\n"
    b"</params>\n</methodCall>\n"
)

RPC_CALL = (b"<?xml version='1.0'?>\n<methodCall>\n<methodName>MakeRpcCall</methodName>\n<params>\n"
            b"<param>\n<value><string>data_arg1</string></value>\n</param>\n<param>\n<value>"
            b"<string>data_arg2</string></value>\n</param>\n</params>\n</methodCall>\n")


def _get_content():
    yield (b"<?xml version='1.0'?>\n<methodResponse>\n<params>\n<param>\n"
           b"<value>TestResponse</value></param>\n</params>\n</methodResponse>\n")
    yield None


class MockResponse:
    def __init__(self):
        self.status = 200
        self.__content = _get_content()

    def getheader(self, *_):
        return ''

    def read(self, _):
        return next(self.__content)


def test_prepare(sock, monkeypatch):
    with monkeypatch.context() as m:
        test_mock = MagicMock()
        m.setattr(socket, 'socket', test_mock)
        m.setattr(asxmlrpcapi.HTTPConnection, 'getresponse', lambda _: MockResponse())
        config = MagicMock(access_server_socket=sock)
        installer = Installer(config, 'access-server')
        installer.prepare()
        test_mock.assert_has_calls([
            mock.call(socket.AF_UNIX, socket.SOCK_STREAM),
            mock.call().connect(sock),
            mock.call().sendall(RPC_HEAD % (sock.encode(), len(RPC_GET_VERSION))),
            mock.call().sendall(RPC_GET_VERSION),
        ])
        test_mock.reset_mock()

        result = installer.rpc_proxy.MakeRpcCall('data_arg1', 'data_arg2')
        assert result == 'TestResponse'
        test_mock.assert_has_calls([
            mock.call(socket.AF_UNIX, socket.SOCK_STREAM),
            mock.call().connect(sock),
            mock.call().sendall(RPC_HEAD % (sock.encode(), len(RPC_CALL))),
            mock.call().sendall(RPC_CALL),
        ])


@pytest.fixture(scope='session')
def sock():
    with tempfile.NamedTemporaryFile(delete=False) as sock_file:
        sock_file.close()
        yield sock_file.name
        if os.path.exists(sock_file.name):
            os.unlink(sock_file.name)


@pytest.fixture(params=[{}])
def make_installer(sock, request, monkeypatch):
    with monkeypatch.context() as m:
        rpc_mock = MagicMock()
        transport_mock = MagicMock()
        m.setattr(xmlrpc.client, 'ServerProxy', rpc_mock)
        m.setattr(installer_access_server, 'UnixStreamTransport', transport_mock)
        config_params = dict(access_server_socket=sock, **request.param)
        config = MagicMock(**config_params)
        installer = Installer(config, 'access-server')
        installer.prepare()
        rpc_mock.assert_has_calls([
            mock.call('http://localhost', transport=transport_mock(sock), allow_none=True),
            mock.call().GetASVersion(),
        ])
        rpc_mock.reset_mock()
        yield rpc_mock, installer


def test_deploy_cert(make_installer):
    rpc_mock, installer = make_installer
    installer.deploy_cert(
        'test',
        _expand_path(CERT_PATH),
        _expand_path(PRIV_KEY_PATH),
        _expand_path(CA_BUNDLE_PATH), ''
    )
    rpc_mock.assert_has_calls([
        mock.call().ConfigPut({
            'cs.priv_key': _expand_path(PRIV_KEY_PATH),
            'cs.cert': _expand_path(CERT_PATH),
            'cs.ca_bundle': _expand_path(CA_BUNDLE_PATH)
        })
    ])


@pytest.mark.parametrize('make_installer', [{'access_server_path_only': False}], indirect=True)
def test_deploy_cert_body(make_installer):
    rpc_mock, installer = make_installer
    installer.deploy_cert(
        'test',
        _expand_path(CERT_PATH),
        _expand_path(PRIV_KEY_PATH),
        _expand_path(CA_BUNDLE_PATH), ''
    )
    rpc_mock.assert_has_calls([
        mock.call().ConfigPut({
            'cs.priv_key': 'priv_key_content\n',
            'cs.cert': 'cert_content\n',
            'cs.ca_bundle': 'ca_bundle_content\n',
        })
    ])


def test_restart(make_installer):
    rpc_mock, installer = make_installer
    installer.restart()
    rpc_mock.assert_has_calls([
        mock.call().RunStart('warm')
    ])


def test_get_all_names(make_installer):
    rpc_mock, installer = make_installer
    rpc_mock().ConfigQuery = MagicMock(
        return_value={'host.name': 'test_host_name'})
    expected_calls = [
        mock.call().ConfigQuery(None, ['host.name']),
    ]
    result = installer.get_all_names()
    assert result == ['test_host_name']
    rpc_mock.assert_has_calls(expected_calls)
    rpc_mock.reset_mock()
    rpc_mock().ConfigQuery = MagicMock(return_value={})
    result = installer.get_all_names()
    assert result == ['']
    rpc_mock.assert_has_calls(expected_calls)


def test_incorrect_socket():
    with pytest.raises(errors.MisconfigurationError):
        config = MagicMock(access_server_socket='/incorrect/socket/path/')
        installer = Installer(config, 'access-server')
        installer.prepare()
