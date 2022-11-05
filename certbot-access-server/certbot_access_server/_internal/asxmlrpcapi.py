"""Transport for communicating with xmlrpc through unix socket"""
from typing import Any

import socket
import xmlrpc.client
from http.client import HTTPConnection


class UnixStreamHTTPConnection(HTTPConnection):
    """A class to make http connection through unix socket"""
    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.host)


class UnixStreamTransport(xmlrpc.client.Transport):
    """A wrapper for xmlrpc transport to use unix socket"""
    def __init__(self, socket_path: str) -> None:
        self.socket_path = socket_path
        super().__init__()

    def make_connection(self, _: Any) -> HTTPConnection:
        return UnixStreamHTTPConnection(self.socket_path)
