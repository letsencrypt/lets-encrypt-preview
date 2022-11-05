"""Installer plugin for OpenVPN Access Server"""
from typing import Callable, Iterable, Optional, Union, List, Any
import xmlrpc.client

from certbot import errors
from certbot.plugins import common
from certbot.compat import os

from certbot_access_server._internal.asxmlrpcapi import UnixStreamTransport

DEFAULT_SOCKET = "/usr/local/openvpn_as/etc/sock/sagent.localroot"


class Installer(common.Installer):
    """Installer plugin for OpenVPN Access Server.

    This plugin installs certificates into Access Server through
    XML-RPC protocol.
    """
    description = "OpenVPN Access Server Installer plugin"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.rpc_proxy: Any = None
        super().__init__(*args, **kwargs)

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None]) -> None:
        add(
            'socket',
            default=DEFAULT_SOCKET,
            type=str,
            help="Socket for connection to OpenVPN Access Server XML-RPC call."
        )
        add(
            'path-only',
            default=False,
            action='store_true',
            help="Set only cert paths instead of cert contents."
        )

    def deploy_cert(self, domain: str, cert_path: str, key_path: str,
                    chain_path: str, fullchain_path: str) -> None:
        if self.conf('path_only'):
            cert_data = {
                'cs.priv_key': key_path,
                'cs.cert': cert_path,
                'cs.ca_bundle': chain_path,
            }
        else:
            with open(key_path) as priv_key_f, open(cert_path) as cert_f, open(
                    chain_path) as chain_f:
                priv_key = priv_key_f.read()
                cert = cert_f.read()
                ca_bundle = chain_f.read()
            cert_data = {
                'cs.priv_key': priv_key,
                'cs.cert': cert,
                'cs.ca_bundle': ca_bundle,
            }
        self.rpc_proxy.ConfigPut(cert_data)

    def config_test(self) -> None:
        pass

    def enhance(self, domain: str, enhancement: str,
                options: Optional[Union[List[str], str]] = None) -> None:
        pass

    def get_all_names(self) -> Iterable[str]:
        profile_name = None  # use default profile
        # certbot ignores an empty string; the default value is more for
        # consistency
        hostname = self.rpc_proxy.ConfigQuery(
            profile_name, ['host.name']).get('host.name', '')

        return [hostname]

    def more_info(self) -> str:
        return 'This plugin installs LetsEncrypt certificate for HTTPS into ' \
               'an OpenVPN Access Server instance'

    def prepare(self) -> None:
        sock_name = self.conf('socket')
        if not os.path.exists(sock_name):
            raise errors.MisconfigurationError(
                f"OpenVPN Access Server socket {sock_name} does not exist. "
                f"OpenVPN Access server not running?”")
        # This is stub address actually because we override make_connection
        # but ServerProxy will raise an exception at init against just empty
        # string
        self.rpc_proxy = xmlrpc.client.ServerProxy(
            'http://localhost',
            transport=UnixStreamTransport(self.conf('socket')),
            allow_none=True,
        )
        try:
            self.rpc_proxy.GetASVersion()
        except ConnectionRefusedError:
            raise errors.MisconfigurationError(
                f"OpenVPN Access Server doesn't appear to be listening on"
                f"socket {sock_name}"
            )

    def restart(self) -> None:
        self.rpc_proxy.RunStart('warm')

    def save(self, title: Optional[str] = None,
             temporary: bool = False) -> None:
        pass

    def supported_enhancements(self) -> List[str]:
        return []
