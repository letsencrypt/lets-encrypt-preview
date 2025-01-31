"""Module configuring Certbot in a snap environment"""
from __future__ import annotations
import logging
import socket
from typing import Iterable
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union

from requests import PreparedRequest, Session
from requests.adapters import HTTPAdapter
from requests.exceptions import HTTPError
from requests.exceptions import RequestException

from certbot.compat import os
from certbot.errors import Error

try:
    from urllib3.connection import HTTPConnection
    from urllib3.connectionpool import HTTPConnectionPool
except ImportError:
    # Stub imports for oldest requirements, that will never be used in snaps.
    HTTPConnection = object  # type: ignore[misc,assignment]
    HTTPConnectionPool = object  # type: ignore[misc,assignment]


_ARCH_TRIPLET_MAP = {
    'arm64': 'aarch64-linux-gnu',
    'armhf': 'arm-linux-gnueabihf',
    'i386': 'i386-linux-gnu',
    'ppc64el': 'powerpc64le-linux-gnu',
    'powerpc': 'powerpc-linux-gnu',
    'amd64': 'x86_64-linux-gnu',
    's390x': 's390x-linux-gnu',
}
CURRENT_PYTHON_VERSION_STRING = 'python3.12'

LOGGER = logging.getLogger(__name__)


def prepare_env(cli_args: List[str]) -> List[str]:
    """
    Prepare runtime environment for a certbot execution in snap.
    :param list cli_args: List of command line arguments
    :return: Update list of command line arguments
    :rtype: list
    """
    snap_arch = os.environ.get('SNAP_ARCH')

    if snap_arch not in _ARCH_TRIPLET_MAP:
        raise Error('Unrecognized value of SNAP_ARCH: {0}'.format(snap_arch))

    os.environ['CERTBOT_AUGEAS_PATH'] = '{0}/usr/lib/{1}/libaugeas.so.0'.format(
        os.environ.get('SNAP'), _ARCH_TRIPLET_MAP[snap_arch])

    with Session() as session:
        session.mount('http://snapd/', _SnapdAdapter())

        try:
            response = session.get('http://snapd/v2/connections?snap=certbot&interface=content',
                                   timeout=30.0)
            response.raise_for_status()
        except RequestException as e:
            if isinstance(e, HTTPError) and e.response.status_code == 404:
                LOGGER.error('An error occurred while fetching Certbot snap plugins: '
                             'your version of snapd is outdated.')
                LOGGER.error('Please run "sudo snap install core; sudo snap refresh core" '
                             'in your terminal and try again.')
            else:
                LOGGER.error('An error occurred while fetching Certbot snap plugins: '
                             'make sure the snapd service is running.')
            raise e

    data = response.json()
    connections = []
    outdated_plugins = []
    for plugin in data.get('result', {}).get('established', []):
        plug: str = plugin.get('plug', {}).get('plug')
        plug_content: str = plugin.get('plug-attrs', {}).get('content')
        if plug == 'plugin' and plug_content == 'certbot-1':
            plugin_name: str = plugin['slot']['snap']
            # First, check that the plugin is using our expected python version,
            # i.e. its "read" slot is something like
            # "$SNAP/lib/python3.12/site-packages". If not, skip it and print an
            # error.
            slot_read: str = plugin.get('slot-attrs', {}).get('read', [])
            if len(slot_read) != 0 and CURRENT_PYTHON_VERSION_STRING not in slot_read[0]:
                outdated_plugins.append(plugin_name)
                continue

            connections.append('/snap/{0}/current/lib/{1}/site-packages/'.format(
                plugin_name,
                CURRENT_PYTHON_VERSION_STRING
            ))

    if outdated_plugins:
        LOGGER.warning('The following plugins are using an outdated python version and must be '
                    'updated to be compatible with Certbot 3.0. Please see '
                    'https://community.letsencrypt.org/t/'
                    'certbot-3-0-could-have-potential-third-party-snap-breakages/226940 '
                    'for more information:')
        plugin_list = '\n'.join('  * {}'.format(plugin) for plugin in outdated_plugins)
        LOGGER.warning(plugin_list)

    os.environ['CERTBOT_PLUGIN_PATH'] = ':'.join(connections)

    cli_args.append('--preconfigured-renewal')

    return cli_args


class _SnapdConnection(HTTPConnection):
    def __init__(self) -> None:
        super().__init__("localhost")
        self.sock: Optional[socket.socket] = None

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect("/run/snapd.socket")


class _SnapdConnectionPool(HTTPConnectionPool):
    def __init__(self) -> None:
        super().__init__("localhost")

    def _new_conn(self) -> _SnapdConnection:
        return _SnapdConnection()


class _SnapdAdapter(HTTPAdapter):
    # get_connection is used with versions of requests before 2.32.2 and
    # get_connection_with_tls_context is used instead in versions after that. as of
    # writing this, Certbot in EPEL 9 is still seeing updates and they have requests 2.25.1 so to
    # help out those packagers while ensuring this code works reliably, we offer custom versions of
    # both functions for now. when certbot does declare a dependency on requests>=2.32.2 in its
    # setup.py files, get_connection can be deleted
    def get_connection(self, url: str | bytes,
                       proxies: Optional[Iterable[str]] = None) -> _SnapdConnectionPool:
        return _SnapdConnectionPool()

    def get_connection_with_tls_context(self, request: PreparedRequest,
                                        verify: bool | str | None,
                                        proxies: Optional[Iterable[str]] = None,
                                        cert: Optional[Union[str, Tuple[str,str]]] = None
                                        ) -> _SnapdConnectionPool:
        """Required method for creating a new connection pool. Simply return our
        shim that forces a UNIX socket connection to snapd."""
        return _SnapdConnectionPool()
