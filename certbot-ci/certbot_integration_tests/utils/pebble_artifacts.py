# pylint: disable=missing-module-docstring
import atexit
import json
import os
import platform
import stat
import sys
from contextlib import ExitStack
from typing import Tuple

import requests

from certbot_integration_tests.utils.constants import DEFAULT_HTTP_01_PORT
from certbot_integration_tests.utils.constants import MOCK_OCSP_SERVER_PORT

if sys.version_info >= (3, 9):  # pragma: no cover
    import importlib.resources as importlib_resources
else:  # pragma: no cover
    import importlib_resources

PEBBLE_VERSION = 'v2.3.1'


def fetch(workspace: str, http_01_port: int = DEFAULT_HTTP_01_PORT) -> Tuple[str, str, str]:
    # pylint: disable=missing-function-docstring
    suffixes = {'Windows': 'windows-amd64.exe', 'Darwin': 'darwin-arm64'}
    suffix = suffixes.get(platform.system(), 'linux-amd64')

    file_manager = ExitStack()
    atexit.register(file_manager.close)
    pebble_path_ref = importlib_resources.files('certbot_integration_tests') / 'assets'
    assets_path = str(file_manager.enter_context(importlib_resources.as_file(pebble_path_ref)))

    pebble_path = _fetch_asset('pebble', suffix, assets_path)
    challtestsrv_path = _fetch_asset('pebble-challtestsrv', suffix, assets_path)
    pebble_config_path = _build_pebble_config(workspace, http_01_port, assets_path)

    return pebble_path, challtestsrv_path, pebble_config_path


def _fetch_asset(asset: str, suffix: str, assets_path: str) -> str:
    asset_path = os.path.join(assets_path, '{0}_{1}_{2}'.format(asset, PEBBLE_VERSION, suffix))
    if not os.path.exists(asset_path):
        asset_url = ('https://github.com/letsencrypt/pebble/releases/download/{0}/{1}_{2}'
                     .format(PEBBLE_VERSION, asset, suffix))
        response = requests.get(asset_url, timeout=30)
        response.raise_for_status()
        with open(asset_path, 'wb') as file_h:
            file_h.write(response.content)
    os.chmod(asset_path, os.stat(asset_path).st_mode | stat.S_IEXEC)

    return asset_path


def _build_pebble_config(workspace: str, http_01_port: int, assets_path: str) -> str:
    config_path = os.path.join(workspace, 'pebble-config.json')
    with open(config_path, 'w') as file_h:
        file_h.write(json.dumps({
            'pebble': {
                'listenAddress': '0.0.0.0:14000',
                'managementListenAddress': '0.0.0.0:15000',
                'certificate': os.path.join(assets_path, 'cert.pem'),
                'privateKey': os.path.join(assets_path, 'key.pem'),
                'httpPort': http_01_port,
                'tlsPort': 5001,
                'ocspResponderURL': 'http://127.0.0.1:{0}'.format(MOCK_OCSP_SERVER_PORT),
            },
        }))

    return config_path
