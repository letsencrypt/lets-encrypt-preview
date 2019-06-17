"""nginx plugin constants."""
import platform

FREEBSD_DARWIN_SERVER_ROOT = "/usr/local/etc/nginx"
LINUX_SERVER_ROOT = "/etc/nginx"

if platform.system() in ('FreeBSD', 'Darwin'):
    server_root_tmp = FREEBSD_DARWIN_SERVER_ROOT
else:
    server_root_tmp = LINUX_SERVER_ROOT

CLI_DEFAULTS = dict(
    server_root=server_root_tmp,
    ctl="nginx",
)
"""CLI defaults."""


MOD_SSL_CONF_DEST = "options-ssl-nginx.conf"
"""Name of the mod_ssl config file as saved in `IConfig.config_dir`."""

UPDATED_MOD_SSL_CONF_DIGEST = ".updated-options-ssl-nginx-conf-digest.txt"
"""Name of the hash of the updated or informed mod_ssl_conf as saved in `IConfig.config_dir`."""

SSL_OPTIONS_HASHES_NEW = [
    '63e2bddebb174a05c9d8a7cf2adf72f7af04349ba59a1a925fe447f73b2f1abf',
    '5f094d6f3f99401865e8a48e5c43e98647a77174dc451fa59e332ad25bd030e7',
]
"""SHA256 hashes of the contents of versions of MOD_SSL_CONF_SRC for nginx >= 1.5.9"""

ALL_SSL_OPTIONS_HASHES = [
    '0f81093a1465e3d4eaa8b0c14e77b2a2e93568b0fc1351c2b87893a95f0de87c',
    '9a7b32c49001fed4cff8ad24353329472a50e86ade1ef9b2b9e43566a619612e',
    'a6d9f1c7d6b36749b52ba061fff1421f9a0a3d2cfdafbd63c05d06f65b990937',
    '7f95624dd95cf5afc708b9f967ee83a24b8025dc7c8d9df2b556bbc64256b3ff',
    '394732f2bbe3e5e637c3fb5c6e980a1f1b90b01e2e8d6b7cff41dde16e2a756d',
    '4b16fec2bcbcd8a2f3296d886f17f9953ffdcc0af54582452ca1e52f5f776f16',
    '21ad3049636c1b1a685bd840a42e0e9e48fe78949523d18ea9c05f301a598d8d',
] + SSL_OPTIONS_HASHES_NEW
"""SHA256 hashes of the contents of all versions of MOD_SSL_CONF_SRC"""

def os_constant(key):
    # XXX TODO: In the future, this could return different constants
    #           based on what OS we are running under.  To see an
    #           approach to how to handle different OSes, see the
    #           apache version of this file.  Currently, we do not
    #           actually have any OS-specific constants on Nginx.
    """
    Get a constant value for operating system

    :param key: name of cli constant
    :return: value of constant for active os
    """
    return CLI_DEFAULTS[key]

HSTS_ARGS = ['\"max-age=31536000\"', ' ', 'always']

HEADER_ARGS = {'Strict-Transport-Security': HSTS_ARGS}
