"""ACME protocol implementation.

This module is an implementation of the `ACME protocol`_.

.. _`ACME protocol`: https://ietf-wg-acme.github.io/acme

"""
import sys

# This code exists to keep backwards compatibility with people using acme.jose
# before it became the standalone josepy package.
#
# It is based on
# https://github.com/requests/requests/blob/1278ecdf71a312dc2268f3bfc0aabfab3c006dcf/requests/packages.py

import josepy as jose

for mod in list(sys.modules):
    # This traversal is apparently necessary such that the identities are
    # preserved (acme.jose.* is josepy.*)
    if mod == 'josepy' or mod.startswith('josepy.'):
        sys.modules['acme.' + mod.replace('josepy', 'jose', 1)] = sys.modules[mod]


class _TLSSNI01DeprecationModule(object):
    """
    Internal class delegating to a module, and displaying warnings when
    attributes related to TLS-SNI-01 are accessed
    """
    def __init__(self, module):
        self.__dict__['_module'] = module

    def __getattr__(self, attr):
        if 'TLSSNI01' in attr:
            sys.stderr.write('TLS-SNI-01 challenges are deprecated, and will '
                             'be removed on April 2019 with acme 0.34.0.\n')
        return getattr(self._module, attr)

    def __setattr__(self, attr, value):  # pragma: no cover
        setattr(self._module, attr, value)

    def __delattr__(self, attr):  # pragma: no cover
        delattr(self._module, attr)

    def __dir__(self):  # pragma: no cover
        return ['_module'] + dir(self._module)
