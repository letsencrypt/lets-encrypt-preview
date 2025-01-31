"""Tests for acme.jose shim."""
import importlib
import sys

import pytest


def _test_it(submodule, attribute):
    if submodule:
        acme_jose_path = 'acme.jose.' + submodule
        josepy_path = 'josepy.' + submodule
    else:
        acme_jose_path = 'acme.jose'
        josepy_path = 'josepy'
    acme_jose_mod = importlib.import_module(acme_jose_path)
    josepy_mod = importlib.import_module(josepy_path)

    assert acme_jose_mod is josepy_mod
    assert getattr(acme_jose_mod, attribute) is getattr(josepy_mod, attribute)

    # We use the imports below with eval, but pylint doesn't
    # understand that.
    import josepy  # pylint: disable=unused-import

    import acme  # pylint: disable=unused-import
    acme_jose_mod = eval(acme_jose_path)  # pylint: disable=eval-used
    josepy_mod = eval(josepy_path)  # pylint: disable=eval-used
    assert acme_jose_mod is josepy_mod
    assert getattr(acme_jose_mod, attribute) is getattr(josepy_mod, attribute)

def test_top_level():
    _test_it('', 'RS512')

def test_submodules():
    # This test ensures that the modules in josepy that were
    # available at the time it was moved into its own package are
    # available under acme.jose. Backwards compatibility with new
    # modules or testing code is not maintained.
    mods_and_attrs = [('b64', 'b64decode',),
                      ('errors', 'Error',),
                      ('interfaces', 'JSONDeSerializable',),
                      ('json_util', 'Field',),
                      ('jwa', 'HS256',),
                      ('jwk', 'JWK',),
                      ('jws', 'JWS',),
                      ('util', 'ImmutableMap',),]

    for mod, attr in mods_and_attrs:
        _test_it(mod, attr)


if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
