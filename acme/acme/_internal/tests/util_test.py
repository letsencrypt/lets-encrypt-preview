"""Tests for acme.util."""
import sys

import pytest


def test_it():
    from acme.util import map_keys
    assert {'a': 'b', 'c': 'd'} == \
                     map_keys({'a': 'b', 'c': 'd'}, lambda key: key)
    assert {2: 2, 4: 4} == map_keys({1: 2, 3: 4}, lambda x: x + 1)


if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
