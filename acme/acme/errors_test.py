"""Tests for acme.errors."""
import unittest

import mock


class BadNonceTest(unittest.TestCase):
    """Tests for acme.errors.BadNonce."""

    def setUp(self):
        from acme.errors import BadNonce
        self.error = BadNonce(nonce="xxx", error="error")

    def test_str(self):
        self.assertEqual("Invalid nonce ('xxx'): error", str(self.error))


class MissingNonceTest(unittest.TestCase):
    """Tests for acme.errors.MissingNonce."""

    def setUp(self):
        from acme.errors import MissingNonce
        self.response = mock.MagicMock(headers={})
        self.response.request.method = 'FOO'
        self.error = MissingNonce(self.response)

    def test_str(self):
        self.assertTrue("FOO" in str(self.error))
        self.assertTrue("{}" in str(self.error))


class PollErrorTest(unittest.TestCase):
    """Tests for acme.errors.PollError."""

    def setUp(self):
        from acme.errors import PollError
        self.timeout = PollError(
            exhausted=set([mock.sentinel.AR]),
            updated={})
        self.invalid = PollError(exhausted=set(), updated={
            mock.sentinel.AR: mock.sentinel.AR2})

    def test_timeout(self):
        self.assertTrue(self.timeout.timeout)
        self.assertFalse(self.invalid.timeout)

    def test_repr(self):
        self.assertEqual('PollError(exhausted=%s, updated={sentinel.AR: '
                         'sentinel.AR2})' % repr(set()), repr(self.invalid))


class ValidationErrorTest(unittest.TestCase):
    """Tests for acme.errors.ValidationError"""

    def setUp(self):
        from acme.errors import ValidationError
        failed_authzr = mock.MagicMock()
        failed_authzr.body.identifier = 'example.com'
        challenge = mock.MagicMock()
        challenge.chall.typ = 'dns-01'
        challenge.error.typ = 'generic error'
        challenge.error.detail = 'detail message'
        failed_authzr.body.challenges = [challenge]
        self.error = ValidationError([failed_authzr])

    def test_repr(self):
        self.assertEqual(
            '\n Authorization for identifier example.com failed.'
            '\n Here are the challenges that were not fulfilled:'
            '\n Challenge Type: dns-01'
            '\n Error information: '
            '\n Type: generic error'
            '\n Details: detail message \n\n',
            str(self.error),
        )


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
