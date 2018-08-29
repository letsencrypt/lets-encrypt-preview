"""Tests for certbot_dns_dnspod.dns_dnspod."""

import os
import unittest

import mock

from certbot import errors
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

ID = 1201
TOKEN = 'a-token'

class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        from certbot_dns_dnspod.dns_dnspod import Authenticator

        super(AuthenticatorTest, self).setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"dnspod_token": TOKEN, "dnspod_id": ID}, path)

        self.config = mock.MagicMock(dnspod_credentials=path,
                                     dnspod_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "dnspod")

        self.mock_client = mock.MagicMock()
        # _get_dnspod_client | pylint: disable=protected-access
        self.auth._get_dnspod_client = mock.MagicMock(return_value=self.mock_client)

    def test_perform(self):
        self.mock_client.domain_list.return_value = {DOMAIN: mock.ANY}
        self.auth.perform([self.achall])

        expected = [mock.call.domain_list(),
                mock.call.ensure_record(DOMAIN, '_acme-challenge.'+DOMAIN, 'TXT', mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_perform_fail_to_find_domain(self):
        self.mock_client.domain_list.return_value = {}

        self.assertRaises(errors.PluginError,
                          self.auth.perform,
                          [self.achall])

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth._find_domain = mock.MagicMock(return_value=DOMAIN)
        self.auth.cleanup([self.achall])

        expected = [mock.call.remove_record_by_sub_domain(DOMAIN, '_acme-challenge.'+DOMAIN, 'TXT')]
        self.assertEqual(expected, self.mock_client.mock_calls)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
