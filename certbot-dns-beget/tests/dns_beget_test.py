"""Tests for certbot_dns_beget._internal.dns_beget."""

import unittest


try:
    import mock
except ImportError: # pragma: no cover
    from unittest import mock # type: ignore
from requests.exceptions import HTTPError

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

LOGIN = 'demo'
PASSWORD = 'demo'
VALID_CONFIG = {"login": LOGIN, "password": PASSWORD}

class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        from certbot_dns_beget._internal.dns_beget import Authenticator

        super(AuthenticatorTest, self).setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write(VALID_CONFIG, path)

        self.config = mock.MagicMock(beget_credentials=path,
                                     beget_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "beget")

        self.mock_client = mock.MagicMock()
        # _get_beget_client | pylint: disable=protected-access
        self.auth._get_beget_client = mock.MagicMock(return_value=self.mock_client)
    
    def test_perform(self):
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record('_acme-challenge.'+DOMAIN, mock.ANY, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record('_acme-challenge.'+DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    
    def test_api_login(self):
        dns_test_common.write({"beget_api_login": LOGIN},
                              self.config.beget_credentials)
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_no_creds(self):
        dns_test_common.write({}, self.config.beget_credentials)
        self.assertRaises(errors.PluginError,
                          self.auth.perform,
                          [self.achall])

class BegetClientTest(unittest.TestCase):
    record_name = "foo"
    record_content = "bar"
    record_priority = 10

    DOMAIN_NOT_FOUND = HTTPError('404 Client Error: Not Found for url: {0}.'.format(DOMAIN))
    LOGIN_ERROR = HTTPError('401 Client Error: Unauthorized for url: {0}.'.format(DOMAIN))

    def setUp(self):
        from certbot_dns_beget._internal.dns_beget import _BegetClient
        self.beget_client = _BegetClient(LOGIN, PASSWORD)
       
    def test_add_txt_record(self):

       self.assertRaises(
            errors.PluginError,
            self.beget_client.add_txt_record,
            DOMAIN, self.record_name, self.record_content, self.record_priority)

    def test_del_txt_record(self):

        self.assertRaises(
            errors.PluginError,
            self.beget_client.del_txt_record,
            DOMAIN, self.record_name, self.record_content, self.record_priority)

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
