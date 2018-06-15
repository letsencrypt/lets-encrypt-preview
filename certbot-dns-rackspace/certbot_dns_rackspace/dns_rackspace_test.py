"""Tests for certbot_dns_rackspace.dns_rackspace."""

import os
import unittest

import mock
from requests.exceptions import HTTPError

from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.tests import util as test_util

USERNAME = 'foo'
APIKEY = '1234567890abcdef1234567890abcdef'
ACCOUNT_ID = '12345678'

class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_dns_rackspace.dns_rackspace import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"rackspace_username": USERNAME, "rackspace_apiKey": APIKEY, \
                               "rackspace_account_id": ACCOUNT_ID}, path)

        self.config = mock.MagicMock(rackspace_credentials=path,
                                     rackspace_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "rackspace")

        self.mock_client = mock.MagicMock()
        # _get_rackspace_client | pylint: disable=protected-access
        self.auth._get_rackspace_client = mock.MagicMock(return_value=self.mock_client)


class RackspaceLexiconClientTest(unittest.TestCase, dns_test_common_lexicon.BaseLexiconClientTest):

    LOGIN_ERROR = HTTPError('401 Client Error: Unauthorized for url: ...')

    def setUp(self):
        from certbot_dns_rackspace.dns_rackspace import _RackspaceLexiconClient

        self.client = _RackspaceLexiconClient(USERNAME, APIKEY, ACCOUNT_ID, 1, 0)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
