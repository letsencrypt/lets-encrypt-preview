"""Tests for certbot_dns_conoha.dns_conoha."""

import os
import unittest

import mock
from requests.exceptions import HTTPError

from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.tests import util as test_util

REGION = 'tyo1'
TENANT_ID = '0123456789abcdef0123456789abcdef'
API_USERNAME = 'gncu01234567'
API_PASSWORD = 'p4ssw0rd'


class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_dns_conoha.dns_conoha import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write(
            {
                'conoha_region': REGION,
                'conoha_tenant_id': TENANT_ID,
                'conoha_api_username': API_USERNAME,
                'conoha_api_password': API_PASSWORD,
            },
            path
        )

        self.config = mock.MagicMock(conoha_credentials=path,
                                     conoha_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "conoha")

        self.mock_client = mock.MagicMock()
        # _get_conoha_client | pylint: disable=protected-access
        self.auth._get_conoha_client = mock.MagicMock(return_value=self.mock_client)


class ConohaLexiconClientTest(unittest.TestCase, dns_test_common_lexicon.BaseLexiconClientTest):
    LOGIN_ERROR = HTTPError('401 Client Error: Unauthorized for url: ...')

    def setUp(self):
        from certbot_dns_conoha.dns_conoha import _ConohaLexiconClient

        self.client = _ConohaLexiconClient(REGION, TENANT_ID, API_USERNAME, API_PASSWORD, 0)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
