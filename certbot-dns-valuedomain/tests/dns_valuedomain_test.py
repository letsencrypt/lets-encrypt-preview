"""Tests for certbot_dns_valuedomain._internal.dns_valuedomain."""

import unittest

try:
    import mock
except ImportError: # pragma: no cover
    from unittest import mock # type: ignore
from requests.exceptions import HTTPError

from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

API_TOKEN = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_dns_valuedomain._internal.dns_valuedomain import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write(
            {"valuedomain_api_token": API_TOKEN},
            path
        )

        self.config = mock.MagicMock(valuedomain_credentials=path,
                                     valuedomain_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "valuedomain")

        self.mock_client = mock.MagicMock()
        # _get_valuedomain_client | pylint: disable=protected-access
        self.auth._get_valuedomain_client = mock.MagicMock(return_value=self.mock_client)


class _ValueDomainLexiconClientTest(unittest.TestCase,
                                     dns_test_common_lexicon.BaseLexiconClientTest):
    DOMAIN_NOT_FOUND = HTTPError('404 Client Error: Not Found for url: {0}.'.format(DOMAIN))
    LOGIN_ERROR = HTTPError('401 Client Error: Unauthorized for url: {0}.'.format(DOMAIN))

    def setUp(self):
        from certbot_dns_valuedomain._internal.dns_valuedomain import _ValueDomainLexiconClient

        self.client = _ValueDomainLexiconClient(API_TOKEN, 0)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
