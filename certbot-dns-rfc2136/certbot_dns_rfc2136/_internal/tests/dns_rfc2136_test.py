"""Tests for certbot_dns_rfc2136._internal.dns_rfc2136."""

import sys
import unittest
from unittest import mock

import dns.flags
import dns.rcode
import dns.tsig
import pytest

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

from certbot_dns_rfc2136._internal.dns_rfc2136 import TXTRecord

SERVER = '192.0.2.1'
PORT = 53
NAME = 'a-tsig-key.'
SECRET = 'SSB3b25kZXIgd2hvIHdpbGwgYm90aGVyIHRvIGRlY29kZSB0aGlzIHRleHQK'
VALID_CONFIG = {"rfc2136_server": SERVER, "rfc2136_name": NAME, "rfc2136_secret": SECRET}
TIMEOUT = 45


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        from certbot_dns_rfc2136._internal.dns_rfc2136 import Authenticator

        super().setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write(VALID_CONFIG, path)

        self.config = mock.MagicMock(rfc2136_credentials=path,
                                     rfc2136_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "rfc2136")

        self.mock_client = mock.MagicMock()
        # _get_rfc2136_client | pylint: disable=protected-access
        self.orig_get_client = self.auth._get_rfc2136_client
        self.auth._get_rfc2136_client = mock.MagicMock(return_value=self.mock_client)

    def test_get_client_default_conf_values(self):
        # algorithm and sign_query are intentionally absent to test that the default (None)
        # value does not crash Certbot.
        creds = { "server": SERVER, "port": PORT, "name": NAME, "secret": SECRET }
        self.auth.credentials = mock.MagicMock()
        self.auth.credentials.conf = lambda key: creds.get(key, None)
        client = self.orig_get_client()
        assert client.algorithm == self.auth.ALGORITHMS["HMAC-MD5"]
        assert client.sign_query == False

    @test_util.patch_display_util()
    def test_perform(self, unused_mock_get_utility):
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_records(TXTRecord(name='_acme-challenge.'+DOMAIN, content=mock.ANY, ttl=mock.ANY))]
        assert expected == self.mock_client.mock_calls

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_records(TXTRecord(name='_acme-challenge.'+DOMAIN, content=mock.ANY))]
        assert expected == self.mock_client.mock_calls

    def test_invalid_algorithm_raises(self):
        config = VALID_CONFIG.copy()
        config["rfc2136_algorithm"] = "INVALID"
        dns_test_common.write(config, self.config.rfc2136_credentials)

        with pytest.raises(errors.PluginError):
            self.auth.perform([self.achall])

    @test_util.patch_display_util()
    def test_valid_algorithm_passes(self, unused_mock_get_utility):
        config = VALID_CONFIG.copy()
        config["rfc2136_algorithm"] = "HMAC-sha512"
        dns_test_common.write(config, self.config.rfc2136_credentials)

        self.auth.perform([self.achall])

    def test_invalid_server_raises(self):
        config = VALID_CONFIG.copy()
        config["rfc2136_server"] = "example.com"
        dns_test_common.write(config, self.config.rfc2136_credentials)

        with pytest.raises(errors.PluginError):
            self.auth.perform([self.achall])

    @test_util.patch_display_util()
    def test_valid_server_passes(self, unused_mock_get_utility):
        config = VALID_CONFIG.copy()
        dns_test_common.write(config, self.config.rfc2136_credentials)

        self.auth.perform([self.achall])

        config["rfc2136_server"] = "2001:db8:3333:4444:cccc:dddd:eeee:ffff"
        dns_test_common.write(config, self.config.rfc2136_credentials)

        self.auth.perform([self.achall])


class RFC2136ClientTest(unittest.TestCase):

    def setUp(self):
        from certbot_dns_rfc2136._internal.dns_rfc2136 import _RFC2136Client

        self.rfc2136_client = _RFC2136Client(SERVER, PORT, NAME, SECRET, dns.tsig.HMAC_MD5,
        False, TIMEOUT)

    @mock.patch("dns.query.tcp")
    def test_add_txt_record(self, query_mock):
        query_mock.return_value.rcode.return_value = dns.rcode.NOERROR
        # _find_domain | pylint: disable=protected-access
        self.rfc2136_client._find_domain = mock.MagicMock(return_value="example.com")

        self.rfc2136_client.add_txt_records([TXTRecord(name="bar", content="baz", ttl=42)])

        query_mock.assert_called_with(mock.ANY, SERVER, TIMEOUT, PORT)
        assert 'bar. 42 IN TXT "baz"' in str(query_mock.call_args[0][0])

    @mock.patch("dns.query.tcp")
    def test_add_txt_record_wraps_errors(self, query_mock):
        query_mock.side_effect = Exception
        # _find_domain | pylint: disable=protected-access
        self.rfc2136_client._find_domain = mock.MagicMock(return_value="example.com")

        with pytest.raises(errors.PluginError):
            self.rfc2136_client.add_txt_records([TXTRecord(name="bar", content="baz", ttl=42)])

    @mock.patch("dns.query.tcp")
    def test_add_txt_record_server_error(self, query_mock):
        query_mock.return_value.rcode.return_value = dns.rcode.NXDOMAIN
        # _find_domain | pylint: disable=protected-access
        self.rfc2136_client._find_domain = mock.MagicMock(return_value="example.com")

        with pytest.raises(errors.PluginError):
            self.rfc2136_client.add_txt_records([TXTRecord(name="bar", content="baz", ttl=42)])

    @mock.patch("dns.query.tcp")
    def test_del_txt_record(self, query_mock):
        query_mock.return_value.rcode.return_value = dns.rcode.NOERROR
        # _find_domain | pylint: disable=protected-access
        self.rfc2136_client._find_domain = mock.MagicMock(return_value="example.com")

        self.rfc2136_client.del_txt_records([TXTRecord(name="bar", content="baz")])

        query_mock.assert_called_with(mock.ANY, SERVER, TIMEOUT, PORT)
        assert 'bar. 0 NONE TXT "baz"' in str(query_mock.call_args[0][0])

    @mock.patch("dns.query.tcp")
    def test_del_txt_record_wraps_errors(self, query_mock):
        query_mock.side_effect = Exception
        # _find_domain | pylint: disable=protected-access
        self.rfc2136_client._find_domain = mock.MagicMock(return_value="example.com")

        with pytest.raises(errors.PluginError):
            self.rfc2136_client.del_txt_records([TXTRecord(name="bar", content="baz")])

    @mock.patch("dns.query.tcp")
    def test_del_txt_record_server_error(self, query_mock):
        query_mock.return_value.rcode.return_value = dns.rcode.NXDOMAIN
        # _find_domain | pylint: disable=protected-access
        self.rfc2136_client._find_domain = mock.MagicMock(return_value="example.com")

        with pytest.raises(errors.PluginError):
            self.rfc2136_client.del_txt_records([TXTRecord(name="bar", content="baz")])

    def test_find_domain(self):
        import certbot_dns_rfc2136._internal.dns_rfc2136
        certbot_dns_rfc2136._internal.dns_rfc2136.SOA_CACHE = {}

        # _query_soa | pylint: disable=protected-access
        self.rfc2136_client._query_soa = mock.MagicMock(side_effect=[False, False, True])

        # _find_domain | pylint: disable=protected-access
        domain = self.rfc2136_client._find_domain('foo.bar.'+DOMAIN)

        assert domain == DOMAIN

    def test_find_domain_wraps_errors(self):
        import certbot_dns_rfc2136._internal.dns_rfc2136
        certbot_dns_rfc2136._internal.dns_rfc2136.SOA_CACHE = {}

        # _query_soa | pylint: disable=protected-access
        self.rfc2136_client._query_soa = mock.MagicMock(return_value=False)

        with pytest.raises(errors.PluginError):
            self.rfc2136_client._find_domain('foo.bar.'+DOMAIN)

    @mock.patch("dns.query.tcp")
    @mock.patch("dns.message.make_query")
    def test_query_soa_found(self, mock_make_query, query_mock):
        query_mock.return_value = mock.MagicMock(answer=[mock.MagicMock()], flags=dns.flags.AA)
        query_mock.return_value.rcode.return_value = dns.rcode.NOERROR
        mock_make_query.return_value = mock.MagicMock()

        # _query_soa | pylint: disable=protected-access
        result = self.rfc2136_client._query_soa(DOMAIN)

        query_mock.assert_called_with(mock.ANY, SERVER, TIMEOUT, PORT)
        mock_make_query.return_value.use_tsig.assert_not_called()
        assert result

    @mock.patch("dns.query.tcp")
    def test_query_soa_not_found(self, query_mock):
        query_mock.return_value.rcode.return_value = dns.rcode.NXDOMAIN

        # _query_soa | pylint: disable=protected-access
        result = self.rfc2136_client._query_soa(DOMAIN)

        query_mock.assert_called_with(mock.ANY, SERVER, TIMEOUT, PORT)
        assert not result

    @mock.patch("dns.query.tcp")
    def test_query_soa_wraps_errors(self, query_mock):
        query_mock.side_effect = Exception

        with pytest.raises(errors.PluginError):
            self.rfc2136_client._query_soa(DOMAIN)

    @mock.patch("dns.query.udp")
    @mock.patch("dns.query.tcp")
    def test_query_soa_fallback_to_udp(self, tcp_mock, udp_mock):
        tcp_mock.side_effect = OSError
        udp_mock.return_value = mock.MagicMock(answer=[mock.MagicMock()], flags=dns.flags.AA)
        udp_mock.return_value.rcode.return_value = dns.rcode.NOERROR

        # _query_soa | pylint: disable=protected-access
        result = self.rfc2136_client._query_soa(DOMAIN)

        tcp_mock.assert_called_with(mock.ANY, SERVER, TIMEOUT, PORT)
        udp_mock.assert_called_with(mock.ANY, SERVER, TIMEOUT, PORT)
        assert result

    @mock.patch("dns.query.tcp")
    @mock.patch("dns.message.make_query")
    def test_query_soa_signed(self, mock_make_query, unused_mock_query):
        mock_make_query.return_value = mock.MagicMock()
        self.rfc2136_client.sign_query = True
        self.rfc2136_client.algorithm = "alg0"

        self.rfc2136_client._query_soa(DOMAIN)

        mock_make_query.return_value.use_tsig.assert_called_with(mock.ANY, algorithm="alg0")


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
