"""Tests for certbot_dns_dnspod.dns_dnspod_client."""
import unittest

import mock

from certbot.plugins.dns_test_common import DOMAIN

dnspod_id = 'id'
dnspod_key = 'key'

class DnspodClientTest(unittest.TestCase):

    record_id = 1
    record_prefix = "_acme-challenge"
    record_name = record_prefix + "." + DOMAIN
    record_type = "TXT"
    record_content = "bar"

    def setUp(self):
        from certbot_dns_dnspod.dns_dnspod_client import DnspodClient
        self.client = DnspodClient(dnspod_id, dnspod_key)
        self.client.request = mock.MagicMock()

    def test_add_record(self):
        self.client.add_record(DOMAIN, self.record_name, self.record_type, self.record_content)

        data = {'record_type': self.record_type, 'domain': DOMAIN, 'sub_domain': self.record_prefix,
                'record_line_id': 0, 'value': self.record_content}
        self.client.request.assert_called_with('Record.Create', data)

    def test_remove_record(self):
        self.client.remove_record(DOMAIN, self.record_id)

        data = {'record_id': self.record_id, 'domain': DOMAIN}
        self.client.request.assert_called_with('Record.Remove', data)

    def test_modify_record(self):
        self.client.modify_record(DOMAIN, self.record_id, self.record_type, self.record_content)

        data = {'record_id': self.record_id, 'record_type': self.record_type, 'domain': DOMAIN,
                'record_line_id': 0, 'value': self.record_content}
        self.client.request.assert_called_with('Record.Modify', data)

    def test_get_record_list(self):
        self.client.get_record_list(DOMAIN, self.record_type)

        data = {'record_type': self.record_type, 'domain': DOMAIN}
        self.client.request.assert_called_with('Record.List', data)

    def test_domain_list(self):
        self.client.domain_list()

        data = {'length': 3000}
        self.client.request.assert_called_with('Domain.List', data)

    def test_ensure_record_add_record(self):
        record_list = [] # type: ignore
        self.client.get_record_list = mock.MagicMock(return_value=record_list)
        self.client.ensure_record(DOMAIN, self.record_name, self.record_type, self.record_content)

        data = {'record_type': self.record_type, 'domain': DOMAIN, 'sub_domain': self.record_prefix,
                'record_line_id': 0, 'value': self.record_content}
        self.client.request.assert_called_with('Record.Create', data)

    def test_ensure_record_modify_record(self):
        record_list = [{'name': self.record_prefix, 'id': self.record_id}]
        self.client.get_record_list = mock.MagicMock(return_value=record_list)
        self.client.ensure_record(DOMAIN, self.record_name, self.record_type, self.record_content)

        data = {'record_id': self.record_id, 'record_type': self.record_type, 'domain': DOMAIN,
                'record_line_id': 0, 'value': self.record_content}
        self.client.request.assert_called_with('Record.Modify', data)

    def test_remove_record_by_sub_domain(self):
        record_list = [{'name': self.record_prefix, 'id': self.record_id}]
        self.client.get_record_list = mock.MagicMock(return_value=record_list)
        self.client.remove_record_by_sub_domain(DOMAIN, self.record_name, self.record_type)

        data = {'record_id': self.record_id, 'domain': DOMAIN}
        self.client.request.assert_called_with('Record.Remove', data)

    def test_get_sub_domain(self):
        from certbot_dns_dnspod.dns_dnspod_client import get_sub_domain
        self.assertEqual(get_sub_domain(DOMAIN, 'www.' + DOMAIN), 'www')
        self.assertEqual(get_sub_domain(DOMAIN, DOMAIN), '@')
        self.assertEqual(get_sub_domain(DOMAIN, '.' + DOMAIN), '@')
        self.assertEqual(get_sub_domain(DOMAIN, '*.' + DOMAIN), '*')

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
