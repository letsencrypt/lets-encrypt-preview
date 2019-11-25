"""Tests for certbot_dns_ispconfig.dns_ispconfig."""

import unittest

import mock
import json
import requests_mock

from certbot import errors
from certbot.compat import os
from certbot.errors import PluginError
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

FAKE_USER = "remoteuser"
FAKE_PW = "password"
FAKE_ENDPOINT = 'mock://endpoint'


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_dns_ispconfig.dns_ispconfig import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({
            "ispconfig_username": FAKE_USER, 
            "ispconfig_password": FAKE_PW, 
            "ispconfig_endpoint": FAKE_ENDPOINT, 
        }, path)

        super(AuthenticatorTest, self).setUp()
        self.config = mock.MagicMock(ispconfig_credentials=path,
                                     ispconfig_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "ispconfig")

        self.mock_client = mock.MagicMock()
        # _get_ispconfig_client | pylint: disable=protected-access
        self.auth._get_ispconfig_client = mock.MagicMock(return_value=self.mock_client)

    def test_perform(self):
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)


class ISPConfigClientTest(unittest.TestCase):
    record_name = "foo"
    record_content = "bar"
    record_ttl = 42

    def setUp(self):
        from certbot_dns_ispconfig.dns_ispconfig import _ISPConfigClient

        self.adapter = requests_mock.Adapter()

        self.client = _ISPConfigClient(FAKE_ENDPOINT, FAKE_USER, FAKE_PW)
        self.client.session.mount('mock', self.adapter)

    def _register_response(self, ep_id, response=None, message=None, additional_matcher=None, **kwargs):
        resp = {"code":"ok",
                "message":message,
                "response":response}
        if message is not None:
            resp['code'] = "remote_failure"

        def add_matcher(request):
            data = json.loads(request.text)
            add_result = True
            if additional_matcher is not None:
                add_result = additionsal_matcher(request)

            return ((('username' in data and data['username'] == FAKE_USER) and
                    ('username' in data and data['password'] == FAKE_PW)) or
                    data['session_id'] == 'FAKE_SESSION') and add_result

        self.adapter.register_uri(
            requests_mock.ANY,
            '{0}?{1}'.format(FAKE_ENDPOINT, ep_id),
            text=json.dumps(resp),
            additional_matcher=add_matcher,
            **kwargs
        )

    def test_add_txt_record(self):
        self._register_response('login', response='FAKE_SESSION')
        self._register_response('dns_zone_get_id', response=23)
        self._register_response('dns_txt_add', response=99)
        self._register_response('dns_zone_get', response={'zone_id': 102, 'server_id': 1})
        self._register_response('dns_rr_get_all_by_zone', response=[])
        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_add_txt_record_fail_to_find_domain(self):
        self._register_response('login', response='FAKE_SESSION')
        self._register_response('dns_zone_get_id', message='Not Found')
        with self.assertRaises(errors.PluginError) as context:
            self.client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_add_txt_record_fail_to_authenticate(self):
        self._register_response('login', message='FAILED')
        with self.assertRaises(errors.PluginError) as context:
            self.client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_del_txt_record(self):
        self._register_response('login', response='FAKE_SESSION')
        self._register_response('dns_zone_get_id', response=23)
        self._register_response('dns_rr_get_all_by_zone', response=[])
        self._register_response('dns_txt_delete', response='')
        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_del_txt_record_fail_to_find_domain(self):
        self._register_response('login', response='FAKE_SESSION')
        self._register_response('dns_zone_get_id', message='Not Found')
        with self.assertRaises(errors.PluginError) as context:
            self.client.del_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_del_txt_record_fail_to_authenticate(self):
        self._register_response('login', message='FAILED')
        with self.assertRaises(errors.PluginError) as context:
            self.client.del_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
