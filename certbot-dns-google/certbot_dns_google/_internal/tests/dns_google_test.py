"""Tests for certbot_dns_google._internal.dns_google."""

import sys
import unittest
from unittest import mock

from google.auth import exceptions as googleauth_exceptions
from googleapiclient import discovery
from googleapiclient.errors import Error
from googleapiclient.http import HttpMock
import pytest

from certbot import errors
from certbot.compat import os
from certbot.errors import PluginError
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

ACCOUNT_JSON_PATH = '/not/a/real/path.json'
API_ERROR = Error()
PROJECT_ID = "test-test-1"
SCOPES = ['https://www.googleapis.com/auth/ndev.clouddns.readwrite']

class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        super().setUp()

        from certbot_dns_google._internal.dns_google import Authenticator

        path = os.path.join(self.tempdir, 'file.json')
        open(path, "wb").close()

        super().setUp()
        self.config = mock.MagicMock(google_credentials=path,
                                     google_project=PROJECT_ID,
                                     google_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "google")

        self.mock_client = mock.MagicMock()

    @test_util.patch_display_util()
    def test_perform(self, unused_mock_get_utility):
        # _get_google_client | pylint: disable=protected-access
        self.auth._get_google_client = mock.MagicMock(return_value=self.mock_client)
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record('_acme-challenge.'+DOMAIN, mock.ANY, mock.ANY)]
        assert expected == self.mock_client.mock_calls

    def test_cleanup(self):
        # _get_google_client | pylint: disable=protected-access
        self.auth._get_google_client = mock.MagicMock(return_value=self.mock_client)
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record('_acme-challenge.'+DOMAIN, mock.ANY, mock.ANY)]
        assert expected == self.mock_client.mock_calls

    @test_util.patch_display_util()
    def test_without_auth(self, unused_mock_get_utility):
        self.auth._get_google_client = mock.MagicMock(side_effect=googleauth_exceptions.DefaultCredentialsError)
        self.config.google_credentials = None
        with pytest.raises(PluginError):
            self.auth.perform([self.achall])

    @mock.patch('certbot_dns_google._internal.dns_google._GoogleClient')
    def test_get_google_client(self, client_mock):
        test_client = mock.MagicMock()
        client_mock.return_value = test_client

        self.auth._get_google_client()
        assert client_mock.called
        assert self.auth.google_client is test_client

    def test_get_google_client_cached(self):
        test_client = mock.MagicMock()
        self.auth.google_client = test_client
        assert self.auth._get_google_client() is test_client


class GoogleClientTest(unittest.TestCase):
    record_name = "foo"
    record_content = "bar"
    record_ttl = 42
    zone = "ZONE_ID"
    change = "an-id"
    visibility = "public"

    def _setUp_client_with_mock(self, zone_request_side_effect, rrs_list_side_effect=None):
        from certbot_dns_google._internal.dns_google import _GoogleClient

        pwd = os.path.dirname(__file__)
        rel_path = 'testdata/discovery.json'
        discovery_file = os.path.join(pwd, rel_path)
        http_mock = HttpMock(discovery_file, {'status': '200'})
        dns_api = discovery.build('dns', 'v1', http=http_mock)

        client = _GoogleClient(ACCOUNT_JSON_PATH, None, dns_api)

        # Setup
        mock_mz = mock.MagicMock()
        mock_mz.list.return_value.execute.side_effect = zone_request_side_effect

        mock_rrs = mock.MagicMock()
        def rrs_list(project=None, managedZone=None, name=None, type=None):
            response = {"rrsets": []}
            if name == "_acme-challenge.example.org.":
                response = {"rrsets": [{"name": "_acme-challenge.example.org.", "type": "TXT",
                              "rrdatas": ["\"example-txt-contents\""], "ttl": 60}]}
            mock_return = mock.MagicMock()
            mock_return.execute.return_value = response
            mock_return.execute.side_effect = rrs_list_side_effect
            return mock_return
        mock_rrs.list.side_effect = rrs_list
        mock_changes = mock.MagicMock()

        client.dns.managedZones = mock.MagicMock(return_value=mock_mz)
        client.dns.changes = mock.MagicMock(return_value=mock_changes)
        client.dns.resourceRecordSets = mock.MagicMock(return_value=mock_rrs)

        return client, mock_changes

    @mock.patch('googleapiclient.discovery.build')
    @mock.patch('google.auth.default')
    def test_client_with_default_credentials(self, credential_mock, discovery_mock):
        test_credentials = mock.MagicMock()
        credential_mock.return_value = (test_credentials, PROJECT_ID)
        from certbot_dns_google._internal.dns_google import _GoogleClient
        client = _GoogleClient(None)
        credential_mock.assert_called_once_with(scopes=SCOPES)
        assert client.project_id == PROJECT_ID
        discovery_mock.assert_called_once_with('dns', 'v1',
                                credentials=test_credentials,
                                cache_discovery=False)

    @mock.patch('googleapiclient.discovery.build')
    @mock.patch('google.auth.load_credentials_from_file')
    def test_client_with_json_credentials(self, credential_mock, discovery_mock):
        test_credentials = mock.MagicMock()
        credential_mock.return_value = (test_credentials, PROJECT_ID)
        from certbot_dns_google._internal.dns_google import _GoogleClient
        client = _GoogleClient(ACCOUNT_JSON_PATH)
        credential_mock.assert_called_once_with(ACCOUNT_JSON_PATH, scopes=SCOPES)
        assert credential_mock.called
        assert client.project_id == PROJECT_ID
        discovery_mock.assert_called_once_with('dns', 'v1',
                                       credentials=test_credentials,
                                       cache_discovery=False)

    @mock.patch('google.auth.load_credentials_from_file')
    def test_client_bad_credentials_file(self, credential_mock):
        credential_mock.side_effect = googleauth_exceptions.DefaultCredentialsError('Some exception buried in google.auth')
        with pytest.raises(errors.PluginError) as exc_info:
            self._setUp_client_with_mock([])
        assert str(exc_info.value) == \
            "Error loading credentials file '/not/a/real/path.json': " \
            "Some exception buried in google.auth"

    @mock.patch('google.auth.load_credentials_from_file')
    def test_client_missing_project_id(self, credential_mock):
        credential_mock.return_value = (mock.MagicMock(), "")
        with pytest.raises(errors.PluginError) as exc_info:
            self._setUp_client_with_mock([])
        assert str(exc_info.value) == \
            "The Google Cloud project could not be automatically determined. " \
            "Please configure it using --dns-google-project <project>."

    @mock.patch('googleapiclient.discovery.build')
    @mock.patch('google.auth.default')
    def test_client_with_project_id(self, credential_mock, unused_discovery_mock):
        credential_mock.return_value = (mock.MagicMock(), PROJECT_ID)
        from certbot_dns_google._internal.dns_google import _GoogleClient
        client = _GoogleClient(None, "test-project-2")
        assert credential_mock.called
        assert client.project_id == "test-project-2"

    @mock.patch('google.auth.load_credentials_from_file')
    @mock.patch('certbot_dns_google._internal.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_add_txt_record(self, credential_mock):
        credential_mock.return_value = (mock.MagicMock(), PROJECT_ID)

        client, changes = self._setUp_client_with_mock([{'managedZones': [{'id': self.zone, 'visibility': self.visibility}]}])
        credential_mock.assert_called_once_with('/not/a/real/path.json', scopes=SCOPES)

        client.add_txt_record(self.record_name, self.record_content, self.record_ttl)

        expected_body = {
            "kind": "dns#change",
            "additions": [
                {
                    "kind": "dns#resourceRecordSet",
                    "type": "TXT",
                    "name": self.record_name + ".",
                    "rrdatas": [self.record_content, ],
                    "ttl": self.record_ttl,
                },
            ],
        }

        changes.create.assert_called_with(body=expected_body,
                                               managedZone=self.zone,
                                               project=PROJECT_ID)

    @mock.patch('google.auth.load_credentials_from_file')
    @mock.patch('certbot_dns_google._internal.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_add_txt_record_and_poll(self, credential_mock):
        credential_mock.return_value = (mock.MagicMock(), PROJECT_ID)

        client, changes = self._setUp_client_with_mock([{'managedZones': [{'id': self.zone, 'visibility': self.visibility}]}])
        changes.create.return_value.execute.return_value = {'status': 'pending', 'id': self.change}
        changes.get.return_value.execute.return_value = {'status': 'done'}

        client.add_txt_record(self.record_name, self.record_content, self.record_ttl)

        changes.create.assert_called_with(body=mock.ANY,
                                               managedZone=self.zone,
                                               project=PROJECT_ID)

        changes.get.assert_called_with(changeId=self.change,
                                            managedZone=self.zone,
                                            project=PROJECT_ID)

    @mock.patch('google.auth.load_credentials_from_file')
    @mock.patch('certbot_dns_google._internal.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_add_txt_record_and_poll_split_horizon(self, credential_mock):
        credential_mock.return_value = (mock.MagicMock(), PROJECT_ID)

        client, changes = self._setUp_client_with_mock([{'managedZones': [{'id': '{zone}-private'.format(zone=self.zone), 'dnsName': DOMAIN, 'visibility': 'private'},{'id': '{zone}-public'.format(zone=self.zone), 'dnsName': DOMAIN, 'visibility': self.visibility}]}])
        changes.create.return_value.execute.return_value = {'status': 'pending', 'id': self.change}
        changes.get.return_value.execute.return_value = {'status': 'done'}

        client.add_txt_record(self.record_name, self.record_content, self.record_ttl)

        changes.create.assert_called_with(body=mock.ANY,
                                               managedZone='{zone}-public'.format(zone=self.zone),
                                               project=PROJECT_ID)

        changes.get.assert_called_with(changeId=self.change,
                                            managedZone='{zone}-public'.format(zone=self.zone),
                                            project=PROJECT_ID)

    @mock.patch('google.auth.load_credentials_from_file')
    @mock.patch('certbot_dns_google._internal.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_add_txt_record_delete_old(self, credential_mock):
        credential_mock.return_value = (mock.MagicMock(), PROJECT_ID)

        client, changes = self._setUp_client_with_mock(
            [{'managedZones': [{'id': self.zone, 'visibility': self.visibility}]}])
        # pylint: disable=line-too-long
        mock_get_rrs = "certbot_dns_google._internal.dns_google._GoogleClient.get_existing_txt_rrset"
        with mock.patch(mock_get_rrs) as mock_rrs:
            mock_rrs.return_value = {"rrdatas": ["sample-txt-contents"], "ttl": self.record_ttl}
            client.add_txt_record(self.record_name, self.record_content, self.record_ttl)
            assert changes.create.called is True
            deletions = changes.create.call_args_list[0][1]["body"]["deletions"][0]
            assert "sample-txt-contents" in deletions["rrdatas"]
            assert self.record_ttl == deletions["ttl"]

    @mock.patch('google.auth.load_credentials_from_file')
    @mock.patch('certbot_dns_google._internal.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_add_txt_record_delete_old_ttl_case(self, credential_mock):
        credential_mock.return_value = (mock.MagicMock(), PROJECT_ID)

        client, changes = self._setUp_client_with_mock(
            [{'managedZones': [{'id': self.zone, 'visibility': self.visibility}]}])
        # pylint: disable=line-too-long
        mock_get_rrs = "certbot_dns_google._internal.dns_google._GoogleClient.get_existing_txt_rrset"
        with mock.patch(mock_get_rrs) as mock_rrs:
            custom_ttl = 300
            mock_rrs.return_value = {"rrdatas": ["sample-txt-contents"], "ttl": custom_ttl}
            client.add_txt_record(self.record_name, self.record_content, self.record_ttl)
            assert changes.create.called is True
            deletions = changes.create.call_args_list[0][1]["body"]["deletions"][0]
            assert "sample-txt-contents" in deletions["rrdatas"]
            assert custom_ttl == deletions["ttl"] #otherwise HTTP 412

    @mock.patch('google.auth.load_credentials_from_file')
    @mock.patch('certbot_dns_google._internal.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_add_txt_record_noop(self, credential_mock):
        credential_mock.return_value = (mock.MagicMock(), PROJECT_ID)

        client, changes = self._setUp_client_with_mock(
            [{'managedZones': [{'id': self.zone, 'visibility': self.visibility}]}])
        client.add_txt_record("_acme-challenge.example.org",
                              "example-txt-contents", self.record_ttl)
        assert changes.create.called is False

    @mock.patch('google.auth.load_credentials_from_file')
    @mock.patch('certbot_dns_google._internal.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_add_txt_record_error_during_zone_lookup(self, credential_mock):
        credential_mock.return_value = (mock.MagicMock(), PROJECT_ID)

        client, unused_changes = self._setUp_client_with_mock(API_ERROR)

        with pytest.raises(errors.PluginError):
            client.add_txt_record(self.record_name, self.record_content, self.record_ttl)

    @mock.patch('google.auth.load_credentials_from_file')
    @mock.patch('certbot_dns_google._internal.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_add_txt_record_zone_not_found(self, credential_mock):
        credential_mock.return_value = (mock.MagicMock(), PROJECT_ID)

        client, unused_changes = self._setUp_client_with_mock([{'managedZones': []},
                                                               {'managedZones': []}])

        with pytest.raises(errors.PluginError):
            client.add_txt_record(self.record_name, self.record_content, self.record_ttl)

    @mock.patch('google.auth.load_credentials_from_file')
    @mock.patch('certbot_dns_google._internal.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_add_txt_record_error_during_add(self, credential_mock):
        credential_mock.return_value = (mock.MagicMock(), PROJECT_ID)

        client, changes = self._setUp_client_with_mock([{'managedZones': [{'id': self.zone, 'visibility': self.visibility}]}])
        changes.create.side_effect = API_ERROR

        with pytest.raises(errors.PluginError):
            client.add_txt_record(self.record_name, self.record_content, self.record_ttl)

    @mock.patch('google.auth.load_credentials_from_file')
    @mock.patch('certbot_dns_google._internal.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_del_txt_record_multi_rrdatas(self, credential_mock):
        credential_mock.return_value = (mock.MagicMock(), PROJECT_ID)

        client, changes = self._setUp_client_with_mock([{'managedZones': [{'id': self.zone, 'visibility': self.visibility}]}])
        # pylint: disable=line-too-long
        mock_get_rrs = "certbot_dns_google._internal.dns_google._GoogleClient.get_existing_txt_rrset"
        with mock.patch(mock_get_rrs) as mock_rrs:
            mock_rrs.return_value = {"rrdatas": ["\"sample-txt-contents\"",
                                     "\"example-txt-contents\""], "ttl": self.record_ttl}
            client.del_txt_record("_acme-challenge.example.org",
                                "example-txt-contents", self.record_ttl)

        expected_body = {
            "kind": "dns#change",
            "deletions": [
                {
                    "kind": "dns#resourceRecordSet",
                    "type": "TXT",
                    "name": "_acme-challenge.example.org.",
                    "rrdatas": ["\"sample-txt-contents\"", "\"example-txt-contents\""],
                    "ttl": self.record_ttl,
                },
            ],
            "additions": [
                {
                    "kind": "dns#resourceRecordSet",
                    "type": "TXT",
                    "name": "_acme-challenge.example.org.",
                    "rrdatas": ["\"sample-txt-contents\"", ],
                    "ttl": self.record_ttl,
                },
            ],
        }

        changes.create.assert_called_with(body=expected_body,
                                               managedZone=self.zone,
                                               project=PROJECT_ID)

    @mock.patch('google.auth.load_credentials_from_file')
    @mock.patch('certbot_dns_google._internal.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_del_txt_record_single_rrdatas(self, credential_mock):
        credential_mock.return_value = (mock.MagicMock(), PROJECT_ID)

        client, changes = self._setUp_client_with_mock([{'managedZones': [{'id': self.zone, 'visibility': self.visibility}]}])
        # pylint: disable=line-too-long
        mock_get_rrs = "certbot_dns_google._internal.dns_google._GoogleClient.get_existing_txt_rrset"
        with mock.patch(mock_get_rrs) as mock_rrs:
            mock_rrs.return_value = {"rrdatas": ["\"example-txt-contents\""], "ttl": self.record_ttl}
            client.del_txt_record("_acme-challenge.example.org",
                                "example-txt-contents", self.record_ttl)

        expected_body = {
            "kind": "dns#change",
            "deletions": [
                {
                    "kind": "dns#resourceRecordSet",
                    "type": "TXT",
                    "name": "_acme-challenge.example.org.",
                    "rrdatas": ["\"example-txt-contents\""],
                    "ttl": self.record_ttl,
                },
            ],
        }

        changes.create.assert_called_with(body=expected_body,
                                               managedZone=self.zone,
                                               project=PROJECT_ID)

    @mock.patch('google.auth.load_credentials_from_file')
    @mock.patch('certbot_dns_google._internal.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_del_txt_record_error_during_zone_lookup(self, credential_mock):
        credential_mock.return_value = (mock.MagicMock(), PROJECT_ID)

        client, changes = self._setUp_client_with_mock(API_ERROR)
        client.del_txt_record(self.record_name, self.record_content, self.record_ttl)
        changes.create.assert_not_called()

    @mock.patch('google.auth.load_credentials_from_file')
    @mock.patch('certbot_dns_google._internal.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_del_txt_record_zone_not_found(self, credential_mock):
        credential_mock.return_value = (mock.MagicMock(), PROJECT_ID)

        client, changes = self._setUp_client_with_mock([{'managedZones': []},
                                                               {'managedZones': []}])
        client.del_txt_record(self.record_name, self.record_content, self.record_ttl)
        changes.create.assert_not_called()

    @mock.patch('google.auth.load_credentials_from_file')
    @mock.patch('certbot_dns_google._internal.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_del_txt_record_error_during_delete(self, credential_mock):
        credential_mock.return_value = (mock.MagicMock(), PROJECT_ID)

        client, changes = self._setUp_client_with_mock([{'managedZones': [{'id': self.zone, 'visibility': self.visibility}]}])
        changes.create.side_effect = API_ERROR

        client.del_txt_record(self.record_name, self.record_content, self.record_ttl)

    @mock.patch('google.auth.load_credentials_from_file')
    @mock.patch('certbot_dns_google._internal.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_get_existing_found(self, credential_mock):
        credential_mock.return_value = (mock.MagicMock(), PROJECT_ID)

        client, unused_changes = self._setUp_client_with_mock(
            [{'managedZones': [{'id': self.zone, 'visibility': self.visibility}]}])
        # Record name mocked in setUp
        found = client.get_existing_txt_rrset(self.zone, "_acme-challenge.example.org")
        assert found["rrdatas"] == ["\"example-txt-contents\""]
        assert found["ttl"] == 60

    @mock.patch('google.auth.load_credentials_from_file')
    @mock.patch('certbot_dns_google._internal.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_get_existing_not_found(self, credential_mock):
        credential_mock.return_value = (mock.MagicMock(), PROJECT_ID)

        client, unused_changes = self._setUp_client_with_mock(
            [{'managedZones': [{'id': self.zone, 'visibility': self.visibility}]}])
        not_found = client.get_existing_txt_rrset(self.zone, "nonexistent.tld")
        assert not_found is None

    @mock.patch('google.auth.load_credentials_from_file')
    @mock.patch('certbot_dns_google._internal.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_get_existing_with_error(self, credential_mock):
        credential_mock.return_value = (mock.MagicMock(), PROJECT_ID)

        client, unused_changes = self._setUp_client_with_mock(
            [{'managedZones': [{'id': self.zone, 'visibility': self.visibility}]}], API_ERROR)
        # Record name mocked in setUp
        found = client.get_existing_txt_rrset(self.zone, "_acme-challenge.example.org")
        assert found is None

    @mock.patch('google.auth.load_credentials_from_file')
    @mock.patch('certbot_dns_google._internal.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_get_existing_fallback(self, credential_mock):
        credential_mock.return_value = (mock.MagicMock(), PROJECT_ID)

        client, unused_changes = self._setUp_client_with_mock(
            [{'managedZones': [{'id': self.zone, 'visibility': self.visibility}]}], API_ERROR)
        rrset = client.get_existing_txt_rrset(self.zone, "_acme-challenge.example.org")
        assert not rrset

if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
