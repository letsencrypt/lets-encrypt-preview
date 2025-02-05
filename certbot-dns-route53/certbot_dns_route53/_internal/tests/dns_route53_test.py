"""Tests for certbot_dns_route53._internal.dns_route53.Authenticator"""

import sys
import unittest
from unittest import mock

from botocore.exceptions import ClientError
from botocore.exceptions import NoCredentialsError
import josepy as jose
import pytest

from acme import challenges
from certbot import achallenges
from certbot import errors
from certbot.compat import os
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import acme_util
from certbot.tests import util as test_util

DOMAIN = 'example.com'
KEY = jose.jwk.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))


class AuthenticatorTest(unittest.TestCase):
    # pylint: disable=protected-access

    achall = achallenges.KeyAuthorizationAnnotatedChallenge(
        challb=acme_util.DNS01, domain=DOMAIN, account_key=KEY)

    def setUp(self):
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        super().setUp()

        self.config = mock.MagicMock()

        # Set up dummy credentials for testing
        os.environ["AWS_ACCESS_KEY_ID"] = "dummy_access_key"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "dummy_secret_access_key"

        self.auth = Authenticator(self.config, "route53")

    def tearDown(self):
        # Remove the dummy credentials from env vars
        del os.environ["AWS_ACCESS_KEY_ID"]
        del os.environ["AWS_SECRET_ACCESS_KEY"]

    def test_more_info(self) -> None:
        self.assertTrue(isinstance(self.auth.more_info(), str))

    def test_get_chall_pref(self) -> None:
        self.assertEqual(self.auth.get_chall_pref("example.org"), [challenges.DNS01])

    def test_perform(self):
        self.auth._change_txt_record = mock.MagicMock() # type: ignore[method-assign, unused-ignore]
        self.auth._wait_for_change = mock.MagicMock() # type: ignore [method-assign, unused-ignore]

        self.auth.perform([self.achall])

        self.auth._change_txt_record.assert_called_once_with("UPSERT",
                                                             '_acme-challenge.' + DOMAIN,
                                                             mock.ANY)
        assert self.auth._wait_for_change.call_count == 1

    def test_perform_no_credentials_error(self):
        self.auth._change_txt_record = mock.MagicMock( # type: ignore [method-assign, unused-ignore]
            side_effect=NoCredentialsError)

        with pytest.raises(errors.PluginError):
            self.auth.perform([self.achall])

    def test_perform_client_error(self):
        self.auth._change_txt_record = mock.MagicMock( # type: ignore [method-assign, unused-ignore]
            side_effect=ClientError({"Error": {"Code": "foo"}}, "bar"))

        with pytest.raises(errors.PluginError):
            self.auth.perform([self.achall])

    def test_cleanup(self):
        self.auth._attempt_cleanup = True

        self.auth._change_txt_record = mock.MagicMock() # type: ignore[method-assign, unused-ignore]

        self.auth.cleanup([self.achall])

        self.auth._change_txt_record.assert_called_once_with("DELETE",
                                                             '_acme-challenge.'+DOMAIN,
                                                             mock.ANY)

    def test_cleanup_no_credentials_error(self):
        self.auth._attempt_cleanup = True

        self.auth._change_txt_record = mock.MagicMock( # type: ignore [method-assign, unused-ignore]
        side_effect=NoCredentialsError)

        self.auth.cleanup([self.achall])

    def test_cleanup_client_error(self):
        self.auth._attempt_cleanup = True

        self.auth._change_txt_record = mock.MagicMock( # type: ignore [method-assign, unused-ignore]
            side_effect=ClientError({"Error": {"Code": "foo"}}, "bar"))

        self.auth.cleanup([self.achall])


class ClientTest(unittest.TestCase):
    # pylint: disable=protected-access

    PRIVATE_ZONE = {
                        "Id": "BAD-PRIVATE",
                        "Name": "example.com",
                        "Config": {
                            "PrivateZone": True
                        }
                    }

    EXAMPLE_NET_ZONE = {
                            "Id": "BAD-WRONG-TLD",
                            "Name": "example.net",
                            "Config": {
                                "PrivateZone": False
                            }
                        }

    EXAMPLE_COM_ZONE = {
                            "Id": "EXAMPLE",
                            "Name": "example.com",
                            "Config": {
                                "PrivateZone": False
                            }
                        }

    FOO_EXAMPLE_COM_ZONE = {
                                "Id": "FOO",
                                "Name": "foo.example.com",
                                "Config": {
                                    "PrivateZone": False
                                }
                            }

    def setUp(self):
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        self.config = mock.MagicMock()

        # Set up dummy credentials for testing
        os.environ["AWS_ACCESS_KEY_ID"] = "dummy_access_key"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "dummy_secret_access_key"

        self.client = Authenticator(self.config, "route53")

    def tearDown(self):
        # Remove the dummy credentials from env vars
        del os.environ["AWS_ACCESS_KEY_ID"]
        del os.environ["AWS_SECRET_ACCESS_KEY"]

    def test_find_zone_id_for_domain(self):
        self.client.r53.get_paginator = mock.MagicMock()
        self.client.r53.get_paginator().paginate.return_value = [
            {
                "HostedZones": [
                    self.EXAMPLE_NET_ZONE,
                    self.EXAMPLE_COM_ZONE,
                ]
            }
        ]

        result = self.client._find_zone_id_for_domain("foo.example.com")
        assert result == "EXAMPLE"

    def test_find_zone_id_for_domain_pagination(self):
        self.client.r53.get_paginator = mock.MagicMock()
        self.client.r53.get_paginator().paginate.return_value = [
            {
                "HostedZones": [
                    self.PRIVATE_ZONE,
                    self.EXAMPLE_COM_ZONE,
                ]
            },
            {
                "HostedZones": [
                    self.PRIVATE_ZONE,
                    self.FOO_EXAMPLE_COM_ZONE,
                ]
            }
        ]

        result = self.client._find_zone_id_for_domain("foo.example.com")
        assert result == "FOO"

    def test_find_zone_id_for_domain_no_results(self):
        self.client.r53.get_paginator = mock.MagicMock()
        self.client.r53.get_paginator().paginate.return_value = []

        with pytest.raises(errors.PluginError):
            self.client._find_zone_id_for_domain("foo.example.com")

    def test_find_zone_id_for_domain_no_correct_results(self):
        self.client.r53.get_paginator = mock.MagicMock()
        self.client.r53.get_paginator().paginate.return_value = [
            {
                "HostedZones": [
                    self.PRIVATE_ZONE,
                    self.EXAMPLE_NET_ZONE,
                ]
            },
        ]

        with pytest.raises(errors.PluginError):
            self.client._find_zone_id_for_domain("foo.example.com")

    def test_change_txt_record(self):
        self.client._find_zone_id_for_domain = mock.MagicMock() # type: ignore [method-assign, unused-ignore]
        self.client.r53.change_resource_record_sets = mock.MagicMock(
            return_value={"ChangeInfo": {"Id": 1}})

        self.client._change_txt_record("FOO", DOMAIN, "foo")

        call_count = self.client.r53.change_resource_record_sets.call_count
        assert call_count == 1

    def test_change_txt_record_delete(self):
        self.client._find_zone_id_for_domain = mock.MagicMock() # type: ignore[ method-assign, unused-ignore]
        self.client.r53.change_resource_record_sets = mock.MagicMock(
            return_value={"ChangeInfo": {"Id": 1}})

        validation = "some-value"
        validation_record = {"Value": '"{0}"'.format(validation)}
        self.client._resource_records[DOMAIN] = [validation_record]

        self.client._change_txt_record("DELETE", DOMAIN, validation)

        call_count = self.client.r53.change_resource_record_sets.call_count
        assert call_count == 1
        call_args = self.client.r53.change_resource_record_sets.call_args_list[0][1]
        call_args_batch = call_args["ChangeBatch"]["Changes"][0]
        assert call_args_batch["Action"] == "DELETE"
        assert call_args_batch["ResourceRecordSet"]["ResourceRecords"] == \
            [validation_record]

    def test_change_txt_record_multirecord(self):
        self.client._find_zone_id_for_domain = mock.MagicMock() # type: ignore [method-assign, unused-ignore]
        self.client._resource_records[DOMAIN] = [
            {"Value": "\"pre-existing-value\""},
            {"Value": "\"pre-existing-value-two\""},
        ]
        self.client.r53.change_resource_record_sets = mock.MagicMock(
            return_value={"ChangeInfo": {"Id": 1}})

        self.client._change_txt_record("DELETE", DOMAIN, "pre-existing-value")

        call_count = self.client.r53.change_resource_record_sets.call_count
        call_args = self.client.r53.change_resource_record_sets.call_args_list[0][1]
        call_args_batch = call_args["ChangeBatch"]["Changes"][0]
        assert call_args_batch["Action"] == "UPSERT"
        assert call_args_batch["ResourceRecordSet"]["ResourceRecords"] == \
            [{"Value": "\"pre-existing-value-two\""}]

        assert call_count == 1

    def test_wait_for_change(self):
        self.client.r53.get_change = mock.MagicMock(
            side_effect=[{"ChangeInfo": {"Status": "PENDING"}},
                         {"ChangeInfo": {"Status": "INSYNC"}}])

        self.client._wait_for_change("1")

        assert self.client.r53.get_change.called

class ClientTest_with_File(test_util.TempDirTestCase):
    # pylint: disable=protected-access

    PRIVATE_ZONE = {
                        "Id": "BAD-PRIVATE",
                        "Name": "example.com",
                        "Config": {
                            "PrivateZone": True
                        }
                    }

    EXAMPLE_NET_ZONE = {
                            "Id": "BAD-WRONG-TLD",
                            "Name": "example.net",
                            "Config": {
                                "PrivateZone": False
                            }
                        }

    EXAMPLE_COM_ZONE = {
                            "Id": "EXAMPLE",
                            "Name": "example.com",
                            "Config": {
                                "PrivateZone": False
                            }
                        }

    FOO_EXAMPLE_COM_ZONE = {
                                "Id": "FOO",
                                "Name": "foo.example.com",
                                "Config": {
                                    "PrivateZone": False
                                }
                            }

    def setUp(self):
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        super().setUp()

        CREDS_FILE = '''[default]
        aws_access_key_id=dummy_access_key
        aws_secret_access_key=dummy_secret_access_key
        '''

        path = os.path.join(self.tempdir, '.ini')
        with open(path, "w") as creds_file:
            creds_file.write(CREDS_FILE)

        self.config = mock.MagicMock(route53_credentials=path)

        self.client = Authenticator(self.config, "route53")

    def test_find_zone_id_for_domain(self):
        self.client.r53.get_paginator = mock.MagicMock()
        self.client.r53.get_paginator().paginate.return_value = [
            {
                "HostedZones": [
                    self.EXAMPLE_NET_ZONE,
                    self.EXAMPLE_COM_ZONE,
                ]
            }
        ]

        result = self.client._find_zone_id_for_domain("foo.example.com")
        assert result == "EXAMPLE"

    def test_find_zone_id_for_domain_pagination(self):
        self.client.r53.get_paginator = mock.MagicMock()
        self.client.r53.get_paginator().paginate.return_value = [
            {
                "HostedZones": [
                    self.PRIVATE_ZONE,
                    self.EXAMPLE_COM_ZONE,
                ]
            },
            {
                "HostedZones": [
                    self.PRIVATE_ZONE,
                    self.FOO_EXAMPLE_COM_ZONE,
                ]
            }
        ]

        result = self.client._find_zone_id_for_domain("foo.example.com")
        assert result == "FOO"

    def test_find_zone_id_for_domain_no_results(self):
        self.client.r53.get_paginator = mock.MagicMock()
        self.client.r53.get_paginator().paginate.return_value = []

        with pytest.raises(errors.PluginError):
            self.client._find_zone_id_for_domain("foo.example.com")

    def test_find_zone_id_for_domain_no_correct_results(self):
        self.client.r53.get_paginator = mock.MagicMock()
        self.client.r53.get_paginator().paginate.return_value = [
            {
                "HostedZones": [
                    self.PRIVATE_ZONE,
                    self.EXAMPLE_NET_ZONE,
                ]
            },
        ]

        with pytest.raises(errors.PluginError):
            self.client._find_zone_id_for_domain("foo.example.com")

    def test_change_txt_record(self):
        self.client._find_zone_id_for_domain = mock.MagicMock()
        self.client.r53.change_resource_record_sets = mock.MagicMock(
            return_value={"ChangeInfo": {"Id": 1}})

        self.client._change_txt_record("FOO", DOMAIN, "foo")

        call_count = self.client.r53.change_resource_record_sets.call_count
        assert call_count == 1

    def test_change_txt_record_delete(self):
        self.client._find_zone_id_for_domain = mock.MagicMock()
        self.client.r53.change_resource_record_sets = mock.MagicMock(
            return_value={"ChangeInfo": {"Id": 1}})

        validation = "some-value"
        validation_record = {"Value": '"{0}"'.format(validation)}
        self.client._resource_records[DOMAIN] = [validation_record]

        self.client._change_txt_record("DELETE", DOMAIN, validation)

        call_count = self.client.r53.change_resource_record_sets.call_count
        assert call_count == 1
        call_args = self.client.r53.change_resource_record_sets.call_args_list[0][1]
        call_args_batch = call_args["ChangeBatch"]["Changes"][0]
        assert call_args_batch["Action"] == "DELETE"
        assert call_args_batch["ResourceRecordSet"]["ResourceRecords"] == \
            [validation_record]

    def test_change_txt_record_multirecord(self):
        self.client._find_zone_id_for_domain = mock.MagicMock()
        self.client._get_validation_rrset = mock.MagicMock()
        self.client._resource_records[DOMAIN] = [
            {"Value": "\"pre-existing-value\""},
            {"Value": "\"pre-existing-value-two\""},
        ]
        self.client.r53.change_resource_record_sets = mock.MagicMock(
            return_value={"ChangeInfo": {"Id": 1}})

        self.client._change_txt_record("DELETE", DOMAIN, "pre-existing-value")

        call_count = self.client.r53.change_resource_record_sets.call_count
        call_args = self.client.r53.change_resource_record_sets.call_args_list[0][1]
        call_args_batch = call_args["ChangeBatch"]["Changes"][0]
        assert call_args_batch["Action"] == "UPSERT"
        assert call_args_batch["ResourceRecordSet"]["ResourceRecords"] == \
            [{"Value": "\"pre-existing-value-two\""}]

        assert call_count == 1

    def test_wait_for_change(self):
        self.client.r53.get_change = mock.MagicMock(
            side_effect=[{"ChangeInfo": {"Status": "PENDING"}},
                         {"ChangeInfo": {"Status": "INSYNC"}}])

        self.client._wait_for_change(1)

        assert self.client.r53.get_change.called

if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
