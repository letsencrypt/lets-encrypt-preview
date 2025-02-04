"""Tests for certbot._internal.renewal"""
import copy
import sys
import unittest
from unittest import mock

import pytest

from acme import challenges
from certbot import configuration
from certbot import errors
from certbot._internal import storage
import certbot.tests.util as test_util


class RenewalTest(test_util.ConfigTestCase):
    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_ancient_webroot_renewal_conf(self, mock_set_by_user):
        mock_set_by_user.return_value = False
        rc_path = test_util.make_lineage(
            self.config.config_dir, 'sample-renewal-ancient.conf')
        self.config.account = None
        self.config.email = None
        self.config.webroot_path = None
        config = configuration.NamespaceConfig(self.config)
        lineage = storage.RenewableCert(rc_path, config)
        renewalparams = lineage.configuration['renewalparams']
        # pylint: disable=protected-access
        from certbot._internal import renewal
        renewal._restore_webroot_config(config, renewalparams)
        assert config.webroot_path == ['/var/www/']

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_webroot_params_conservation(self, mock_set_by_user):
        # For more details about why this test is important, see:
        # certbot._internal.plugins.webroot_test::
        #   WebrootActionTest::test_webroot_map_partial_without_perform
        from certbot._internal import renewal
        mock_set_by_user.return_value = False

        renewalparams = {
            'webroot_map': {'test.example.com': '/var/www/test'},
            'webroot_path': ['/var/www/test', '/var/www/other'],
        }
        renewal._restore_webroot_config(self.config, renewalparams)  # pylint: disable=protected-access
        assert self.config.webroot_map == {'test.example.com': '/var/www/test'}
        assert self.config.webroot_path == ['/var/www/test', '/var/www/other']

        renewalparams = {
            'webroot_map': {},
            'webroot_path': '/var/www/test',
        }
        renewal._restore_webroot_config(self.config, renewalparams)  # pylint: disable=protected-access
        assert self.config.webroot_map == {}
        assert self.config.webroot_path == ['/var/www/test']

    @mock.patch('certbot._internal.renewal._avoid_reuse_key_conflicts')
    def test_reuse_key_renewal_params(self, unused_mock_avoid_reuse_conflicts):
        self.config.elliptic_curve = 'INVALID_VALUE'
        self.config.reuse_key = True
        self.config.dry_run = True
        config = configuration.NamespaceConfig(self.config)

        rc_path = test_util.make_lineage(
            self.config.config_dir, 'sample-renewal.conf')
        lineage = storage.RenewableCert(rc_path, config)

        le_client = mock.MagicMock()
        le_client.obtain_certificate.return_value = (None, None, None, None)

        from certbot._internal import renewal

        with mock.patch('certbot._internal.renewal.hooks.renew_hook'):
            renewal.renew_cert(self.config, None, le_client, lineage)

        assert self.config.elliptic_curve == 'secp256r1'

    @mock.patch('certbot._internal.renewal._avoid_reuse_key_conflicts')
    def test_reuse_ec_key_renewal_params(self, unused_mock_avoid_reuse_conflicts):
        self.config.elliptic_curve = 'INVALID_CURVE'
        self.config.reuse_key = True
        self.config.dry_run = True
        self.config.key_type = 'ecdsa'
        config = configuration.NamespaceConfig(self.config)

        rc_path = test_util.make_lineage(
            self.config.config_dir,
            'sample-renewal-ec.conf',
            ec=True,
        )
        lineage = storage.RenewableCert(rc_path, config)

        le_client = mock.MagicMock()
        le_client.obtain_certificate.return_value = (None, None, None, None)

        from certbot._internal import renewal

        with mock.patch('certbot._internal.renewal.hooks.renew_hook'):
            renewal.renew_cert(self.config, None, le_client, lineage)

        assert self.config.elliptic_curve == 'secp256r1'

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_new_key(self, mock_set_by_user):
        mock_set_by_user.return_value = False
        # When renewing with both reuse_key and new_key, the key should be regenerated,
        # the key type, key parameters and reuse_key should be kept.
        self.config.reuse_key = True
        self.config.new_key = True
        self.config.dry_run = True
        config = configuration.NamespaceConfig(self.config)

        rc_path = test_util.make_lineage(
            self.config.config_dir, 'sample-renewal.conf')
        lineage = storage.RenewableCert(rc_path, config)

        le_client = mock.MagicMock()
        le_client.obtain_certificate.return_value = (None, None, None, None)

        from certbot._internal import renewal

        with mock.patch('certbot._internal.renewal.hooks.renew_hook'):
            renewal.renew_cert(self.config, None, le_client, lineage)

        assert self.config.elliptic_curve == 'secp256r1'
        assert self.config.key_type == 'ecdsa'
        assert self.config.reuse_key
        # None is passed as the existing key, i.e. the key is not actually being reused.
        le_client.obtain_certificate.assert_called_with(mock.ANY, None, ari_hint=mock.ANY)

    @mock.patch('certbot._internal.renewal.hooks.renew_hook')
    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_reuse_key_conflicts(self, mock_set_by_user, unused_mock_renew_hook):
        mock_set_by_user.return_value = False

        # When renewing with reuse_key and a conflicting key parameter (size, curve)
        # an error should be raised ...
        self.config.reuse_key = True
        self.config.key_type = "rsa"
        self.config.rsa_key_size = 4096
        self.config.dry_run = True

        config = configuration.NamespaceConfig(self.config)

        rc_path = test_util.make_lineage(
            self.config.config_dir, 'sample-renewal.conf')
        lineage = storage.RenewableCert(rc_path, config)
        lineage.configuration["renewalparams"]["reuse_key"] = True

        le_client = mock.MagicMock()
        le_client.obtain_certificate.return_value = (None, None, None, None)

        from certbot._internal import renewal

        with pytest.raises(errors.Error, match="Unable to change the --key-type"):
            renewal.renew_cert(self.config, None, le_client, lineage)

        # ... unless --no-reuse-key is set
        mock_set_by_user.side_effect = lambda var: var == "reuse_key"
        self.config.reuse_key = False
        renewal.renew_cert(self.config, None, le_client, lineage)

    @test_util.patch_display_util()
    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_remove_deprecated_config_elements(self, mock_set_by_user, unused_mock_get_utility):
        mock_set_by_user.return_value = False
        config = configuration.NamespaceConfig(self.config)
        config.certname = "sample-renewal-deprecated-option"

        rc_path = test_util.make_lineage(
            self.config.config_dir, 'sample-renewal-deprecated-option.conf')

        from certbot._internal import renewal
        lineage_config = copy.deepcopy(self.config)
        renewal_candidate = renewal.reconstitute(lineage_config, rc_path)
        # This means that manual_public_ip_logging_ok was not modified in the config based on its
        # value in the renewal conf file
        assert isinstance(lineage_config.manual_public_ip_logging_ok, mock.MagicMock)

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_absent_key_type_restored(self, mock_set_by_user):
        mock_set_by_user.return_value = False

        rc_path = test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf', ec=False)

        from certbot._internal import renewal
        lineage_config = copy.deepcopy(self.config)
        renewal.reconstitute(lineage_config, rc_path)
        assert lineage_config.key_type == 'rsa'


class RestoreRequiredConfigElementsTest(test_util.ConfigTestCase):
    """Tests for certbot._internal.renewal.restore_required_config_elements."""
    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot._internal.renewal import restore_required_config_elements
        return restore_required_config_elements(*args, **kwargs)

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_allow_subset_of_names_success(self, mock_set_by_user):
        mock_set_by_user.return_value = False
        self._call(self.config, {'allow_subset_of_names': 'True'})
        assert self.config.allow_subset_of_names is True

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_allow_subset_of_names_failure(self, mock_set_by_user):
        mock_set_by_user.return_value = False
        renewalparams = {'allow_subset_of_names': 'maybe'}
        with pytest.raises(errors.Error):
            self._call(self.config, renewalparams)

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_pref_challs_list(self, mock_set_by_user):
        mock_set_by_user.return_value = False
        renewalparams = {'pref_challs': 'http-01, dns'.split(',')}
        self._call(self.config, renewalparams)
        expected = [challenges.HTTP01.typ, challenges.DNS01.typ]
        assert self.config.pref_challs == expected

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_pref_challs_str(self, mock_set_by_user):
        mock_set_by_user.return_value = False
        renewalparams = {'pref_challs': 'dns'}
        self._call(self.config, renewalparams)
        expected = [challenges.DNS01.typ]
        assert self.config.pref_challs == expected

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_pref_challs_failure(self, mock_set_by_user):
        mock_set_by_user.return_value = False
        renewalparams = {'pref_challs': 'finding-a-shrubbery'}
        with pytest.raises(errors.Error):
            self._call(self.config, renewalparams)

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_must_staple_success(self, mock_set_by_user):
        mock_set_by_user.return_value = False
        self._call(self.config, {'must_staple': 'True'})
        assert self.config.must_staple is True

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_must_staple_failure(self, mock_set_by_user):
        mock_set_by_user.return_value = False
        renewalparams = {'must_staple': 'maybe'}
        with pytest.raises(errors.Error):
            self._call(self.config, renewalparams)

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_ancient_server_renewal_conf(self, mock_set_by_user):
        from certbot._internal import constants
        self.config.server = None
        mock_set_by_user.return_value = False
        self._call(self.config, {'server': constants.V1_URI})
        assert self.config.server == constants.CLI_DEFAULTS['server']

    def test_related_values(self):
        # certbot.configuration.NamespaceConfig.set_by_user considers some values as related to each
        # other and considers both set by the user if either is. This test ensures all renewal
        # parameters are restored regardless of their restoration order or relation between values.
        # See https://github.com/certbot/certbot/issues/9805 for more info.
        renewalparams = {
            'server': 'https://example.org',
            'account': 'somehash',
        }
        self._call(self.config, renewalparams)
        self.assertEqual(self.config.account, renewalparams['account'])


class DescribeResultsTest(unittest.TestCase):
    """Tests for certbot._internal.renewal._renew_describe_results."""
    def setUp(self):
        self.patchers = {
            'log_error': mock.patch('certbot._internal.renewal.logger.error'),
            'notify': mock.patch('certbot._internal.renewal.display_util.notify')}
        self.mock_notify = self.patchers['notify'].start()
        self.mock_error = self.patchers['log_error'].start()

    def tearDown(self):
        for patch in self.patchers.values():
            patch.stop()

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot._internal.renewal import _renew_describe_results
        _renew_describe_results(*args, **kwargs)

    def _assert_success_output(self, lines):
        self.mock_notify.assert_has_calls([mock.call(l) for l in lines])

    def test_no_renewal_attempts(self):
        self._call(mock.MagicMock(dry_run=True), [], [], [], [])
        self._assert_success_output(['No simulated renewals were attempted.'])

    def test_successful_renewal(self):
        self._call(mock.MagicMock(dry_run=False), ['good.pem'], None, None, None)
        self._assert_success_output([
            '\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -',
            'Congratulations, all renewals succeeded: ',
            '  good.pem (success)',
            '- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -',
        ])

    def test_failed_renewal(self):
        self._call(mock.MagicMock(dry_run=False), [], ['bad.pem'], [], [])
        self._assert_success_output([
            '\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -',
            '- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -',
        ])
        self.mock_error.assert_has_calls([
            mock.call('All %ss failed. The following certificates could not be renewed:', 'renewal'),
            mock.call('  bad.pem (failure)'),
        ])

    def test_all_renewal(self):
        self._call(mock.MagicMock(dry_run=True),
                   ['good.pem', 'good2.pem'], ['bad.pem', 'bad2.pem'],
                   ['foo.pem expires on 123'], ['errored.conf'])
        self._assert_success_output([
            '\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -',
            'The following certificates are not due for renewal yet:',
            '  foo.pem expires on 123 (skipped)',
            'The following simulated renewals succeeded:',
            '  good.pem (success)\n  good2.pem (success)\n',
            '\nAdditionally, the following renewal configurations were invalid: ',
            '  errored.conf (parsefail)',
            '- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -',
        ])
        self.mock_error.assert_has_calls([
            mock.call('The following %ss failed:', 'simulated renewal'),
            mock.call('  bad.pem (failure)\n  bad2.pem (failure)'),
        ])


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
