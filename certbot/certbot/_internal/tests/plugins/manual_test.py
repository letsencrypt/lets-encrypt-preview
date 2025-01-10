"""Tests for certbot._internal.plugins.manual"""
import sys
import textwrap
from unittest import mock

import pytest

from acme import challenges
from certbot import errors
from certbot.compat import filesystem
from certbot.compat import os
from certbot.tests import acme_util
from certbot.tests import util as test_util


class AuthenticatorTest(test_util.TempDirTestCase):
    """Tests for certbot._internal.plugins.manual.Authenticator."""

    def setUp(self):
        super().setUp()
        get_display_patch = test_util.patch_display_util()
        self.mock_get_display = get_display_patch.start()
        self.addCleanup(get_display_patch.stop)

        self.http_achall = acme_util.HTTP01_A
        self.dns_achall = acme_util.DNS01_A
        self.dns_achall_2 = acme_util.DNS01_A_2
        self.achalls = [self.http_achall, self.dns_achall, self.dns_achall_2]
        for d in ["config_dir", "work_dir", "in_progress"]:
            filesystem.mkdir(os.path.join(self.tempdir, d))
            # "backup_dir" and "temp_checkpoint_dir" get created in
            # certbot.util.make_or_verify_dir() during the Reverter
            # initialization.
        self.config = mock.MagicMock(
            http01_port=0, manual_auth_hook=None, manual_cleanup_hook=None,
            noninteractive_mode=False, validate_hooks=False,
            config_dir=os.path.join(self.tempdir, "config_dir"),
            work_dir=os.path.join(self.tempdir, "work_dir"),
            backup_dir=os.path.join(self.tempdir, "backup_dir"),
            temp_checkpoint_dir=os.path.join(
                                        self.tempdir, "temp_checkpoint_dir"),
            in_progress_dir=os.path.join(self.tempdir, "in_progess"))

        from certbot._internal.plugins.manual import Authenticator
        self.auth = Authenticator(self.config, name='manual')

    def test_prepare_no_hook_noninteractive(self):
        self.config.noninteractive_mode = True
        with pytest.raises(errors.PluginError):
            self.auth.prepare()

    def test_prepare_bad_hook(self):
        self.config.manual_auth_hook = os.path.abspath(os.sep)  # is / on UNIX
        self.config.validate_hooks = True
        with pytest.raises(errors.HookCommandNotFound):
            self.auth.prepare()

    def test_more_info(self):
        assert isinstance(self.auth.more_info(), str)

    def test_get_chall_pref(self):
        assert self.auth.get_chall_pref('example.org') == \
                         [challenges.HTTP01, challenges.DNS01]

    def test_script_perform(self):
        self.config.manual_auth_hook = (
            '{0} -c "'
            'from certbot.compat import os;'
            'print(os.environ.get(\'CERTBOT_DOMAIN\'));'
            'print(os.environ.get(\'CERTBOT_TOKEN\', \'notoken\'));'
            'print(os.environ.get(\'CERTBOT_VALIDATION\', \'novalidation\'));'
            'print(os.environ.get(\'CERTBOT_ALL_DOMAINS\'));'
            'print(os.environ.get(\'CERTBOT_REMAINING_CHALLENGES\'));"'
            .format(sys.executable))
        dns_expected = '{0}\n{1}\n{2}\n{3}\n{4}'.format(
            self.dns_achall.domain, 'notoken',
            self.dns_achall.validation(self.dns_achall.account_key),
            ','.join(achall.domain for achall in self.achalls),
            len(self.achalls) - self.achalls.index(self.dns_achall) - 1)
        http_expected = '{0}\n{1}\n{2}\n{3}\n{4}'.format(
            self.http_achall.domain, self.http_achall.chall.encode('token'),
            self.http_achall.validation(self.http_achall.account_key),
            ','.join(achall.domain for achall in self.achalls),
            len(self.achalls) - self.achalls.index(self.http_achall) - 1)

        assert self.auth.perform(self.achalls) == \
            [achall.response(achall.account_key) for achall in self.achalls]
        assert self.auth.env[self.dns_achall]['CERTBOT_AUTH_OUTPUT'] == \
            dns_expected
        assert self.auth.env[self.http_achall]['CERTBOT_AUTH_OUTPUT'] == \
            http_expected

        # Successful hook output should be sent to notify
        assert self.mock_get_display().notification.call_count == len(self.achalls)
        for i, (args, _) in enumerate(self.mock_get_display().notification.call_args_list):
            needle = textwrap.indent(self.auth.env[self.achalls[i]]['CERTBOT_AUTH_OUTPUT'], ' ')
            assert needle in args[0]

    def test_manual_perform(self):
        assert self.auth.perform(self.achalls) == \
            [achall.response(achall.account_key) for achall in self.achalls]

        assert self.mock_get_display().notification.call_count == len(self.achalls)
        for i, (args, kwargs) in enumerate(self.mock_get_display().notification.call_args_list):
            achall = self.achalls[i]
            assert achall.validation(achall.account_key) in args[0]
            assert kwargs['wrap'] is False

    def test_cleanup(self):
        self.config.manual_auth_hook = ('{0} -c "import sys; sys.stdout.write(\'foo\')"'
                                        .format(sys.executable))
        self.config.manual_cleanup_hook = '# cleanup'
        self.auth.perform(self.achalls)

        for achall in self.achalls:
            self.auth.cleanup([achall])
            assert os.environ['CERTBOT_AUTH_OUTPUT'] == 'foo'
            assert os.environ['CERTBOT_DOMAIN'] == achall.domain
            if isinstance(achall.chall, (challenges.HTTP01, challenges.DNS01)):
                assert os.environ['CERTBOT_VALIDATION'] == \
                    achall.validation(achall.account_key)
            if isinstance(achall.chall, challenges.HTTP01):
                assert os.environ['CERTBOT_TOKEN'] == \
                    achall.chall.encode('token')
            else:
                assert 'CERTBOT_TOKEN' not in os.environ

    def test_auth_hint_hook(self):
        self.config.manual_auth_hook = '/bin/true'
        assert self.auth.auth_hint([acme_util.DNS01_A, acme_util.HTTP01_A]) == \
            'The Certificate Authority failed to verify the DNS TXT records and challenge ' \
            'files created by the --manual-auth-hook. Ensure that this hook is functioning ' \
            'correctly and that it waits a sufficient duration of time for DNS propagation. ' \
            'Refer to "certbot --help manual" and the Certbot User Guide.'
        assert self.auth.auth_hint([acme_util.HTTP01_A]) == \
            'The Certificate Authority failed to verify the challenge files created by the ' \
            '--manual-auth-hook. Ensure that this hook is functioning correctly. Refer to ' \
            '"certbot --help manual" and the Certbot User Guide.'

    def test_auth_hint_no_hook(self):
        assert self.auth.auth_hint([acme_util.DNS01_A, acme_util.HTTP01_A]) == \
            'The Certificate Authority failed to verify the manually created DNS TXT records ' \
            'and challenge files. Ensure that you created these in the correct location, or ' \
            'try waiting longer for DNS propagation on the next attempt.'
        assert self.auth.auth_hint([acme_util.HTTP01_A, acme_util.HTTP01_A, acme_util.HTTP01_A]) == \
            'The Certificate Authority failed to verify the manually created challenge files. ' \
            'Ensure that you created these in the correct location.'


if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
