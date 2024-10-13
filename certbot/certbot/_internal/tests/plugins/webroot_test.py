"""Tests for certbot._internal.plugins.webroot."""

from __future__ import print_function

import argparse
import errno
import json
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import josepy as jose
import pytest

from acme import challenges
from certbot import achallenges
from certbot import errors
from certbot.compat import filesystem
from certbot.compat import os
from certbot.display import util as display_util
from certbot.tests import acme_util
from certbot.tests import util as test_util

KEY = jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))


class AuthenticatorTest(unittest.TestCase):
    """Tests for certbot._internal.plugins.webroot.Authenticator."""

    achall = achallenges.KeyAuthorizationAnnotatedChallenge(
        challb=acme_util.HTTP01_P, domain="thing.com", account_key=KEY)

    def setUp(self):
        from certbot._internal.plugins.webroot import Authenticator

        # On Linux directories created by tempfile.mkdtemp inherit their permissions from their
        # parent directory. So the actual permissions are inconsistent over various tests env.
        # To circumvent this, a dedicated sub-workspace is created under the workspace, using
        # filesystem.mkdir to get consistent permissions.
        self.workspace = tempfile.mkdtemp()
        self.path = os.path.join(self.workspace, 'webroot')
        filesystem.mkdir(self.path)
        self.partial_root_challenge_path = os.path.join(
            self.path, ".well-known")
        self.root_challenge_path = os.path.join(
            self.path, ".well-known", "acme-challenge")
        self.validation_path = os.path.join(
            self.root_challenge_path,
            "ZXZhR3hmQURzNnBTUmIyTEF2OUlaZjE3RHQzanV4R0orUEN0OTJ3citvQQ")
        self.config = mock.MagicMock(webroot_path=self.path,
                                     webroot_map={"thing.com": self.path},
                                     webroot_propagation_seconds=0)
        self.auth = Authenticator(self.config, "webroot")

    def tearDown(self):
        shutil.rmtree(self.path)

    def test_more_info(self):
        more_info = self.auth.more_info()
        assert isinstance(more_info, str)
        assert self.path in more_info

    def test_add_parser_arguments(self):
        add = mock.MagicMock()
        self.auth.add_parser_arguments(add)
        assert 3 == add.call_count

    def test_prepare(self):
        self.auth.prepare()  # shouldn't raise any exceptions

    @test_util.patch_display_util()
    def test_webroot_from_list(self, mock_get_utility):
        self.config.webroot_path = []
        self.config.webroot_map = {"otherthing.com": self.path}
        mock_display = mock_get_utility()
        mock_display.menu.return_value = (display_util.OK, 1,)

        self.auth.perform([self.achall])
        assert mock_display.menu.called
        for call in mock_display.menu.call_args_list:
            assert self.achall.domain in call[0][0]
            assert all(
                webroot in call[0][1]
                for webroot in self.config.webroot_map.values())
        assert self.config.webroot_map[self.achall.domain] == \
                         self.path

    @unittest.skipIf(filesystem.POSIX_MODE, reason='Test specific to Windows')
    @test_util.patch_display_util()
    def test_webconfig_file_generate_and_cleanup(self, mock_get_utility):
        mock_display = mock_get_utility()
        mock_display.menu.return_value = (display_util.OK, 1,)

        self.auth.perform([self.achall])
        assert os.path.exists(os.path.join(self.root_challenge_path, "web.config"))
        self.auth.cleanup([self.achall])
        assert not os.path.exists(os.path.join(self.root_challenge_path, "web.config"))

    @unittest.skipIf(filesystem.POSIX_MODE, reason='Test specific to Windows')
    @test_util.patch_display_util()
    def test_foreign_webconfig_file_handling(self, mock_get_utility):
        mock_display = mock_get_utility()
        mock_display.menu.return_value = (display_util.OK, 1,)

        challenge_path = os.path.join(self.path, ".well-known", "acme-challenge")
        filesystem.makedirs(challenge_path)

        webconfig_path = os.path.join(challenge_path, "web.config")
        with open(webconfig_path, "w") as file:
            file.write("something")
        self.auth.perform([self.achall])
        from certbot import crypto_util
        webconfig_hash = crypto_util.sha256sum(webconfig_path)
        from certbot._internal.plugins.webroot import _WEB_CONFIG_SHA256SUMS
        assert webconfig_hash not in _WEB_CONFIG_SHA256SUMS

    @unittest.skipIf(filesystem.POSIX_MODE, reason='Test specific to Windows')
    def test_foreign_webconfig_multiple_domains(self):
        # Covers bug https://github.com/certbot/certbot/issues/9091
        achall_2 = achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.chall_to_challb(challenges.HTTP01(token=b"bingo"), "pending"),
            domain="second-thing.com", account_key=KEY)
        self.config.webroot_map["second-thing.com"] = self.path

        challenge_path = os.path.join(self.path, ".well-known", "acme-challenge")
        filesystem.makedirs(challenge_path)

        webconfig_path = os.path.join(challenge_path, "web.config")
        with open(webconfig_path, "w") as file:
            file.write("something")
        self.auth.perform([self.achall, achall_2])

    @test_util.patch_display_util()
    def test_webroot_from_list_help_and_cancel(self, mock_get_utility):
        self.config.webroot_path = []
        self.config.webroot_map = {"otherthing.com": self.path}

        mock_display = mock_get_utility()
        mock_display.menu.side_effect = ((display_util.CANCEL, -1),)
        with pytest.raises(errors.PluginError):
            self.auth.perform([self.achall])
        assert mock_display.menu.called
        for call in mock_display.menu.call_args_list:
            assert self.achall.domain in call[0][0]
            assert all(
                webroot in call[0][1]
                for webroot in self.config.webroot_map.values())

    @test_util.patch_display_util()
    def test_new_webroot(self, mock_get_utility):
        self.config.webroot_path = []
        self.config.webroot_map = {"something.com": self.path}

        mock_display = mock_get_utility()
        mock_display.menu.return_value = (display_util.OK, 0,)
        with mock.patch('certbot.display.ops.validated_directory') as m:
            m.side_effect = ((display_util.CANCEL, -1),
                             (display_util.OK, self.path,))

            self.auth.perform([self.achall])

        assert self.config.webroot_map[self.achall.domain] == self.path

    @test_util.patch_display_util()
    def test_new_webroot_empty_map_cancel(self, mock_get_utility):
        self.config.webroot_path = []
        self.config.webroot_map = {}

        mock_display = mock_get_utility()
        mock_display.menu.return_value = (display_util.OK, 0,)
        with mock.patch('certbot.display.ops.validated_directory') as m:
            m.return_value = (display_util.CANCEL, -1)
            with pytest.raises(errors.PluginError):
                self.auth.perform([self.achall])

    def test_perform_missing_root(self):
        self.config.webroot_path = None
        self.config.webroot_map = {}
        with pytest.raises(errors.PluginError):
            self.auth.perform([])

    def test_perform_reraises_other_errors(self):
        self.auth.full_path = os.path.join(self.path, "null")
        permission_canary = os.path.join(self.path, "rnd")
        with open(permission_canary, "w") as f:
            f.write("thingimy")
        filesystem.chmod(self.path, 0o000)
        try:
            with open(permission_canary, "r"):
                pass
            print("Warning, running tests as root skips permissions tests...")
        except IOError:
            # ok, permissions work, test away...
            with pytest.raises(errors.PluginError):
                self.auth.perform([])
        filesystem.chmod(self.path, 0o700)

    @mock.patch("certbot._internal.plugins.webroot.filesystem.copy_ownership_and_apply_mode")
    def test_failed_chown(self, mock_ownership):
        mock_ownership.side_effect = OSError(errno.EACCES, "msg")
        self.auth.perform([self.achall])  # exception caught and logged

    @test_util.patch_display_util()
    def test_perform_new_webroot_not_in_map(self, mock_get_utility):
        new_webroot = tempfile.mkdtemp()
        self.config.webroot_path = []
        self.config.webroot_map = {"whatever.com": self.path}
        mock_display = mock_get_utility()
        mock_display.menu.side_effect = ((display_util.OK, 0),
                                         (display_util.OK, new_webroot))
        achall = achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.HTTP01_P, domain="something.com", account_key=KEY)
        with mock.patch('certbot.display.ops.validated_directory') as m:
            m.return_value = (display_util.OK, new_webroot,)
            self.auth.perform([achall])
        assert self.config.webroot_map[achall.domain] == new_webroot

    def test_perform_permissions(self):
        self.auth.prepare()

        # Remove exec bit from permission check, so that it
        # matches the file
        self.auth.perform([self.achall])
        assert filesystem.check_mode(self.validation_path, 0o644)

        # Check permissions of the directories
        for dirpath, dirnames, _ in os.walk(self.path):
            for directory in dirnames:
                full_path = os.path.join(dirpath, directory)
                assert filesystem.check_mode(full_path, 0o755)

        assert filesystem.has_same_ownership(self.validation_path, self.path)

    def test_perform_cleanup(self):
        self.auth.prepare()
        responses = self.auth.perform([self.achall])
        assert 1 == len(responses)
        assert os.path.exists(self.validation_path)
        with open(self.validation_path) as validation_f:
            validation = validation_f.read()
        assert challenges.KeyAuthorizationChallengeResponse(
                key_authorization=validation).verify(
                    self.achall.chall, KEY.public_key())

        self.auth.cleanup([self.achall])
        assert not os.path.exists(self.validation_path)
        assert not os.path.exists(self.root_challenge_path)
        assert not os.path.exists(self.partial_root_challenge_path)

    def test_perform_cleanup_existing_dirs(self):
        filesystem.mkdir(self.partial_root_challenge_path)
        self.auth.prepare()
        self.auth.perform([self.achall])
        self.auth.cleanup([self.achall])

        # Ensure we don't "clean up" directories that previously existed
        assert not os.path.exists(self.validation_path)
        assert not os.path.exists(self.root_challenge_path)

    def test_perform_cleanup_multiple_challenges(self):
        bingo_achall = achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.chall_to_challb(
                challenges.HTTP01(token=b"bingo"), "pending"),
            domain="thing.com", account_key=KEY)

        bingo_validation_path = "YmluZ28"
        filesystem.mkdir(self.partial_root_challenge_path)
        self.auth.prepare()
        self.auth.perform([bingo_achall, self.achall])

        self.auth.cleanup([self.achall])
        assert not os.path.exists(bingo_validation_path)
        assert os.path.exists(self.root_challenge_path)
        self.auth.cleanup([bingo_achall])
        assert not os.path.exists(self.validation_path)
        assert not os.path.exists(self.root_challenge_path)

    def test_cleanup_leftovers(self):
        self.auth.prepare()
        self.auth.perform([self.achall])

        leftover_path = os.path.join(self.root_challenge_path, 'leftover')
        filesystem.mkdir(leftover_path)

        self.auth.cleanup([self.achall])
        assert not os.path.exists(self.validation_path)
        assert os.path.exists(self.root_challenge_path)

        os.rmdir(leftover_path)

    @mock.patch('certbot.compat.os.rmdir')
    def test_cleanup_failure(self, mock_rmdir):
        self.auth.prepare()
        self.auth.perform([self.achall])

        os_error = OSError()
        os_error.errno = errno.EACCES
        mock_rmdir.side_effect = os_error

        self.auth.cleanup([self.achall])
        assert not os.path.exists(self.validation_path)
        assert os.path.exists(self.root_challenge_path)

    @mock.patch('certbot.display.util.notify')
    def test_propagation_seconds_default(self, mock_notify):
        self.auth.prepare()
        self.auth.perform([self.achall])

        mock_notify.assert_not_called()

    @mock.patch('certbot.display.util.notify')
    def test_propagation_seconds_non_default(self, mock_notify):
        self.config.webroot_propagation_seconds = 1
        self.auth.prepare()
        self.auth.perform([self.achall])

        mock_notify.assert_called_once_with(
            "Waiting 1 seconds for webroot challenge file(s) to propagate"
        )


class WebrootActionTest(unittest.TestCase):
    """Tests for webroot argparse actions."""

    achall = achallenges.KeyAuthorizationAnnotatedChallenge(
        challb=acme_util.HTTP01_P, domain="thing.com", account_key=KEY)

    def setUp(self):
        from certbot._internal.plugins.webroot import Authenticator
        self.path = tempfile.mkdtemp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("-d", "--domains",
                                 action="append", default=[])
        Authenticator.inject_parser_options(self.parser, "webroot")

    def test_webroot_map_action(self):
        args = self.parser.parse_args(
            ["--webroot-map", json.dumps({'thing.com': self.path})])
        assert args.webroot_map["thing.com"] == self.path

    def test_domain_before_webroot(self):
        args = self.parser.parse_args(
            "-d {0} -w {1}".format(self.achall.domain, self.path).split())
        config = self._get_config_after_perform(args)
        assert config.webroot_map[self.achall.domain] == self.path

    def test_domain_before_webroot_error(self):
        with pytest.raises(errors.PluginError):
            self.parser.parse_args("-d foo -w bar -w baz".split())
        with pytest.raises(errors.PluginError):
            self.parser.parse_args("-d foo -w bar -d baz -w qux".split())

    def test_multiwebroot(self):
        args = self.parser.parse_args("-w {0} -d {1} -w {2} -d bar".format(
            self.path, self.achall.domain, tempfile.mkdtemp()).split())
        assert args.webroot_map[self.achall.domain] == self.path
        config = self._get_config_after_perform(args)
        assert config.webroot_map[self.achall.domain] == self.path

    def test_webroot_map_partial_without_perform(self):
        # This test acknowledges the fact that webroot_map content will be partial if webroot
        # plugin perform method is not invoked (corner case when all auths are already valid).
        # To not be a problem, the webroot_path must always been conserved during renew.
        # This condition is challenged by:
        # certbot.tests.renewal_tests::RenewalTest::test_webroot_params_conservation
        # See https://github.com/certbot/certbot/pull/7095 for details.
        other_webroot_path = tempfile.mkdtemp()
        args = self.parser.parse_args("-w {0} -d {1} -w {2} -d bar".format(
            self.path, self.achall.domain, other_webroot_path).split())
        assert args.webroot_map == {self.achall.domain: self.path}
        assert args.webroot_path == [self.path, other_webroot_path]

    def test_propagation_seconds_default_action(self):
        args = self.parser.parse_args([])
        assert args.webroot_propagation_seconds == 0

    def test_propagation_seconds_non_default_action(self):
        args = self.parser.parse_args(["--webroot-propagation-seconds", "10"])
        assert args.webroot_propagation_seconds == 10

    def _get_config_after_perform(self, config):
        from certbot._internal.plugins.webroot import Authenticator
        auth = Authenticator(config, "webroot")
        auth.perform([self.achall])
        return auth.config


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
