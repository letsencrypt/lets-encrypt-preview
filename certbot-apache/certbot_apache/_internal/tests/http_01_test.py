"""Test for certbot_apache._internal.http_01."""
import errno
import sys
from typing import List
from unittest import mock

import pytest

from acme import challenges
from certbot import achallenges
from certbot import errors
from certbot.compat import filesystem
from certbot.compat import os
from certbot.tests import acme_util
from certbot_apache._internal.parser import get_aug_path
from certbot_apache._internal.tests import util

NUM_ACHALLS = 3


class ApacheHttp01Test(util.ApacheTest):
    """Test for certbot_apache._internal.http_01.ApacheHttp01."""

    def setUp(self, *args, **kwargs):  # pylint: disable=arguments-differ
        super().setUp(*args, **kwargs)

        self.account_key = self.rsa512jwk
        self.achalls: List[achallenges.KeyAuthorizationAnnotatedChallenge] = []
        vh_truth = util.get_vh_truth(
            self.temp_dir, "debian_apache_2_4/multiple_vhosts")
        # Takes the vhosts for encryption-example.demo, certbot.demo
        # and vhost.in.rootconf
        self.vhosts = [vh_truth[0], vh_truth[3], vh_truth[10]]

        for i in range(NUM_ACHALLS):
            self.achalls.append(
                achallenges.KeyAuthorizationAnnotatedChallenge(
                    challb=acme_util.chall_to_challb(
                        challenges.HTTP01(token=((chr(ord('a') + i).encode() * 16))),
                        "pending"),
                    domain=self.vhosts[i].name, account_key=self.account_key))

        modules = ["ssl", "rewrite", "authz_core", "authz_host"]
        for mod in modules:
            self.config.parser.modules["mod_{0}.c".format(mod)] = None
            self.config.parser.modules[mod + "_module"] = None

        from certbot_apache._internal.http_01 import ApacheHttp01
        self.http = ApacheHttp01(self.config)

    def test_empty_perform(self):
        assert len(self.http.perform()) == 0

    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator.enable_mod")
    def test_enable_modules_apache_2_4(self, mock_enmod):
        del self.config.parser.modules["authz_core_module"]
        del self.config.parser.modules["mod_authz_host.c"]

        enmod_calls = self.common_enable_modules_test(mock_enmod)
        assert enmod_calls[0][0][0] == "authz_core"

    def common_enable_modules_test(self, mock_enmod):
        """Tests enabling mod_rewrite and other modules."""
        del self.config.parser.modules["rewrite_module"]
        del self.config.parser.modules["mod_rewrite.c"]

        self.http.prepare_http01_modules()

        assert mock_enmod.called is True
        calls = mock_enmod.call_args_list
        other_calls = []
        for call in calls:
            if call[0][0] != "rewrite":
                other_calls.append(call)

        # If these lists are equal, we never enabled mod_rewrite
        assert calls != other_calls
        return other_calls

    def test_same_vhost(self):
        vhost = next(v for v in self.config.vhosts if v.name == "certbot.demo")
        achalls = [
            achallenges.KeyAuthorizationAnnotatedChallenge(
                challb=acme_util.chall_to_challb(
                    challenges.HTTP01(token=((b'a' * 16))),
                    "pending"),
                domain=vhost.name, account_key=self.account_key),
            achallenges.KeyAuthorizationAnnotatedChallenge(
                challb=acme_util.chall_to_challb(
                    challenges.HTTP01(token=((b'b' * 16))),
                    "pending"),
                domain=next(iter(vhost.aliases)), account_key=self.account_key)
        ]
        self.common_perform_test(achalls, [vhost])

    def test_anonymous_vhost(self):
        vhosts = [v for v in self.config.vhosts if not v.ssl]
        achalls = [
            achallenges.KeyAuthorizationAnnotatedChallenge(
                challb=acme_util.chall_to_challb(
                    challenges.HTTP01(token=((b'a' * 16))),
                    "pending"),
                domain="something.nonexistent", account_key=self.account_key)]
        self.common_perform_test(achalls, vhosts)

    def test_configure_multiple_vhosts(self):
        vhosts = [v for v in self.config.vhosts if "duplicate.example.com" in v.get_names()]
        assert len(vhosts) == 2
        achalls = [
            achallenges.KeyAuthorizationAnnotatedChallenge(
                challb=acme_util.chall_to_challb(
                    challenges.HTTP01(token=((b'a' * 16))),
                    "pending"),
                domain="duplicate.example.com", account_key=self.account_key)]
        self.common_perform_test(achalls, vhosts)

    def test_configure_name_and_blank(self):
        domain = "certbot.demo"
        vhosts = [v for v in self.config.vhosts if v.name == domain or v.name is None]
        achalls = [
            achallenges.KeyAuthorizationAnnotatedChallenge(
                challb=acme_util.chall_to_challb(
                    challenges.HTTP01(token=((b'a' * 16))),
                    "pending"),
                domain=domain, account_key=self.account_key),
        ]
        self.common_perform_test(achalls, vhosts)

    def test_no_vhost(self):
        for achall in self.achalls:
            self.http.add_chall(achall)
        self.config.config.http01_port = 12345
        with pytest.raises(errors.PluginError):
            self.http.perform()

    def test_perform_1_achall_apache_2_4(self):
        self.combinations_perform_test(num_achalls=1, minor_version=4)

    def test_perform_2_achall_apache_2_4(self):
        self.combinations_perform_test(num_achalls=2, minor_version=4)

    def test_perform_3_achall_apache_2_4(self):
        self.combinations_perform_test(num_achalls=3, minor_version=4)

    def test_activate_disabled_vhost(self):
        vhosts = [v for v in self.config.vhosts if v.name == "certbot.demo"]
        achalls = [
            achallenges.KeyAuthorizationAnnotatedChallenge(
                challb=acme_util.chall_to_challb(
                    challenges.HTTP01(token=((b'a' * 16))),
                    "pending"),
                domain="certbot.demo", account_key=self.account_key)]
        vhosts[0].enabled = False
        self.common_perform_test(achalls, vhosts)
        matches = self.config.parser.find_dir(
            "Include", vhosts[0].filep,
            get_aug_path(self.config.parser.loc["default"]))
        assert len(matches) == 1

    def combinations_perform_test(self, num_achalls, minor_version):
        """Test perform with the given achall count and Apache version."""
        achalls = self.achalls[:num_achalls]
        vhosts = self.vhosts[:num_achalls]
        self.config.version = (2, minor_version)
        self.common_perform_test(achalls, vhosts)

    def common_perform_test(self, achalls, vhosts):
        """Tests perform with the given achalls."""
        challenge_dir = self.http.challenge_dir
        assert os.path.exists(challenge_dir) is False
        for achall in achalls:
            self.http.add_chall(achall)

        expected_response = [
            achall.response(self.account_key) for achall in achalls]
        assert self.http.perform() == expected_response

        assert os.path.isdir(self.http.challenge_dir) is True
        assert filesystem.has_min_permissions(self.http.challenge_dir, 0o755) is True
        self._test_challenge_conf()

        for achall in achalls:
            self._test_challenge_file(achall)

        for vhost in vhosts:
            matches = self.config.parser.find_dir("Include",
                                                self.http.challenge_conf_pre,
                                                vhost.path)
            assert len(matches) == 1
            matches = self.config.parser.find_dir("Include",
                                                self.http.challenge_conf_post,
                                                vhost.path)
            assert len(matches) == 1

        assert os.path.exists(challenge_dir) is True

    @mock.patch("certbot_apache._internal.http_01.filesystem.makedirs")
    def test_failed_makedirs(self, mock_makedirs):
        mock_makedirs.side_effect = OSError(errno.EACCES, "msg")
        self.http.add_chall(self.achalls[0])
        with pytest.raises(errors.PluginError):
            self.http.perform()

    def _test_challenge_conf(self):
        with open(self.http.challenge_conf_pre) as f:
            pre_conf_contents = f.read()

        with open(self.http.challenge_conf_post) as f:
            post_conf_contents = f.read()

        assert "RewriteEngine on" in pre_conf_contents
        assert "RewriteRule" in pre_conf_contents

        assert self.http.challenge_dir in post_conf_contents
        assert "Require all granted" in post_conf_contents

    def _test_challenge_file(self, achall):
        name = os.path.join(self.http.challenge_dir, achall.chall.encode("token"))
        validation = achall.validation(self.account_key)

        assert filesystem.has_min_permissions(name, 0o644) is True
        with open(name, 'rb') as f:
            assert f.read() == validation.encode()


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
