"""Tests for certbot._internal.storage."""
# pylint disable=protected-access
import datetime
import shutil
import stat
import sys
import unittest
from unittest import mock

import configobj
import pytest
import pytz

import certbot
from certbot import configuration
from certbot import errors
from certbot._internal.storage import ALL_FOUR
from certbot.compat import filesystem
from certbot.compat import os
import certbot.tests.util as test_util

CERT = test_util.load_cert('cert_512.pem')


def unlink_all(rc_object):
    """Unlink all four items associated with this RenewableCert."""
    for kind in ALL_FOUR:
        os.unlink(getattr(rc_object, kind))


def fill_with_sample_data(rc_object):
    """Put dummy data into all four files of this RenewableCert."""
    for kind in ALL_FOUR:
        with open(getattr(rc_object, kind), "w") as f:
            f.write(kind)


class RelevantValuesTest(unittest.TestCase):
    """Tests for certbot._internal.storage.relevant_values."""

    def setUp(self):
        self.values = {"server": "example.org", "key_type": "rsa"}
        self.mock_config = mock.MagicMock()
        self.mock_config.set_by_user = mock.MagicMock()

    def _call(self, values):
        from certbot._internal.storage import relevant_values
        self.mock_config.to_dict.return_value = values
        return relevant_values(self.mock_config)

    @mock.patch("certbot._internal.plugins.disco.PluginsRegistry.find_all")
    def test_namespace(self, mock_find_all):
        mock_find_all.return_value = ["certbot-foo:bar"]
        self.mock_config.set_by_user.return_value = True

        self.values["certbot_foo:bar_baz"] = 42
        assert self._call(self.values.copy()) == self.values

    def test_option_set(self):
        self.mock_config.set_by_user.return_value = True

        self.values["allow_subset_of_names"] = True
        self.values["authenticator"] = "apache"
        self.values["rsa_key_size"] = 1337
        expected_relevant_values = self.values.copy()
        self.values["hello"] = "there"

        assert self._call(self.values) == expected_relevant_values

    def test_option_unset(self):
        self.mock_config.set_by_user.return_value = False

        expected_relevant_values = self.values.copy()
        self.values["rsa_key_size"] = 2048

        assert self._call(self.values) == expected_relevant_values

    def test_deprecated_item(self):
        deprected_option = 'manual_public_ip_logging_ok'
        self.mock_config.set_by_user = lambda v: False if v == deprected_option else True
        # deprecated items should never be relevant to store
        expected_relevant_values = self.values.copy()
        self.values[deprected_option] = None
        assert self._call(self.values) == expected_relevant_values
        self.values[deprected_option] = True
        assert self._call(self.values) == expected_relevant_values
        self.values[deprected_option] = False
        assert self._call(self.values) == expected_relevant_values

    def test_with_real_parser(self):
        from certbot._internal.storage import relevant_values
        from certbot._internal.plugins import disco
        from certbot._internal import cli
        from certbot._internal import constants

        PLUGINS = disco.PluginsRegistry.find_all()
        namespace = cli.prepare_and_parse_args(PLUGINS, [
            '--allow-subset-of-names',
            '--authenticator', 'apache',
        ])
        expected_relevant_values = {
            'server': constants.CLI_DEFAULTS['server'],
            'key_type': 'ecdsa',
            'allow_subset_of_names': True,
            'authenticator': 'apache',
        }

        assert relevant_values(namespace) == expected_relevant_values


class BaseRenewableCertTest(test_util.ConfigTestCase):
    """Base class for setting up Renewable Cert tests.

    .. note:: It may be required to write out self.config for
    your test.  Check :class:`.cli_test.DuplicateCertTest` for an example.

    """

    def setUp(self):
        from certbot._internal import storage

        super().setUp()

        # TODO: maybe provide NamespaceConfig.make_dirs?
        # TODO: main() should create those dirs, c.f. #902
        filesystem.makedirs(os.path.join(self.config.config_dir, "live", "example.org"))
        archive_path = os.path.join(self.config.config_dir, "archive", "example.org")
        filesystem.makedirs(archive_path)
        filesystem.makedirs(os.path.join(self.config.config_dir, "renewal"))

        config_file = configobj.ConfigObj()
        for kind in ALL_FOUR:
            kind_path = os.path.join(self.config.config_dir, "live", "example.org",
                                        kind + ".pem")
            config_file[kind] = kind_path
        with open(os.path.join(self.config.config_dir, "live", "example.org",
                                        "README"), 'a'):
            pass
        config_file["archive"] = archive_path
        config_file.filename = os.path.join(self.config.config_dir, "renewal",
                                       "example.org.conf")
        config_file.write()
        self.config_file = config_file

        # We also create a file that isn't a renewal config in the same
        # location to test that logic that reads in all-and-only renewal
        # configs will ignore it and NOT attempt to parse it.
        with open(os.path.join(self.config.config_dir, "renewal", "IGNORE.THIS"), "w") as junk:
            junk.write("This file should be ignored!")

        self.defaults = configobj.ConfigObj()

        with mock.patch("certbot._internal.storage.RenewableCert._check_symlinks") as check:
            check.return_value = True
            self.test_rc = storage.RenewableCert(config_file.filename, self.config)

    def _write_out_kind(self, kind, ver, value=None):
        link = getattr(self.test_rc, kind)
        if os.path.lexists(link):
            os.unlink(link)
        os.symlink(os.path.join(os.path.pardir, os.path.pardir, "archive",
                                "example.org", "{0}{1}.pem".format(kind, ver)),
                   link)
        with open(link, "wb") as f:
            f.write(kind.encode('ascii') if value is None else value)
        if kind == "privkey":
            filesystem.chmod(link, 0o600)

    def _write_out_ex_kinds(self):
        for kind in ALL_FOUR:
            self._write_out_kind(kind, 12)
            self._write_out_kind(kind, 11)


class RenewableCertTests(BaseRenewableCertTest):
    """Tests for certbot._internal.storage."""

    def test_initialization(self):
        assert self.test_rc.lineagename == "example.org"
        for kind in ALL_FOUR:
            assert getattr(self.test_rc, kind) == os.path.join(
                    self.config.config_dir, "live", "example.org", kind + ".pem")

    def test_renewal_bad_config(self):
        """Test that the RenewableCert constructor will complain if
        the renewal configuration file doesn't end in ".conf"

        """
        from certbot._internal import storage
        broken = os.path.join(self.config.config_dir, "broken.conf")
        with open(broken, "w") as f:
            f.write("[No closing bracket for you!")
        with pytest.raises(errors.CertStorageError):
            storage.RenewableCert(broken, self.config)
        os.unlink(broken)
        with pytest.raises(errors.CertStorageError):
            storage.RenewableCert("fun", self.config)

    def test_renewal_incomplete_config(self):
        """Test that the RenewableCert constructor will complain if
        the renewal configuration file is missing a required file element."""
        from certbot._internal import storage
        config = configobj.ConfigObj()
        config["cert"] = "imaginary_cert.pem"
        # Here the required privkey is missing.
        config["chain"] = "imaginary_chain.pem"
        config["fullchain"] = "imaginary_fullchain.pem"
        config.filename = os.path.join(self.config.config_dir, "imaginary_config.conf")
        config.write()
        with pytest.raises(errors.CertStorageError):
            storage.RenewableCert(config.filename, self.config)

    def test_no_renewal_version(self):
        from certbot._internal import storage

        self._write_out_ex_kinds()
        assert "version" not in self.config_file

        with mock.patch("certbot._internal.storage.logger") as mock_logger:
            storage.RenewableCert(self.config_file.filename, self.config)
        assert mock_logger.warning.called is False

    def test_renewal_newer_version(self):
        from certbot._internal import storage

        self._write_out_ex_kinds()
        self.config_file["version"] = "99.99.99"
        self.config_file.write()

        with mock.patch("certbot._internal.storage.logger") as mock_logger:
            storage.RenewableCert(self.config_file.filename, self.config)
        assert mock_logger.info.called
        assert "version" in mock_logger.info.call_args[0][0]

    def test_consistent(self):
        # pylint: disable=protected-access
        oldcert = self.test_rc.cert
        self.test_rc.cert = "relative/path"
        # Absolute path for item requirement
        assert not self.test_rc._consistent()
        self.test_rc.cert = oldcert
        # Items must exist requirement
        assert not self.test_rc._consistent()
        # Items must be symlinks requirements
        fill_with_sample_data(self.test_rc)
        assert not self.test_rc._consistent()
        unlink_all(self.test_rc)
        # Items must point to desired place if they are relative
        for kind in ALL_FOUR:
            os.symlink(os.path.join("..", kind + "17.pem"),
                       getattr(self.test_rc, kind))
        assert not self.test_rc._consistent()
        unlink_all(self.test_rc)
        # Items must point to desired place if they are absolute
        for kind in ALL_FOUR:
            os.symlink(os.path.join(self.config.config_dir, kind + "17.pem"),
                       getattr(self.test_rc, kind))
        assert not self.test_rc._consistent()
        unlink_all(self.test_rc)
        # Items must point to things that exist
        for kind in ALL_FOUR:
            os.symlink(os.path.join("..", "..", "archive", "example.org",
                                    kind + "17.pem"),
                       getattr(self.test_rc, kind))
        assert not self.test_rc._consistent()
        # This version should work
        fill_with_sample_data(self.test_rc)
        assert self.test_rc._consistent()
        # Items must point to things that follow the naming convention
        os.unlink(self.test_rc.fullchain)
        os.symlink(os.path.join("..", "..", "archive", "example.org",
                                "fullchain_17.pem"), self.test_rc.fullchain)
        with open(self.test_rc.fullchain, "w") as f:
            f.write("wrongly-named fullchain")
        assert not self.test_rc._consistent()

    def test_current_target(self):
        # Relative path logic
        self._write_out_kind("cert", 17)
        assert os.path.samefile(self.test_rc.current_target("cert"),
                                         os.path.join(self.config.config_dir, "archive",
                                                      "example.org",
                                                      "cert17.pem"))
        # Absolute path logic
        os.unlink(self.test_rc.cert)
        os.symlink(os.path.join(self.config.config_dir, "archive", "example.org",
                                "cert17.pem"), self.test_rc.cert)
        with open(self.test_rc.cert, "w") as f:
            f.write("cert")
        assert os.path.samefile(self.test_rc.current_target("cert"),
                                         os.path.join(self.config.config_dir, "archive",
                                                      "example.org",
                                                      "cert17.pem"))

    def test_current_version(self):
        for ver in (1, 5, 10, 20):
            self._write_out_kind("cert", ver)
        os.unlink(self.test_rc.cert)
        os.symlink(os.path.join("..", "..", "archive", "example.org",
                                "cert10.pem"), self.test_rc.cert)
        assert self.test_rc.current_version("cert") == 10

    def test_no_current_version(self):
        assert self.test_rc.current_version("cert") is None

    def test_latest_and_next_versions(self):
        for ver in range(1, 6):
            for kind in ALL_FOUR:
                self._write_out_kind(kind, ver)
        assert self.test_rc.latest_common_version() == 5
        assert self.test_rc.next_free_version() == 6
        # Having one kind of file of a later version doesn't change the
        # result
        self._write_out_kind("privkey", 7)
        assert self.test_rc.latest_common_version() == 5
        # ... although it does change the next free version
        assert self.test_rc.next_free_version() == 8
        # Nor does having three out of four change the result
        self._write_out_kind("cert", 7)
        self._write_out_kind("fullchain", 7)
        assert self.test_rc.latest_common_version() == 5
        # If we have everything from a much later version, it does change
        # the result
        for kind in ALL_FOUR:
            self._write_out_kind(kind, 17)
        assert self.test_rc.latest_common_version() == 17
        assert self.test_rc.next_free_version() == 18

    @mock.patch("certbot._internal.storage.logger")
    def test_ensure_deployed(self, mock_logger):
        mock_update = self.test_rc.update_all_links_to = mock.Mock()
        mock_has_pending = self.test_rc.has_pending_deployment = mock.Mock()
        self.test_rc.latest_common_version = mock.Mock()

        mock_has_pending.return_value = False
        assert self.test_rc.ensure_deployed() is True
        assert mock_update.call_count == 0
        assert mock_logger.warning.call_count == 0

        mock_has_pending.return_value = True
        assert self.test_rc.ensure_deployed() is False
        assert mock_update.call_count == 1
        assert mock_logger.warning.call_count == 1


    def test_update_link_to(self):
        for ver in range(1, 6):
            for kind in ALL_FOUR:
                self._write_out_kind(kind, ver)
                assert ver == self.test_rc.current_version(kind)
        # pylint: disable=protected-access
        self.test_rc._update_link_to("cert", 3)
        self.test_rc._update_link_to("privkey", 2)
        assert 3 == self.test_rc.current_version("cert")
        assert 2 == self.test_rc.current_version("privkey")
        assert 5 == self.test_rc.current_version("chain")
        assert 5 == self.test_rc.current_version("fullchain")
        # Currently we are allowed to update to a version that doesn't exist
        self.test_rc._update_link_to("chain", 3000)
        # However, current_version doesn't allow querying the resulting
        # version (because it's a broken link).
        assert os.path.basename(filesystem.readlink(self.test_rc.chain)) == \
                         "chain3000.pem"

    def test_version(self):
        self._write_out_kind("cert", 12)
        # TODO: We should probably test that the directory is still the
        #       same, but it's tricky because we can get an absolute
        #       path out when we put a relative path in.
        assert "cert8.pem" == \
                         os.path.basename(self.test_rc.version("cert", 8))

    def test_update_all_links_to_success(self):
        for ver in range(1, 6):
            for kind in ALL_FOUR:
                self._write_out_kind(kind, ver)
                assert ver == self.test_rc.current_version(kind)
        assert self.test_rc.latest_common_version() == 5
        for ver in range(1, 6):
            self.test_rc.update_all_links_to(ver)
            for kind in ALL_FOUR:
                assert ver == self.test_rc.current_version(kind)
            assert self.test_rc.latest_common_version() == 5

    def test_update_all_links_to_partial_failure(self):
        def unlink_or_raise(path, real_unlink=os.unlink):
            # pylint: disable=missing-docstring
            basename = os.path.basename(path)
            if "fullchain" in basename and basename.startswith("prev"):
                raise ValueError
            real_unlink(path)

        self._write_out_ex_kinds()
        with mock.patch("certbot._internal.storage.os.unlink") as mock_unlink:
            mock_unlink.side_effect = unlink_or_raise
            with pytest.raises(ValueError):
                self.test_rc.update_all_links_to(12)

        for kind in ALL_FOUR:
            assert self.test_rc.current_version(kind) == 12

    def test_update_all_links_to_full_failure(self):
        def unlink_or_raise(path, real_unlink=os.unlink):
            # pylint: disable=missing-docstring
            if "fullchain" in os.path.basename(path):
                raise ValueError
            real_unlink(path)

        self._write_out_ex_kinds()
        with mock.patch("certbot._internal.storage.os.unlink") as mock_unlink:
            mock_unlink.side_effect = unlink_or_raise
            with pytest.raises(ValueError):
                self.test_rc.update_all_links_to(12)

        for kind in ALL_FOUR:
            assert self.test_rc.current_version(kind) == 11

    def test_has_pending_deployment(self):
        for ver in range(1, 6):
            for kind in ALL_FOUR:
                self._write_out_kind(kind, ver)
                assert ver == self.test_rc.current_version(kind)
        for ver in range(1, 6):
            self.test_rc.update_all_links_to(ver)
            for kind in ALL_FOUR:
                assert ver == self.test_rc.current_version(kind)
            if ver < 5:
                assert self.test_rc.has_pending_deployment()
            else:
                assert not self.test_rc.has_pending_deployment()

    def test_names(self):
        # Trying the current version
        self._write_out_kind("cert", 12, test_util.load_vector("cert-san_512.pem"))

        assert self.test_rc.names() == \
                         ["example.com", "www.example.com"]

        # Trying missing cert
        os.unlink(self.test_rc.cert)
        with pytest.raises(errors.CertStorageError):
            self.test_rc.names()

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    @mock.patch("certbot._internal.storage.datetime")
    def test_time_interval_judgments(self, mock_datetime, mock_set_by_user):
        """Test should_autorenew() on the basis of expiry time windows."""
        test_cert = test_util.load_vector("cert_512.pem")

        self._write_out_ex_kinds()

        self.test_rc.update_all_links_to(12)
        with open(self.test_rc.cert, "wb") as f:
            f.write(test_cert)
        self.test_rc.update_all_links_to(11)
        with open(self.test_rc.cert, "wb") as f:
            f.write(test_cert)

        mock_datetime.timedelta = datetime.timedelta
        mock_set_by_user.return_value = False
        self.test_rc.configuration["renewalparams"] = {}

        for (current_time, interval, result) in [
                # 2014-12-13 12:00:00+00:00 (about 5 days prior to expiry)
                # Times that should result in autorenewal/autodeployment
                (1418472000, "2 months", True), (1418472000, "1 week", True),
                # Times that should not
                (1418472000, "4 days", False), (1418472000, "2 days", False),
                # 2009-05-01 12:00:00+00:00 (about 5 years prior to expiry)
                # Times that should result in autorenewal/autodeployment
                (1241179200, "7 years", True),
                (1241179200, "11 years 2 months", True),
                # Times that should not
                (1241179200, "8 hours", False), (1241179200, "2 days", False),
                (1241179200, "40 days", False), (1241179200, "9 months", False),
                # 2015-01-01 (after expiry has already happened, so all
                #            intervals should cause autorenewal/autodeployment)
                (1420070400, "0 seconds", True),
                (1420070400, "10 seconds", True),
                (1420070400, "10 minutes", True),
                (1420070400, "10 weeks", True), (1420070400, "10 months", True),
                (1420070400, "10 years", True), (1420070400, "99 months", True),
        ]:
            sometime = datetime.datetime.fromtimestamp(current_time, pytz.UTC)
            mock_datetime.datetime.now.return_value = sometime
            self.test_rc.configuration["renew_before_expiry"] = interval
            assert self.test_rc.should_autorenew() == result

    def test_autorenewal_is_enabled(self):
        self.test_rc.configuration["renewalparams"] = {}
        assert self.test_rc.autorenewal_is_enabled()
        self.test_rc.configuration["renewalparams"]["autorenew"] = "True"
        assert self.test_rc.autorenewal_is_enabled()

        self.test_rc.configuration["renewalparams"]["autorenew"] = "False"
        assert not self.test_rc.autorenewal_is_enabled()

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    @mock.patch("certbot._internal.storage.RenewableCert.ocsp_revoked")
    def test_should_autorenew(self, mock_ocsp, mock_set_by_user):
        """Test should_autorenew on the basis of reasons other than
        expiry time window."""
        mock_set_by_user.return_value = False
        # Autorenewal turned off
        self.test_rc.configuration["renewalparams"] = {"autorenew": "False"}
        assert not self.test_rc.should_autorenew()
        self.test_rc.configuration["renewalparams"]["autorenew"] = "True"
        for kind in ALL_FOUR:
            self._write_out_kind(kind, 12)
        # Mandatory renewal on the basis of OCSP revocation
        mock_ocsp.return_value = True
        assert self.test_rc.should_autorenew()
        mock_ocsp.return_value = False

    @mock.patch("certbot._internal.storage.relevant_values")
    def test_save_successor(self, mock_rv):
        # Mock relevant_values() to claim that all values are relevant here
        # (to avoid instantiating parser)
        mock_rv.side_effect = lambda x: x.to_dict()

        for ver in range(1, 6):
            for kind in ALL_FOUR:
                self._write_out_kind(kind, ver)
        self.test_rc.update_all_links_to(3)
        assert 6 == self.test_rc.save_successor(3, b'new cert', None,
                                           b'new chain', self.config)
        with open(self.test_rc.version("cert", 6)) as f:
            assert f.read() == "new cert"
        with open(self.test_rc.version("chain", 6)) as f:
            assert f.read() == "new chain"
        with open(self.test_rc.version("fullchain", 6)) as f:
            assert f.read() == "new cert" + "new chain"
        # version 6 of the key should be a link back to version 3
        assert not os.path.islink(self.test_rc.version("privkey", 3))
        assert os.path.islink(self.test_rc.version("privkey", 6))
        # Let's try two more updates
        assert 7 == self.test_rc.save_successor(6, b'again', None,
                                           b'newer chain', self.config)
        assert 8 == self.test_rc.save_successor(7, b'hello', None,
                                           b'other chain', self.config)
        # All of the subsequent versions should link directly to the original
        # privkey.
        for i in (6, 7, 8):
            assert os.path.islink(self.test_rc.version("privkey", i))
            assert "privkey3.pem" == os.path.basename(filesystem.readlink(
                self.test_rc.version("privkey", i)))

        for kind in ALL_FOUR:
            assert self.test_rc.available_versions(kind) == list(range(1, 9))
            assert self.test_rc.current_version(kind) == 3
        # Test updating from latest version rather than old version
        self.test_rc.update_all_links_to(8)
        assert 9 == self.test_rc.save_successor(8, b'last', None,
                                           b'attempt', self.config)
        for kind in ALL_FOUR:
            assert self.test_rc.available_versions(kind) == \
                             list(range(1, 10))
            assert self.test_rc.current_version(kind) == 8
        with open(self.test_rc.version("fullchain", 9)) as f:
            assert f.read() == "last" + "attempt"
        temp_config_file = os.path.join(self.config.renewal_configs_dir,
                                        self.test_rc.lineagename) + ".conf.new"
        with open(temp_config_file, "w") as f:
            f.write("We previously crashed while writing me :(")
        # Test updating when providing a new privkey.  The key should
        # be saved in a new file rather than creating a new symlink.
        assert 10 == self.test_rc.save_successor(9, b'with', b'a',
                                            b'key', self.config)
        assert os.path.exists(self.test_rc.version("privkey", 10))
        assert not os.path.islink(self.test_rc.version("privkey", 10))
        assert not os.path.exists(temp_config_file)

    @test_util.skip_on_windows('Group/everybody permissions are not maintained on Windows.')
    @mock.patch("certbot._internal.storage.relevant_values")
    def test_save_successor_maintains_group_mode(self, mock_rv):
        # Mock relevant_values() to claim that all values are relevant here
        # (to avoid instantiating parser)
        mock_rv.side_effect = lambda x: x.to_dict()
        for kind in ALL_FOUR:
            self._write_out_kind(kind, 1)
        self.test_rc.update_all_links_to(1)
        assert filesystem.check_mode(self.test_rc.version("privkey", 1), 0o600)
        filesystem.chmod(self.test_rc.version("privkey", 1), 0o444)
        # If no new key, permissions should be the same (we didn't write any keys)
        self.test_rc.save_successor(1, b"newcert", None, b"new chain", self.config)
        assert filesystem.check_mode(self.test_rc.version("privkey", 2), 0o444)
        # If new key, permissions should be kept as 644
        self.test_rc.save_successor(2, b"newcert", b"new_privkey", b"new chain", self.config)
        assert filesystem.check_mode(self.test_rc.version("privkey", 3), 0o644)
        # If permissions reverted, next renewal will also revert permissions of new key
        filesystem.chmod(self.test_rc.version("privkey", 3), 0o400)
        self.test_rc.save_successor(3, b"newcert", b"new_privkey", b"new chain", self.config)
        assert filesystem.check_mode(self.test_rc.version("privkey", 4), 0o600)

    @mock.patch("certbot._internal.storage.relevant_values")
    @mock.patch("certbot._internal.storage.filesystem.copy_ownership_and_apply_mode")
    def test_save_successor_maintains_gid(self, mock_ownership, mock_rv):
        # Mock relevant_values() to claim that all values are relevant here
        # (to avoid instantiating parser)
        mock_rv.side_effect = lambda x: x.to_dict()
        for kind in ALL_FOUR:
            self._write_out_kind(kind, 1)
        self.test_rc.update_all_links_to(1)
        self.test_rc.save_successor(1, b"newcert", None, b"new chain", self.config)
        assert mock_ownership.called is False
        self.test_rc.save_successor(2, b"newcert", b"new_privkey", b"new chain", self.config)
        assert mock_ownership.called

    @mock.patch("certbot._internal.storage.relevant_values")
    def test_new_lineage(self, mock_rv):
        """Test for new_lineage() class method."""
        # Mock relevant_values to say everything is relevant here (so we
        # don't have to mock the parser to help it decide!)
        mock_rv.side_effect = lambda x: x.to_dict()

        from certbot._internal import storage
        result = storage.RenewableCert.new_lineage(
            "the-lineage.com", b"cert", b"privkey", b"chain", self.config)
        # This consistency check tests most relevant properties about the
        # newly created cert lineage.
        # pylint: disable=protected-access
        assert result._consistent()
        assert os.path.exists(os.path.join(
            self.config.renewal_configs_dir, "the-lineage.com.conf"))
        assert os.path.exists(os.path.join(
            self.config.live_dir, "README"))
        assert os.path.exists(os.path.join(
            self.config.live_dir, "the-lineage.com", "README"))
        assert filesystem.check_mode(result.key_path, 0o600)
        with open(result.fullchain, "rb") as f:
            assert f.read() == b"cert" + b"chain"
        # Let's do it again and make sure it makes a different lineage
        result = storage.RenewableCert.new_lineage(
            "the-lineage.com", b"cert2", b"privkey2", b"chain2", self.config)
        assert os.path.exists(os.path.join(
            self.config.renewal_configs_dir, "the-lineage.com-0001.conf"))
        assert os.path.exists(os.path.join(
            self.config.live_dir, "the-lineage.com-0001", "README"))
        # Allow write to existing but empty dir
        filesystem.mkdir(os.path.join(self.config.default_archive_dir, "the-lineage.com-0002"))
        result = storage.RenewableCert.new_lineage(
            "the-lineage.com", b"cert3", b"privkey3", b"chain3", self.config)
        assert os.path.exists(os.path.join(
            self.config.live_dir, "the-lineage.com-0002", "README"))
        assert filesystem.check_mode(result.key_path, 0o600)
        # Now trigger the detection of already existing files
        shutil.copytree(os.path.join(self.config.live_dir, "the-lineage.com"),
                        os.path.join(self.config.live_dir, "the-lineage.com-0003"))
        with pytest.raises(errors.CertStorageError):
            storage.RenewableCert.new_lineage("the-lineage.com",
                          b"cert4", b"privkey4", b"chain4", self.config)
        shutil.copytree(os.path.join(self.config.live_dir, "the-lineage.com"),
                        os.path.join(self.config.live_dir, "other-example.com"))
        with pytest.raises(errors.CertStorageError):
            storage.RenewableCert.new_lineage("other-example.com", b"cert5",
                          b"privkey5", b"chain5", self.config)
        # Make sure it can accept renewal parameters
        result = storage.RenewableCert.new_lineage(
            "the-lineage.com", b"cert2", b"privkey2", b"chain2", self.config)
        # TODO: Conceivably we could test that the renewal parameters actually
        #       got saved

    @mock.patch("certbot._internal.storage.relevant_values")
    def test_new_lineage_nonexistent_dirs(self, mock_rv):
        """Test that directories can be created if they don't exist."""
        # Mock relevant_values to say everything is relevant here (so we
        # don't have to mock the parser to help it decide!)
        mock_rv.side_effect = lambda x: x.to_dict()

        from certbot._internal import storage
        shutil.rmtree(self.config.renewal_configs_dir)
        shutil.rmtree(self.config.default_archive_dir)
        shutil.rmtree(self.config.live_dir)

        storage.RenewableCert.new_lineage(
            "the-lineage.com", b"cert2", b"privkey2", b"chain2", self.config)
        assert os.path.exists(
            os.path.join(
                self.config.renewal_configs_dir, "the-lineage.com.conf"))
        assert os.path.exists(os.path.join(
            self.config.live_dir, "the-lineage.com", "privkey.pem"))
        assert os.path.exists(os.path.join(
            self.config.default_archive_dir, "the-lineage.com", "privkey1.pem"))

    @mock.patch("certbot._internal.storage.util.unique_lineage_name")
    def test_invalid_config_filename(self, mock_uln):
        from certbot._internal import storage
        mock_uln.return_value = "this_does_not_end_with_dot_conf", "yikes"
        with pytest.raises(errors.CertStorageError):
            storage.RenewableCert.new_lineage("example.com",
                          "cert", "privkey", "chain", self.config)

    def test_bad_kind(self):
        with pytest.raises(errors.CertStorageError):
            self.test_rc.current_target("elephant")
        with pytest.raises(errors.CertStorageError):
            self.test_rc.current_version("elephant")
        with pytest.raises(errors.CertStorageError):
            self.test_rc.version("elephant", 17)
        with pytest.raises(errors.CertStorageError):
            self.test_rc.available_versions("elephant")
        with pytest.raises(errors.CertStorageError):
            self.test_rc.newest_available_version("elephant")
        # pylint: disable=protected-access
        with pytest.raises(errors.CertStorageError):
            self.test_rc._update_link_to("elephant", 17)

    @mock.patch("certbot.ocsp.RevocationChecker.ocsp_revoked_by_paths")
    def test_ocsp_revoked(self, mock_checker):
        # Write out test files
        for kind in ALL_FOUR:
            self._write_out_kind(kind, 1)
        version = self.test_rc.latest_common_version()
        expected_cert_path = self.test_rc.version("cert", version)
        expected_chain_path = self.test_rc.version("chain", version)

        # Test with cert revoked
        mock_checker.return_value = True
        assert self.test_rc.ocsp_revoked(version)
        assert mock_checker.call_args[0][0] == expected_cert_path
        assert mock_checker.call_args[0][1] == expected_chain_path

        # Test with cert not revoked
        mock_checker.return_value = False
        assert not self.test_rc.ocsp_revoked(version)
        assert mock_checker.call_args[0][0] == expected_cert_path
        assert mock_checker.call_args[0][1] == expected_chain_path

        # Test with error
        mock_checker.side_effect = ValueError
        with mock.patch("certbot._internal.storage.logger.warning") as logger:
            assert not self.test_rc.ocsp_revoked(version)
        assert mock_checker.call_args[0][0] == expected_cert_path
        assert mock_checker.call_args[0][1] == expected_chain_path
        log_msg = logger.call_args[0][0]
        assert "An error occurred determining the OCSP status" in log_msg

    def test_add_time_interval(self):
        from certbot._internal import storage

        # this month has 30 days, and the next year is a leap year
        time_1 = datetime.datetime(2003, 11, 20, 11, 59, 21, tzinfo=pytz.UTC)

        # this month has 31 days, and the next year is not a leap year
        time_2 = datetime.datetime(2012, 10, 18, 21, 31, 16, tzinfo=pytz.UTC)

        # in different time zone (GMT+8)
        time_3 = pytz.timezone('Asia/Shanghai').fromutc(
            datetime.datetime(2015, 10, 26, 22, 25, 41))

        intended = {
            (time_1, ""): time_1,
            (time_2, ""): time_2,
            (time_3, ""): time_3,
            (time_1, "17 days"): time_1 + datetime.timedelta(17),
            (time_2, "17 days"): time_2 + datetime.timedelta(17),
            (time_1, "30"): time_1 + datetime.timedelta(30),
            (time_2, "30"): time_2 + datetime.timedelta(30),
            (time_1, "7 weeks"): time_1 + datetime.timedelta(49),
            (time_2, "7 weeks"): time_2 + datetime.timedelta(49),
            # 1 month is always 30 days, no matter which month it is
            (time_1, "1 month"): time_1 + datetime.timedelta(30),
            (time_2, "1 month"): time_2 + datetime.timedelta(31),
            # 1 year could be 365 or 366 days, depends on the year
            (time_1, "1 year"): time_1 + datetime.timedelta(366),
            (time_2, "1 year"): time_2 + datetime.timedelta(365),
            (time_1, "1 year 1 day"): time_1 + datetime.timedelta(367),
            (time_2, "1 year 1 day"): time_2 + datetime.timedelta(366),
            (time_1, "1 year-1 day"): time_1 + datetime.timedelta(365),
            (time_2, "1 year-1 day"): time_2 + datetime.timedelta(364),
            (time_1, "4 years"): time_1 + datetime.timedelta(1461),
            (time_2, "4 years"): time_2 + datetime.timedelta(1461),
        }

        for parameters, excepted in intended.items():
            base_time, interval = parameters
            assert storage.add_time_interval(base_time, interval) == \
                             excepted
    
    def test_parse_js_time(self):
        ts = "2024-07-04T19:56:35Z"
        from certbot._internal import storage
        t = storage.parse_js_time(ts)
        assert t == datetime.datetime(2024, 7, 4, 19, 56, 35, tzinfo=datetime.timezone.utc)

    def test_server(self):
        self.test_rc.configuration["renewalparams"] = {}
        assert self.test_rc.server is None
        rp = self.test_rc.configuration["renewalparams"]
        rp["server"] = "https://acme.example/dir"
        assert self.test_rc.server == "https://acme.example/dir"

    def test_is_test_cert(self):
        self.test_rc.configuration["renewalparams"] = {}
        rp = self.test_rc.configuration["renewalparams"]
        assert self.test_rc.is_test_cert is False
        rp["server"] = "https://acme-staging-v02.api.letsencrypt.org/directory"
        assert self.test_rc.is_test_cert is True
        rp["server"] = "https://staging.someotherca.com/directory"
        assert self.test_rc.is_test_cert is True
        rp["server"] = "https://acme-v01.api.letsencrypt.org/directory"
        assert self.test_rc.is_test_cert is False
        rp["server"] = "https://acme-v02.api.letsencrypt.org/directory"
        assert self.test_rc.is_test_cert is False

    def test_missing_cert(self):
        from certbot._internal import storage
        with pytest.raises(errors.CertStorageError):
            storage.RenewableCert(self.config_file.filename, self.config)
        os.symlink("missing", self.config_file[ALL_FOUR[0]])
        with pytest.raises(errors.CertStorageError):
            storage.RenewableCert(self.config_file.filename, self.config)

    def test_write_renewal_config(self):
        # Mostly tested by the process of creating and updating lineages,
        # but we can test that this successfully creates files, removes
        # unneeded items, and preserves comments.
        temp = os.path.join(self.config.config_dir, "sample-file")
        temp2 = os.path.join(self.config.config_dir, "sample-file.new")
        with open(temp, "w") as f:
            f.write("[renewalparams]\nuseful = value # A useful value\n"
                    "useless = value # Not needed\n")
        filesystem.chmod(temp, 0o640)
        target = {}
        for x in ALL_FOUR:
            target[x] = "somewhere"
        archive_dir = "the_archive"
        relevant_data = {"useful": "new_value"}

        from certbot._internal import storage
        storage.write_renewal_config(temp, temp2, archive_dir, target, relevant_data)

        with open(temp2, "r") as f:
            content = f.read()
        # useful value was updated
        assert "useful = new_value" in content
        # associated comment was preserved
        assert "A useful value" in content
        # useless value was deleted
        assert "useless" not in content
        # check version was stored
        assert "version = {0}".format(certbot.__version__) in content
        # ensure permissions are copied
        assert stat.S_IMODE(os.lstat(temp).st_mode) == \
                         stat.S_IMODE(os.lstat(temp2).st_mode)

    def test_truncate(self):
        # It should not do anything when there's less than 5 cert history
        for kind in ALL_FOUR:
            self._write_out_kind(kind, 1)
        with mock.patch('certbot.compat.os.unlink') as mock_unlink:
            self.test_rc.truncate()
            mock_unlink.assert_not_called()

        # It should truncate the excess when there's more than 5 cert history
        for kind in ALL_FOUR:
            for i in range(2, 8):
                self._write_out_kind(kind, i)
        with mock.patch('certbot.compat.os.unlink') as mock_unlink:
            self.test_rc.truncate()
            assert mock_unlink.call_count == 1 * len(ALL_FOUR)
            assert "1.pem" in mock_unlink.call_args_list[0][0][0]

class DeleteFilesTest(BaseRenewableCertTest):
    """Tests for certbot._internal.storage.delete_files"""
    def setUp(self):
        super().setUp()

        for kind in ALL_FOUR:
            kind_path = os.path.join(self.config.config_dir, "live", "example.org",
                                        kind + ".pem")
            with open(kind_path, 'a'):
                pass
        self.config_file.write()
        assert os.path.exists(os.path.join(
            self.config.renewal_configs_dir, "example.org.conf"))
        assert os.path.exists(os.path.join(
            self.config.live_dir, "example.org"))
        assert os.path.exists(os.path.join(
            self.config.config_dir, "archive", "example.org"))

    def _call(self):
        from certbot._internal import storage
        with mock.patch("certbot._internal.storage.logger"):
            storage.delete_files(self.config, "example.org")

    def test_delete_all_files(self):
        self._call()

        assert not os.path.exists(os.path.join(
            self.config.renewal_configs_dir, "example.org.conf"))
        assert not os.path.exists(os.path.join(
            self.config.live_dir, "example.org"))
        assert not os.path.exists(os.path.join(
            self.config.config_dir, "archive", "example.org"))

    def test_bad_renewal_config(self):
        with open(self.config_file.filename, 'a') as config_file:
            config_file.write("asdfasfasdfasdf")

        with pytest.raises(errors.CertStorageError):
            self._call()
        assert os.path.exists(os.path.join(
            self.config.live_dir, "example.org"))
        assert not os.path.exists(os.path.join(
            self.config.renewal_configs_dir, "example.org.conf"))

    def test_no_renewal_config(self):
        os.remove(self.config_file.filename)
        with pytest.raises(errors.CertStorageError):
            self._call()
        assert os.path.exists(os.path.join(
            self.config.live_dir, "example.org"))
        assert not os.path.exists(self.config_file.filename)

    def test_no_cert_file(self):
        os.remove(os.path.join(
            self.config.live_dir, "example.org", "cert.pem"))
        self._call()
        assert not os.path.exists(self.config_file.filename)
        assert not os.path.exists(os.path.join(
            self.config.live_dir, "example.org"))
        assert not os.path.exists(os.path.join(
            self.config.config_dir, "archive", "example.org"))

    def test_no_readme_file(self):
        os.remove(os.path.join(
            self.config.live_dir, "example.org", "README"))
        self._call()
        assert not os.path.exists(self.config_file.filename)
        assert not os.path.exists(os.path.join(
            self.config.live_dir, "example.org"))
        assert not os.path.exists(os.path.join(
            self.config.config_dir, "archive", "example.org"))

    def test_livedir_not_empty(self):
        with open(os.path.join(
            self.config.live_dir, "example.org", "other_file"), 'a'):
            pass
        self._call()
        assert not os.path.exists(self.config_file.filename)
        assert os.path.exists(os.path.join(
            self.config.live_dir, "example.org"))
        assert not os.path.exists(os.path.join(
            self.config.config_dir, "archive", "example.org"))

    def test_no_archive(self):
        archive_dir = os.path.join(self.config.config_dir, "archive", "example.org")
        os.rmdir(archive_dir)
        self._call()
        assert not os.path.exists(self.config_file.filename)
        assert not os.path.exists(os.path.join(
            self.config.live_dir, "example.org"))
        assert not os.path.exists(archive_dir)

class CertPathForCertNameTest(BaseRenewableCertTest):
    """Test for certbot._internal.storage.cert_path_for_cert_name"""
    def setUp(self):
        super().setUp()
        self.config_file.write()
        self._write_out_ex_kinds()
        self.fullchain = os.path.join(self.config.config_dir, 'live', 'example.org',
                'fullchain.pem')
        self.config.cert_path = self.fullchain

    def _call(self, cli_config, certname):
        from certbot._internal.storage import cert_path_for_cert_name
        return cert_path_for_cert_name(cli_config, certname)

    def test_simple_cert_name(self):
        assert self._call(self.config, 'example.org') == self.fullchain

    def test_no_such_cert_name(self):
        with pytest.raises(errors.CertStorageError):
            self._call(self.config, 'fake-example.org')

if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
