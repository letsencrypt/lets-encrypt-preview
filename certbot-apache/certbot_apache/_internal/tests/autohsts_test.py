# pylint: disable=too-many-lines
"""Test for certbot_apache._internal.configurator AutoHSTS functionality"""
import re
import sys
from unittest import mock

import pytest

from certbot import errors
from certbot_apache._internal import constants
from certbot_apache._internal.tests import util


class AutoHSTSTest(util.ApacheTest):
    """Tests for AutoHSTS feature"""
    # pylint: disable=protected-access

    def setUp(self, **kwargs):
        super().setUp()

        self.config = util.get_apache_configurator(
            self.config_path, self.vhost_path, self.config_dir, self.work_dir)
        self.config.parser.modules["headers_module"] = None
        self.config.parser.modules["mod_headers.c"] = None
        self.config.parser.modules["ssl_module"] = None
        self.config.parser.modules["mod_ssl.c"] = None

        self.vh_truth = util.get_vh_truth(
            self.temp_dir, "debian_apache_2_4/multiple_vhosts")

    def get_autohsts_value(self, vh_path):
        """ Get value from Strict-Transport-Security header """
        header_path = self.config.parser.find_dir("Header", None, vh_path)
        if header_path:
            pat = '(?:[ "]|^)(strict-transport-security)(?:[ "]|$)'
            for head in header_path:
                if re.search(pat, self.config.parser.aug.get(head).lower()):
                    return self.config.parser.aug.get(
                        head.replace("arg[3]", "arg[4]"))
        return None  # pragma: no cover

    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator.restart")
    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator.enable_mod")
    def test_autohsts_enable_headers_mod(self, mock_enable, _restart):
        self.config.parser.modules.pop("headers_module", None)
        self.config.parser.modules.pop("mod_header.c", None)
        self.config.enable_autohsts(mock.MagicMock(), ["ocspvhost.com"])
        assert mock_enable.called is True

    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator.restart")
    def test_autohsts_deploy_already_exists(self, _restart):
        self.config.enable_autohsts(mock.MagicMock(), ["ocspvhost.com"])
        with pytest.raises(errors.PluginEnhancementAlreadyPresent):
            self.config.enable_autohsts(mock.MagicMock(), ["ocspvhost.com"])

    @mock.patch("certbot_apache._internal.constants.AUTOHSTS_FREQ", 0)
    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator.restart")
    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator.prepare")
    def test_autohsts_increase(self, mock_prepare, _mock_restart):
        self.config._prepared = False
        maxage = "\"max-age={0}\""
        initial_val = maxage.format(constants.AUTOHSTS_STEPS[0])
        inc_val = maxage.format(constants.AUTOHSTS_STEPS[1])

        self.config.enable_autohsts(mock.MagicMock(), ["ocspvhost.com"])
        # Verify initial value
        assert self.get_autohsts_value(self.vh_truth[7].path) == \
                          initial_val
        # Increase
        self.config.update_autohsts(mock.MagicMock())
        # Verify increased value
        assert self.get_autohsts_value(self.vh_truth[7].path) == \
                          inc_val
        assert mock_prepare.called is True

    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator.restart")
    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator._autohsts_increase")
    def test_autohsts_increase_noop(self, mock_increase, _restart):
        maxage = "\"max-age={0}\""
        initial_val = maxage.format(constants.AUTOHSTS_STEPS[0])
        self.config.enable_autohsts(mock.MagicMock(), ["ocspvhost.com"])
        # Verify initial value
        assert self.get_autohsts_value(self.vh_truth[7].path) == \
                          initial_val

        self.config.update_autohsts(mock.MagicMock())
        # Freq not patched, so value shouldn't increase
        assert mock_increase.called is False


    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator.restart")
    @mock.patch("certbot_apache._internal.constants.AUTOHSTS_FREQ", 0)
    def test_autohsts_increase_no_header(self, _restart):
        self.config.enable_autohsts(mock.MagicMock(), ["ocspvhost.com"])
        # Remove the header
        dir_locs = self.config.parser.find_dir("Header", None,
                                              self.vh_truth[7].path)
        dir_loc = "/".join(dir_locs[0].split("/")[:-1])
        self.config.parser.aug.remove(dir_loc)
        with pytest.raises(errors.PluginError):
            self.config.update_autohsts(mock.MagicMock())

    @mock.patch("certbot_apache._internal.constants.AUTOHSTS_FREQ", 0)
    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator.restart")
    def test_autohsts_increase_and_make_permanent(self, _mock_restart):
        maxage = "\"max-age={0}\""
        max_val = maxage.format(constants.AUTOHSTS_PERMANENT)
        mock_lineage = mock.MagicMock()
        mock_lineage.key_path = "/etc/apache2/ssl/key-certbot_15.pem"
        self.config.enable_autohsts(mock.MagicMock(), ["ocspvhost.com"])
        for i in range(len(constants.AUTOHSTS_STEPS)-1):
            # Ensure that value is not made permanent prematurely
            self.config.deploy_autohsts(mock_lineage)
            assert self.get_autohsts_value(self.vh_truth[7].path) != \
                                 max_val
            self.config.update_autohsts(mock.MagicMock())
            # Value should match pre-permanent increment step
            cur_val = maxage.format(constants.AUTOHSTS_STEPS[i+1])
            assert self.get_autohsts_value(self.vh_truth[7].path) == \
                              cur_val
        # Ensure that the value is raised to max
        assert self.get_autohsts_value(self.vh_truth[7].path) == \
                          maxage.format(constants.AUTOHSTS_STEPS[-1])
        # Make permanent
        self.config.deploy_autohsts(mock_lineage)
        assert self.get_autohsts_value(self.vh_truth[7].path) == \
                          max_val

    def test_autohsts_update_noop(self):
        with mock.patch("certbot_apache._internal.configurator.time") as mock_time_module:
            # Time mock is used to make sure that the execution does not
            # continue when no autohsts entries exist in pluginstorage
            self.config.update_autohsts(mock.MagicMock())
            assert not mock_time_module.time.called

    def test_autohsts_make_permanent_noop(self):
        self.config.storage.put = mock.MagicMock()
        self.config.deploy_autohsts(mock.MagicMock())
        # Make sure that the execution does not continue when no entries in store
        assert self.config.storage.put.called is False

    @mock.patch("certbot_apache._internal.display_ops.select_vhost")
    def test_autohsts_no_ssl_vhost(self, mock_select):
        mock_select.return_value = self.vh_truth[0]
        with mock.patch("certbot_apache._internal.configurator.logger.error") as mock_log:
            with pytest.raises(errors.PluginError):
                self.config.enable_autohsts(mock.MagicMock(), "invalid.example.com")
            assert "Certbot was not able to find SSL" in mock_log.call_args[0][0]

    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator.restart")
    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator.add_vhost_id")
    def test_autohsts_dont_enhance_twice(self, mock_id, _restart):
        mock_id.return_value = "1234567"
        self.config.enable_autohsts(mock.MagicMock(), ["ocspvhost.com", "ocspvhost.com"])
        assert mock_id.call_count == 1

    def test_autohsts_remove_orphaned(self):
        # pylint: disable=protected-access
        self.config._autohsts_fetch_state()
        self.config._autohsts["orphan_id"] = {"laststep": 0, "timestamp": 0}

        self.config._autohsts_save_state()
        self.config.update_autohsts(mock.MagicMock())
        assert "orphan_id" not in self.config._autohsts
        # Make sure it's removed from the pluginstorage file as well
        self.config._autohsts = None
        self.config._autohsts_fetch_state()
        assert not self.config._autohsts

    def test_autohsts_make_permanent_vhost_not_found(self):
        # pylint: disable=protected-access
        self.config._autohsts_fetch_state()
        self.config._autohsts["orphan_id"] = {"laststep": 999, "timestamp": 0}
        self.config._autohsts_save_state()
        with mock.patch("certbot_apache._internal.configurator.logger.error") as mock_log:
            self.config.deploy_autohsts(mock.MagicMock())
            assert mock_log.called is True
            assert "VirtualHost with id orphan_id was not" in mock_log.call_args[0][0]


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
