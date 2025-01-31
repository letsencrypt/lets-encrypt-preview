"""Test for certbot_apache._internal.configurator for Fedora 29+ overrides"""
import sys
from unittest import mock

import pytest

from certbot import errors
from certbot.compat import filesystem
from certbot.compat import os
from certbot_apache._internal import obj
from certbot_apache._internal import override_fedora
from certbot_apache._internal.tests import util


def get_vh_truth(temp_dir, config_name):
    """Return the ground truth for the specified directory."""
    prefix = os.path.join(
        temp_dir, config_name, "httpd/conf.d")

    aug_pre = "/files" + prefix
    # TODO: eventually, these tests should have a dedicated configuration instead
    #  of reusing the ones from centos_test
    vh_truth = [
        obj.VirtualHost(
            os.path.join(prefix, "centos.example.com.conf"),
            os.path.join(aug_pre, "centos.example.com.conf/VirtualHost"),
            {obj.Addr.fromstring("*:80")},
            False, True, "centos.example.com"),
        obj.VirtualHost(
            os.path.join(prefix, "ssl.conf"),
            os.path.join(aug_pre, "ssl.conf/VirtualHost"),
            {obj.Addr.fromstring("_default_:443")},
            True, True, None)
    ]
    return vh_truth


class FedoraRestartTest(util.ApacheTest):
    """Tests for Fedora specific self-signed certificate override"""

    # TODO: eventually, these tests should have a dedicated configuration instead
    #  of reusing the ones from centos_test
    def setUp(self, **kwargs):
        test_dir = "centos7_apache/apache"
        config_root = "centos7_apache/apache/httpd"
        vhost_root = "centos7_apache/apache/httpd/conf.d"
        super().setUp(test_dir=test_dir,
                      config_root=config_root,
                      vhost_root=vhost_root)
        self.config = util.get_apache_configurator(
            self.config_path, self.vhost_path, self.config_dir, self.work_dir,
            os_info="fedora")
        self.vh_truth = get_vh_truth(
            self.temp_dir, "centos7_apache/apache")

    def _run_fedora_test(self):
        assert isinstance(self.config, override_fedora.FedoraConfigurator)
        self.config.config_test()

    def test_fedora_restart_error(self):
        c_test = "certbot_apache._internal.configurator.ApacheConfigurator.config_test"
        with mock.patch(c_test) as mock_test:
            # First call raises error, second doesn't
            mock_test.side_effect = [errors.MisconfigurationError, '']
            with mock.patch("certbot.util.run_script") as mock_run:
                mock_run.side_effect = errors.SubprocessError
                with pytest.raises(errors.MisconfigurationError):
                    self._run_fedora_test()

    def test_fedora_restart(self):
        c_test = "certbot_apache._internal.configurator.ApacheConfigurator.config_test"
        with mock.patch(c_test) as mock_test:
            with mock.patch("certbot.util.run_script") as mock_run:
                # First call raises error, second doesn't
                mock_test.side_effect = [errors.MisconfigurationError, '']
                self._run_fedora_test()
                assert mock_test.call_count == 2
                assert mock_run.call_args[0][0] == \
                                ['systemctl', 'restart', 'httpd']


class MultipleVhostsTestFedora(util.ApacheTest):
    """Multiple vhost tests for CentOS / RHEL family of distros"""

    def setUp(self, **kwargs):
        test_dir = "centos7_apache/apache"
        config_root = "centos7_apache/apache/httpd"
        vhost_root = "centos7_apache/apache/httpd/conf.d"
        super().setUp(test_dir=test_dir,
                      config_root=config_root,
                      vhost_root=vhost_root)

        self.config = util.get_apache_configurator(
            self.config_path, self.vhost_path, self.config_dir, self.work_dir,
            os_info="fedora")
        self.vh_truth = get_vh_truth(
            self.temp_dir, "centos7_apache/apache")

    def test_get_parser(self):
        assert isinstance(self.config.parser, override_fedora.FedoraParser)

    @mock.patch("certbot_apache._internal.apache_util._get_runtime_cfg")
    def test_opportunistic_httpd_runtime_parsing(self, mock_get):
        define_val = (
            'Define: TEST1\n'
            'Define: TEST2\n'
            'Define: DUMP_RUN_CFG\n'
        )
        mod_val = (
            'Loaded Modules:\n'
            ' mock_module (static)\n'
            ' another_module (static)\n'
        )
        def mock_get_cfg(command):
            """Mock httpd process stdout"""
            if command == ['httpd', '-t', '-D', 'DUMP_RUN_CFG']:
                return define_val
            elif command == ['httpd', '-t', '-D', 'DUMP_MODULES']:
                return mod_val
            return ""
        mock_get.side_effect = mock_get_cfg
        self.config.parser.modules = {}
        self.config.parser.variables = {}

        with mock.patch("certbot.util.get_os_info") as mock_osi:
            # Make sure we have the have the CentOS httpd constants
            mock_osi.return_value = ("fedora", "29")
            self.config.parser.update_runtime_variables()

        assert mock_get.call_count == 3
        assert len(self.config.parser.modules) == 4
        assert len(self.config.parser.variables) == 2
        assert "TEST2" in self.config.parser.variables
        assert "mod_another.c" in self.config.parser.modules

    @mock.patch("certbot_apache._internal.configurator.util.run_script")
    def test_get_version(self, mock_run_script):
        mock_run_script.return_value = ('', None)
        with pytest.raises(errors.PluginError):
            self.config.get_version()
        assert mock_run_script.call_args[0][0][0] == 'httpd'

    def test_get_virtual_hosts(self):
        """Make sure all vhosts are being properly found."""
        vhs = self.config.get_virtual_hosts()
        assert len(vhs) == 2
        found = 0

        for vhost in vhs:
            for centos_truth in self.vh_truth:
                if vhost == centos_truth:
                    found += 1
                    break
            else:
                raise Exception("Missed: %s" % vhost)  # pragma: no cover
        assert found == 2

    @mock.patch("certbot_apache._internal.apache_util._get_runtime_cfg")
    def test_get_sysconfig_vars(self, mock_cfg):
        """Make sure we read the sysconfig OPTIONS variable correctly"""
        # Return nothing for the process calls
        mock_cfg.return_value = ""
        self.config.parser.sysconfig_filep = filesystem.realpath(
            os.path.join(self.config.parser.root, "../sysconfig/httpd"))
        self.config.parser.variables = {}

        with mock.patch("certbot.util.get_os_info") as mock_osi:
            # Make sure we have the have the CentOS httpd constants
            mock_osi.return_value = ("fedora", "29")
            self.config.parser.update_runtime_variables()

        assert "mock_define" in self.config.parser.variables
        assert "mock_define_too" in self.config.parser.variables
        assert "mock_value" in self.config.parser.variables
        assert "TRUE" == self.config.parser.variables["mock_value"]
        assert "MOCK_NOSEP" in self.config.parser.variables
        assert "NOSEP_VAL" == self.config.parser.variables["NOSEP_TWO"]

    @mock.patch("certbot_apache._internal.configurator.util.run_script")
    def test_alt_restart_works(self, mock_run_script):
        mock_run_script.side_effect = [None, errors.SubprocessError, None]
        self.config.restart()
        assert mock_run_script.call_count == 3

    @mock.patch("certbot_apache._internal.configurator.util.run_script")
    def test_alt_restart_errors(self, mock_run_script):
        mock_run_script.side_effect = [None,
                                       errors.SubprocessError,
                                       errors.SubprocessError]
        with pytest.raises(errors.MisconfigurationError):
            self.config.restart()


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
