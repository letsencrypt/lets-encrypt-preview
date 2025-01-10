"""Tests for certbot._internal.cli."""
import argparse
import copy
import io
import sys
import tempfile
from typing import Any, List
import unittest
from unittest import mock

import pytest

from acme import challenges
from certbot import errors
from certbot.configuration import ArgumentSource, NamespaceConfig
from certbot._internal import cli
from certbot._internal import constants
from certbot._internal.cli.cli_utils import flag_default
from certbot._internal.plugins import disco
from certbot.compat import filesystem
from certbot.compat import os
import certbot.tests.util as test_util
from certbot.tests.util import TempDirTestCase

PLUGINS = disco.PluginsRegistry.find_all()


class TestReadFile(TempDirTestCase):
    """Test cli.read_file"""
    def test_read_file(self):
        curr_dir = os.getcwd()
        try:
            # On Windows current directory may be on a different drive than self.tempdir.
            # However a relative path between two different drives is invalid. So we move to
            # self.tempdir to ensure that we stay on the same drive.
            os.chdir(self.tempdir)
            # The read-only filesystem introduced with macOS Catalina can break
            # code using relative paths below. See
            # https://bugs.python.org/issue38295 for another example of this.
            # Eliminating any possible symlinks in self.tempdir before passing
            # it to os.path.relpath solves the problem. This is done by calling
            # filesystem.realpath which removes any symlinks in the path on
            # POSIX systems.
            real_path = filesystem.realpath(os.path.join(self.tempdir, 'foo'))
            relative_path = os.path.relpath(real_path)
            with pytest.raises(argparse.ArgumentTypeError):
                cli.read_file(relative_path)

            test_contents = b'bar\n'
            with open(relative_path, 'wb') as f:
                f.write(test_contents)

            path, contents = cli.read_file(relative_path)
            assert path == os.path.abspath(path)
            assert contents == test_contents
        finally:
            os.chdir(curr_dir)


class FlagDefaultTest(unittest.TestCase):
    """Tests cli.flag_default"""

    def test_default_directories(self):
        if os.name != 'nt':
            assert cli.flag_default('config_dir') == '/etc/letsencrypt'
            assert cli.flag_default('work_dir') == '/var/lib/letsencrypt'
            assert cli.flag_default('logs_dir') == '/var/log/letsencrypt'
        else:
            assert cli.flag_default('config_dir') == 'C:\\Certbot'
            assert cli.flag_default('work_dir') == 'C:\\Certbot\\lib'
            assert cli.flag_default('logs_dir') == 'C:\\Certbot\\log'


def assert_set_by_user_with_value(namespace, attr: str, value: Any):
    assert getattr(namespace, attr) == value
    assert namespace.set_by_user(attr)


def assert_value_and_source(namespace, attr: str, value: Any, source: ArgumentSource):
    assert getattr(namespace, attr) == value
    assert namespace.argument_sources[attr] == source


class ParseTest(unittest.TestCase):
    '''Test the cli args entrypoint'''

    @staticmethod
    def _unmocked_parse(args: List[str]) -> NamespaceConfig:
        """Get result of cli.prepare_and_parse_args."""
        return cli.prepare_and_parse_args(PLUGINS, args)

    @staticmethod
    def parse(args: List[str]) -> NamespaceConfig:
        """Mocks certbot._internal.display.obj.get_display and calls _unmocked_parse."""
        with test_util.patch_display_util():
            return ParseTest._unmocked_parse(args)

    def _help_output(self, args: List[str]):
        "Run a command, and return the output string for scrutiny"

        output = io.StringIO()

        def write_msg(message, *args, **kwargs): # pylint: disable=missing-docstring,unused-argument
            output.write(message)

        with mock.patch('certbot._internal.main.sys.stdout', new=output):
            with test_util.patch_display_util() as mock_get_utility:
                mock_get_utility().notification.side_effect = write_msg
                with mock.patch('certbot._internal.main.sys.stderr'):
                    with pytest.raises(SystemExit):
                        self._unmocked_parse(args)

        return output.getvalue()

    @mock.patch("certbot._internal.cli.helpful.flag_default")
    def test_cli_ini_domains(self, mock_flag_default):
        with tempfile.NamedTemporaryFile() as tmp_config:
            tmp_config.close()  # close now because of compatibility issues on Windows
            # use a shim to get ConfigArgParse to pick up tmp_config
            shim = (
                    lambda v: copy.deepcopy(constants.CLI_DEFAULTS[v])
                    if v != "config_files"
                    else [tmp_config.name]
                    )
            mock_flag_default.side_effect = shim

            namespace = self.parse(["certonly"])
            assert_value_and_source(namespace, 'domains', [], ArgumentSource.DEFAULT)
            with open(tmp_config.name, 'w') as file_h:
                file_h.write("domains = example.com")
            namespace = self.parse(["certonly"])
            assert_value_and_source(namespace, 'domains', ["example.com"], ArgumentSource.CONFIG_FILE)
            namespace = self.parse(["renew"])
            assert_value_and_source(namespace, 'domains', [], ArgumentSource.RUNTIME)

    def test_no_args(self):
        namespace = self.parse([])
        for d in ('config_dir', 'logs_dir', 'work_dir'):
            assert getattr(namespace, d) == cli.flag_default(d)
            assert not namespace.set_by_user(d)

    def test_install_abspath(self):
        cert = 'cert'
        key = 'key'
        chain = 'chain'
        fullchain = 'fullchain'

        with mock.patch('certbot._internal.main.install'):
            namespace = self.parse(['install', '--cert-path', cert,
                                    '--key-path', 'key', '--chain-path',
                                    'chain', '--fullchain-path', 'fullchain'])

        assert namespace.cert_path == os.path.abspath(cert)
        assert namespace.key_path == os.path.abspath(key)
        assert namespace.chain_path == os.path.abspath(chain)
        assert namespace.fullchain_path == os.path.abspath(fullchain)

    def test_help(self):
        self._help_output(['--help'])  # assert SystemExit is raised here
        out = self._help_output(['--help', 'all'])
        assert "--configurator" in out
        assert "how a certificate is deployed" in out
        assert "--webroot-path" in out
        assert "--text" not in out
        assert "%s" not in out
        assert "{0}" not in out
        assert "--renew-hook" not in out

        out = self._help_output(['-h', 'nginx'])
        if "nginx" in PLUGINS:
            # may be false while building distributions without plugins
            assert "--nginx-ctl" in out
        assert "--webroot-path" not in out
        assert "--checkpoints" not in out

        out = self._help_output(['-h'])
        if "nginx" in PLUGINS:
            assert "Use the Nginx plugin" in out
        else:
            assert "(the certbot nginx plugin is not" in out

        out = self._help_output(['--help', 'plugins'])
        assert "--webroot-path" not in out
        assert "--prepare" in out
        assert '"plugins" subcommand' in out

        # test multiple topics
        out = self._help_output(['-h', 'renew'])
        assert "--keep" in out
        out = self._help_output(['-h', 'automation'])
        assert "--keep" in out
        out = self._help_output(['-h', 'revoke'])
        assert "--keep" not in out

        out = self._help_output(['--help', 'install'])
        assert "--cert-path" in out
        assert "--key-path" in out

        out = self._help_output(['--help', 'revoke'])
        assert "--cert-path" in out
        assert "--key-path" in out
        assert "--reason" in out
        assert "--delete-after-revoke" in out
        assert "--no-delete-after-revoke" in out

        out = self._help_output(['-h', 'register'])
        assert "--cert-path" not in out
        assert "--key-path" not in out

        out = self._help_output(['-h'])
        assert cli.SHORT_USAGE in out
        assert cli.COMMAND_OVERVIEW[:100] in out
        assert "%s" not in out
        assert "{0}" not in out

    def test_help_no_dashes(self):
        self._help_output(['help'])  # assert SystemExit is raised here

        out = self._help_output(['help', 'all'])
        assert "--configurator" in out
        assert "how a certificate is deployed" in out
        assert "--webroot-path" in out
        assert "--text" not in out
        assert "%s" not in out
        assert "{0}" not in out

        out = self._help_output(['help', 'install'])
        assert "--cert-path" in out
        assert "--key-path" in out

        out = self._help_output(['help', 'revoke'])
        assert "--cert-path" in out
        assert "--key-path" in out

    def test_parse_domains(self):
        short_args = ['-d', 'example.com']
        namespace = self.parse(short_args)
        assert_set_by_user_with_value(namespace, 'domains', ['example.com'])

        short_args = ['-d', 'trailing.period.com.']
        namespace = self.parse(short_args)
        assert_set_by_user_with_value(namespace, 'domains', ['trailing.period.com'])

        short_args = ['-d', 'example.com,another.net,third.org,example.com']
        namespace = self.parse(short_args)
        assert_set_by_user_with_value(namespace, 'domains',
            ['example.com', 'another.net', 'third.org'])

        long_args = ['--domains', 'example.com']
        namespace = self.parse(long_args)
        assert_set_by_user_with_value(namespace, 'domains', ['example.com'])

        long_args = ['--domains', 'trailing.period.com.']
        namespace = self.parse(long_args)
        assert_set_by_user_with_value(namespace, 'domains', ['trailing.period.com'])

        long_args = ['--domains', 'example.com,another.net,example.com']
        namespace = self.parse(long_args)
        assert_set_by_user_with_value(namespace, 'domains', ['example.com', 'another.net'])

    def test_preferred_challenges(self):
        short_args = ['--preferred-challenges', 'http, dns']
        namespace = self.parse(short_args)

        expected = [challenges.HTTP01.typ, challenges.DNS01.typ]
        assert_set_by_user_with_value(namespace, 'pref_challs', expected)

        short_args = ['--preferred-challenges', 'jumping-over-the-moon']
        # argparse.ArgumentError makes argparse print more information
        # to stderr and call sys.exit()
        with mock.patch('sys.stderr'):
            with pytest.raises(SystemExit):
                self.parse(short_args)

    def test_server_flag(self):
        namespace = self.parse('--server example.com'.split())
        assert_set_by_user_with_value(namespace, 'server', 'example.com')

    def test_must_staple_flag(self):
        namespace = self.parse(['--must-staple'])
        assert_set_by_user_with_value(namespace, 'must_staple', True)
        assert_value_and_source(namespace, 'staple', True, ArgumentSource.RUNTIME)

    def test_must_staple_and_staple_ocsp_flags(self):
        namespace = self.parse(['--must-staple', '--staple-ocsp'])
        assert_set_by_user_with_value(namespace, 'must_staple', True)
        assert_set_by_user_with_value(namespace, 'staple', True)

    def _check_server_conflict_message(self, parser_args, conflicting_args):
        try:
            self.parse(parser_args)
            self.fail(  # pragma: no cover
                "The following flags didn't conflict with "
                '--server: {0}'.format(', '.join(conflicting_args)))
        except errors.Error as error:
            assert '--server' in str(error)
            for arg in conflicting_args:
                assert arg in str(error)

    def test_staging_flag(self):
        short_args = ['--staging']
        namespace = self.parse(short_args)
        assert_set_by_user_with_value(namespace, 'staging', True)
        assert_set_by_user_with_value(namespace, 'server', constants.STAGING_URI)

        short_args += '--server example.com'.split()
        self._check_server_conflict_message(short_args, '--staging')

    def _assert_dry_run_flag_worked(self, namespace, existing_account):
        assert_set_by_user_with_value(namespace, 'dry_run', True)
        assert_value_and_source(namespace, 'break_my_certs', True, ArgumentSource.RUNTIME)
        assert_value_and_source(namespace, 'staging', True, ArgumentSource.RUNTIME)
        assert_value_and_source(namespace, 'server', constants.STAGING_URI, ArgumentSource.RUNTIME)

        if existing_account:
            assert_value_and_source(namespace, 'tos', True, ArgumentSource.RUNTIME)
            assert_value_and_source(namespace, 'register_unsafely_without_email', True, ArgumentSource.RUNTIME)
        else:
            assert_value_and_source(namespace, 'tos', False, ArgumentSource.DEFAULT)
            assert_value_and_source(namespace, 'register_unsafely_without_email', False, ArgumentSource.DEFAULT)

    def test_dry_run_flag(self):
        config_dir = tempfile.mkdtemp()
        short_args = '--dry-run --config-dir {0}'.format(config_dir).split()
        with pytest.raises(errors.Error):
            self.parse(short_args)

        self._assert_dry_run_flag_worked(
            self.parse(short_args + ['auth']), False)
        self._assert_dry_run_flag_worked(
            self.parse(short_args + ['certonly']), False)
        self._assert_dry_run_flag_worked(
            self.parse(short_args + ['renew']), False)

        account_dir = os.path.join(config_dir, constants.ACCOUNTS_DIR)
        filesystem.mkdir(account_dir)
        filesystem.mkdir(os.path.join(account_dir, 'fake_account_dir'))

        self._assert_dry_run_flag_worked(self.parse(short_args + ['auth']), True)
        self._assert_dry_run_flag_worked(self.parse(short_args + ['renew']), True)
        self._assert_dry_run_flag_worked(self.parse(short_args + ['certonly']), True)

        short_args += ['certonly']

        # `--dry-run --server example.com` should emit example.com
        config = self.parse(short_args + ['--server', 'example.com'])
        assert_set_by_user_with_value(config, 'server', 'example.com')

        # `--dry-run --server STAGING_URI` should emit STAGING_URI
        config = self.parse(short_args + ['--server', constants.STAGING_URI])
        assert_set_by_user_with_value(config, 'server', constants.STAGING_URI)

        # `--dry-run --server LIVE` should emit STAGING_URI
        config = self.parse(short_args + ['--server', cli.flag_default("server")])
        assert_value_and_source(config, 'server', constants.STAGING_URI, ArgumentSource.RUNTIME)

        # `--dry-run --server example.com --staging` should emit an error
        conflicts = ['--staging']
        self._check_server_conflict_message(short_args + ['--server', 'example.com', '--staging'],
                                            conflicts)

    def test_user_set_rsa_key_size(self):
        key_size_option = 'rsa_key_size'
        key_size_value = cli.flag_default(key_size_option)
        config = self.parse('--rsa-key-size {0}'.format(key_size_value).split())

        assert config.set_by_user(key_size_option)

        config_dir_option = 'config_dir'
        assert not config.set_by_user(
            config_dir_option)
        assert not config.set_by_user('authenticator')

    def test_user_set_installer_and_authenticator(self):
        config = self.parse('--apache')
        assert config.set_by_user('installer')
        assert config.set_by_user('authenticator')

        config = self.parse('--installer webroot')
        assert config.set_by_user('installer')
        assert not config.set_by_user('authenticator')

    def test_user_set_ecdsa_key_option(self):
        elliptic_curve_option = 'elliptic_curve'
        elliptic_curve_option_value = cli.flag_default(elliptic_curve_option)
        config = self.parse('--elliptic-curve {0}'.format(elliptic_curve_option_value).split())
        assert config.set_by_user(elliptic_curve_option)

    def test_user_set_invalid_key_type(self):
        key_type_option = 'key_type'
        key_type_value = cli.flag_default(key_type_option)
        config = self.parse('--key-type {0}'.format(key_type_value).split())
        assert config.set_by_user(key_type_option)

        with pytest.raises(SystemExit):
            self.parse("--key-type foo")

    @mock.patch('certbot._internal.hooks.validate_hooks')
    def test_user_set_deploy_hook(self, unused_mock_validate_hooks):
        args = 'renew --deploy-hook foo'.split()
        plugins = disco.PluginsRegistry.find_all()
        config = cli.prepare_and_parse_args(plugins, args)
        assert config.set_by_user('renew_hook')

    @mock.patch('certbot._internal.plugins.webroot._validate_webroot')
    def test_user_set_webroot_map(self, mock_validate_webroot):
        args = 'renew -w /var/www/html -d example.com'.split()
        mock_validate_webroot.return_value = '/var/www/html'
        plugins = disco.PluginsRegistry.find_all()
        config = cli.prepare_and_parse_args(plugins, args)
        assert config.set_by_user('webroot_map')

    def test_encode_revocation_reason(self):
        for reason, code in constants.REVOCATION_REASONS.items():
            namespace = self.parse(['--reason', reason])
            assert namespace.reason == code
        for reason, code in constants.REVOCATION_REASONS.items():
            namespace = self.parse(['--reason', reason.upper()])
            assert namespace.reason == code

    def test_force_interactive(self):
        with pytest.raises(errors.Error):
            self.parse("renew --force-interactive".split())
        with pytest.raises(errors.Error):
            self.parse("-n --force-interactive".split())

    def test_deploy_hook_conflict(self):
        with mock.patch("certbot._internal.cli.sys.stderr"):
            with pytest.raises(SystemExit):
                self.parse("--renew-hook foo --deploy-hook bar".split())

    def test_deploy_hook_matches_renew_hook(self):
        value = "foo"
        namespace = self.parse(["--renew-hook", value,
                                "--deploy-hook", value,
                                "--disable-hook-validation"])
        assert_set_by_user_with_value(namespace, 'deploy_hook', value)
        assert_set_by_user_with_value(namespace, 'renew_hook', value)

    def test_deploy_hook_sets_renew_hook(self):
        value = "foo"
        namespace = self.parse(
            ["--deploy-hook", value, "--disable-hook-validation"])
        assert_set_by_user_with_value(namespace, 'deploy_hook', value)
        assert_set_by_user_with_value(namespace, 'renew_hook', value)

    def test_renew_hook_conflict(self):
        with mock.patch("sys.stderr"):
            with pytest.raises(SystemExit):
                self.parse("--deploy-hook foo --renew-hook bar".split())

    def test_renew_hook_matches_deploy_hook(self):
        value = "foo"
        namespace = self.parse(["--deploy-hook", value,
                                "--renew-hook", value,
                                "--disable-hook-validation"])
        assert_set_by_user_with_value(namespace, 'deploy_hook', value)
        assert_set_by_user_with_value(namespace, 'renew_hook', value)

    def test_renew_hook_does_not_set_renew_hook(self):
        value = "foo"
        namespace = self.parse(
            ["--renew-hook", value, "--disable-hook-validation"])
        assert namespace.deploy_hook is None
        assert_set_by_user_with_value(namespace, 'renew_hook', value)

    def test_max_log_backups_error(self):
        with mock.patch('certbot._internal.cli.sys.stderr'):
            with pytest.raises(SystemExit):
                self.parse("--max-log-backups foo".split())
            with pytest.raises(SystemExit):
                self.parse("--max-log-backups -42".split())

    def test_max_log_backups_success(self):
        value = "42"
        namespace = self.parse(["--max-log-backups", value])
        assert_set_by_user_with_value(namespace, 'max_log_backups', int(value))

    def test_unchanging_defaults(self):
        namespace = self.parse([])
        assert_value_and_source(namespace, 'domains', [], ArgumentSource.DEFAULT)
        assert_value_and_source(namespace, 'pref_challs', [], ArgumentSource.DEFAULT)

        namespace.pref_challs = [challenges.HTTP01.typ]
        namespace.domains = ['example.com']

        namespace = self.parse([])
        assert_value_and_source(namespace, 'domains', [], ArgumentSource.DEFAULT)
        assert_value_and_source(namespace, 'pref_challs', [], ArgumentSource.DEFAULT)

    def test_no_directory_hooks_set(self):
        namespace = self.parse(["--no-directory-hooks"])
        assert_set_by_user_with_value(namespace, 'directory_hooks', False)

    def test_no_directory_hooks_unset(self):
        namespace = self.parse([])
        assert_value_and_source(namespace, 'directory_hooks', True, ArgumentSource.DEFAULT)

    def test_delete_after_revoke(self):
        namespace = self.parse(["--delete-after-revoke"])
        assert_set_by_user_with_value(namespace, 'delete_after_revoke', True)

    def test_delete_after_revoke_default(self):
        namespace = self.parse([])
        assert namespace.delete_after_revoke is None
        assert not namespace.set_by_user('delete_after_revoke')

    def test_no_delete_after_revoke(self):
        namespace = self.parse(["--no-delete-after-revoke"])
        assert_set_by_user_with_value(namespace, 'delete_after_revoke', False)

    def test_allow_subset_with_wildcard(self):
        with pytest.raises(errors.Error):
            self.parse("--allow-subset-of-names -d *.example.org".split())

    def test_route53_no_revert(self):
        for help_flag in ['-h', '--help']:
            for topic in ['all', 'plugins', 'dns-route53']:
                assert 'certbot-route53:auth' not in self._help_output([help_flag, topic])

    def test_parse_args_hosts_and_auto_hosts(self):
        with pytest.raises(errors.Error):
            self.parse(['--hsts', '--auto-hsts'])

    def test_parse_with_multiple_argument_sources(self):
        DEFAULT_VALUE = flag_default('server')
        CONFIG_FILE_VALUE = 'configfile.biz'
        COMMAND_LINE_VALUE = 'commandline.edu'

        # check that the default is set
        namespace = self.parse(['certonly'])
        assert_value_and_source(namespace, 'server', DEFAULT_VALUE, ArgumentSource.DEFAULT)

        with tempfile.NamedTemporaryFile() as tmp_config:
            tmp_config.close()  # close now because of compatibility issues on Windows
            with open(tmp_config.name, 'w') as file_h:
                file_h.write(f'server = {CONFIG_FILE_VALUE}')

            # first, just provide a value from a config file
            namespace = self.parse([
                'certonly',
                '-c', tmp_config.name,
            ])
            assert_value_and_source(namespace, 'server', CONFIG_FILE_VALUE, ArgumentSource.CONFIG_FILE)

            # now provide config file + command line values
            namespace = self.parse([
                'certonly',
                '-c', tmp_config.name,
                '--server', COMMAND_LINE_VALUE,
            ])
            assert_value_and_source(namespace, 'server', COMMAND_LINE_VALUE, ArgumentSource.COMMAND_LINE)

    def test_abbreviated_arguments(self):
        # Argparse's "allow_abbrev" option (which is True by default) allows
        # for unambiguous partial arguments (e.g. "--preferred-chal dns" will be
        # interepreted the same as "--preferred-challenges dns")
        namespace = self.parse('--preferred-chal dns --no-dir')
        assert_set_by_user_with_value(namespace, 'pref_challs', ['dns-01'])
        assert_set_by_user_with_value(namespace, 'directory_hooks', False)

        with tempfile.NamedTemporaryFile() as tmp_config:
            tmp_config.close()  # close now because of compatibility issues on Windows
            with open(tmp_config.name, 'w') as file_h:
                file_h.write('preferred-chal = dns')

            namespace = self.parse([
                'certonly',
                '--config', tmp_config.name,
            ])
            assert_set_by_user_with_value(namespace, 'pref_challs', ['dns-01'])

    @mock.patch('certbot._internal.hooks.validate_hooks')
    def test_argument_with_equals(self, unsused_mock_validate_hooks):
        namespace = self.parse('-d=example.com')
        assert_set_by_user_with_value(namespace, 'domains', ['example.com'])

        # make sure it doesn't choke on equals signs being present in the argument value
        plugins = disco.PluginsRegistry.find_all()
        namespace = cli.prepare_and_parse_args(plugins, ['run', '--pre-hook="foo=bar"'])
        assert_set_by_user_with_value(namespace, 'pre_hook', '"foo=bar"')

    def test_adjacent_short_args(self):
        namespace = self.parse('-tv')
        assert_set_by_user_with_value(namespace, 'text_mode', True)
        assert_set_by_user_with_value(namespace, 'verbose_count', 1)

        namespace = self.parse('-tvvv')
        assert_set_by_user_with_value(namespace, 'text_mode', True)
        assert_set_by_user_with_value(namespace, 'verbose_count', 3)

        namespace = self.parse('-tvm foo@example.com')
        assert_set_by_user_with_value(namespace, 'text_mode', True)
        assert_set_by_user_with_value(namespace, 'verbose_count', 1)
        assert_set_by_user_with_value(namespace, 'email', 'foo@example.com')

    def test_arg_with_contained_spaces(self):
        # This can happen if a user specifies an arg like "-d foo.com" enclosed
        # in double quotes, or as its own line in a docker-compose.yml file (as
        # in #9811)
        namespace = self.parse(['certonly', '-d foo.com'])
        assert_set_by_user_with_value(namespace, 'domains', ['foo.com'])

if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
