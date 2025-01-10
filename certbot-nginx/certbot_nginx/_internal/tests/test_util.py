"""Common utilities for certbot_nginx."""
import copy
import importlib.resources
import shutil
import tempfile
from contextlib import contextmanager
from unittest import mock

import josepy as jose

from certbot import util
from certbot.compat import os
from certbot.plugins import common
from certbot.tests import util as test_util
from certbot_nginx._internal import configurator
from certbot_nginx._internal import nginxparser


class NginxTest(test_util.ConfigTestCase):

    def setUp(self):
        super().setUp()

        self.configuration = self.config
        self.config = None

        self.temp_dir, self.config_dir, self.work_dir = common.dir_setup(
            "etc_nginx", __package__)
        self.logs_dir = tempfile.mkdtemp('logs')

        self.config_path = os.path.join(self.temp_dir, "etc_nginx")

        self.rsa512jwk = jose.JWKRSA.load(test_util.load_vector(
            "rsa512_key.pem"))

    def tearDown(self):
        # Cleanup opened resources after a test. This is usually done through atexit handlers in
        # Certbot, but during tests, atexit will not run registered functions before tearDown is
        # called and instead will run them right before the entire test process exits.
        # It is a problem on Windows, that does not accept to clean resources before closing them.
        util._release_locks()  # pylint: disable=protected-access

        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)
        shutil.rmtree(self.logs_dir)

    def get_nginx_configurator(self, config_path, config_dir, work_dir, logs_dir,
            version=(1, 6, 2), openssl_version="1.0.2g"):
        """Create an Nginx Configurator with the specified options."""

        backups = os.path.join(work_dir, "backups")

        self.configuration.nginx_server_root = config_path
        self.configuration.nginx_sleep_seconds = 0.1234
        self.configuration.le_vhost_ext = "-le-ssl.conf"
        self.configuration.config_dir = config_dir
        self.configuration.work_dir = work_dir
        self.configuration.logs_dir = logs_dir
        self.configuration.backup_dir = backups
        self.configuration.temp_checkpoint_dir = os.path.join(work_dir, "temp_checkpoints")
        self.configuration.in_progress_dir = os.path.join(backups, "IN_PROGRESS")
        self.configuration.server = "https://acme-server.org:443/new"
        self.configuration.http01_port = 80
        self.configuration.https_port = 5001

        with mock.patch("certbot_nginx._internal.configurator.NginxConfigurator."
                        "config_test"):
            with mock.patch("certbot_nginx._internal.configurator.util."
                            "exe_exists") as mock_exe_exists:
                mock_exe_exists.return_value = True
                config = configurator.NginxConfigurator(
                    self.configuration,
                    name="nginx",
                    version=version,
                    openssl_version=openssl_version)
                config.prepare()

        return config


@contextmanager
def get_data_filename(filename):
    """Gets the filename of a test data file."""
    ref = importlib.resources.files(__package__) / "testdata" / "etc_nginx"/ filename
    with importlib.resources.as_file(ref) as path:
        yield path


def filter_comments(tree):
    """Filter comment nodes from parsed configurations."""

    def traverse(tree):
        """Generator dropping comment nodes"""
        for entry in tree:
            # key, values = entry
            spaceless = [e for e in entry if not nginxparser.spacey(e)]
            if spaceless:
                key = spaceless[0]
                values = spaceless[1] if len(spaceless) > 1 else None
            else:
                key = values = ""
            if isinstance(key, list):
                new = copy.deepcopy(entry)
                new[1] = filter_comments(values)
                yield new
            else:
                if key != '#' and spaceless:
                    yield spaceless

    return list(traverse(tree))


def contains_at_depth(haystack, needle, n):
    """Is the needle in haystack at depth n?

    Return true if the needle is present in one of the sub-iterables in haystack
    at depth n. Haystack must be an iterable.
    """
    # Specifically use hasattr rather than isinstance(..., collections.Iterable)
    # because we want to include lists but reject strings.
    if not hasattr(haystack, '__iter__') or hasattr(haystack, 'strip'):
        return False
    if n == 0:
        return needle in haystack
    for item in haystack:
        if contains_at_depth(item, needle, n - 1):
            return True
    return False
