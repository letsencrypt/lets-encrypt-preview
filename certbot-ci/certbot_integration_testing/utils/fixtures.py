import os
import subprocess
import tempfile
import shutil

import pytest

from certbot_integration_testing.utils.misc import find_certbot_executable, find_certbot_sources


@pytest.fixture(scope='session')
def acme_url():
    integration = os.environ.get('CERTBOT_INTEGRATION')

    if integration == 'boulder-v1':
        return 'http://localhost:4000/directory'
    if integration == 'boulder-v2':
        return 'http://localhost:4001/directory'
    if integration == 'pebble' or integration == 'pebble-strict':
        return 'https://localhost:14000/dir'

    raise ValueError('Invalid CERTBOT_INTEGRATION value')


@pytest.fixture(scope='session')
def workspace():
    workspace = tempfile.mkdtemp()
    try:
        yield workspace
    finally:
        shutil.rmtree(workspace)


@pytest.fixture(scope='session')
def config_dir(workspace):
    return os.path.join(workspace, 'conf')


@pytest.fixture(scope='session')
def work_dir(workspace):
    return os.path.join(workspace, 'work')


@pytest.fixture(scope='session')
def renewal_hooks_dirs(config_dir):
    renewal_hooks_root = os.path.join(config_dir, 'renewal-hooks')
    return [os.path.join(renewal_hooks_root, item) for item in ['pre', 'deploy', 'post']]


@pytest.fixture(scope='session')
def tls_sni_01_port():
    return 5001


@pytest.fixture(scope='session')
def http_01_port():
    return 5002


@pytest.fixture(scope='session')
def certbot_test_no_force_renew(config_dir, work_dir, acme_url):
    certbot = find_certbot_executable()
    sources = find_certbot_sources()
    omit_patterns = (
        '*/*.egg-info/*,*/dns_common*,*/setup.py,*/test_*,*/tests/*,'
        '$omit_patterns,*_test.py,*_test_*,certbot-apache/*,'
        '$omit_patterns,certbot-compatibility-test/*,certbot-dns*/,'
        '$omit_patterns,certbot-nginx/certbot_nginx/parser_obj.py'
    )

    def func(args):
        command = [
            'coverage', 'run', '--append', '--source', ','.join(sources), '--omit', omit_patterns,
            certbot, '--server', acme_url, '--no-verify-ssl', '--tls-sni-01-port', '5001',
            '--http-01-port', '5002', '--manual-public-ip-logging-ok', '--config-dir',
            config_dir, '--work-dir', work_dir, '--non-interactive', '--no-redirect',
            '--agree-tos', '--register-unsafely-without-email', '--debug', '-vv'
        ]

        command.extend(args)

        print('Invoke command:\n{0}'.format(subprocess.list2cmdline(command)))
        subprocess.check_call(command)

    return func


@pytest.fixture(scope='session')
def certbot_test(certbot_test_no_force_renew):
    def func(args):
        command = ['--renew-by-default']
        command.extend(args)
        certbot_test_no_force_renew(command)

    return func
