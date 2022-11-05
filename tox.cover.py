#!/usr/bin/env python
from __future__ import print_function

import argparse
import os
import subprocess
import sys

DEFAULT_PACKAGES = [
    'certbot', 'acme', 'certbot_apache', 'certbot_access_server', 'certbot_dns_cloudflare', 'certbot_dns_cloudxns',
    'certbot_dns_digitalocean', 'certbot_dns_dnsimple', 'certbot_dns_dnsmadeeasy',
    'certbot_dns_gehirn', 'certbot_dns_google', 'certbot_dns_linode', 'certbot_dns_luadns',
    'certbot_dns_nsone', 'certbot_dns_ovh', 'certbot_dns_rfc2136', 'certbot_dns_route53',
    'certbot_dns_sakuracloud', 'certbot_nginx']

COVER_THRESHOLDS = {
    'certbot': {'linux': 94, 'windows': 96},
    'acme': {'linux': 100, 'windows': 99},
    'certbot_apache': {'linux': 100, 'windows': 100},
    'certbot_access_server': {'linux': 94, 'windows': 94},
    'certbot_dns_cloudflare': {'linux': 98, 'windows': 98},
    'certbot_dns_cloudxns': {'linux': 98, 'windows': 98},
    'certbot_dns_digitalocean': {'linux': 98, 'windows': 98},
    'certbot_dns_dnsimple': {'linux': 98, 'windows': 98},
    'certbot_dns_dnsmadeeasy': {'linux': 99, 'windows': 99},
    'certbot_dns_gehirn': {'linux': 97, 'windows': 97},
    'certbot_dns_google': {'linux': 99, 'windows': 99},
    'certbot_dns_linode': {'linux': 98, 'windows': 98},
    'certbot_dns_luadns': {'linux': 98, 'windows': 98},
    'certbot_dns_nsone': {'linux': 99, 'windows': 99},
    'certbot_dns_ovh': {'linux': 97, 'windows': 97},
    'certbot_dns_rfc2136': {'linux': 99, 'windows': 99},
    'certbot_dns_route53': {'linux': 92, 'windows': 92},
    'certbot_dns_sakuracloud': {'linux': 97, 'windows': 97},
    'certbot_nginx': {'linux': 97, 'windows': 97},
}

SKIP_PROJECTS_ON_WINDOWS = ['certbot-apache', 'certbot-access-server']


def cover(package):
    threshold = COVER_THRESHOLDS.get(package)['windows' if os.name == 'nt' else 'linux']

    pkg_dir = package.replace('_', '-')

    if os.name == 'nt' and pkg_dir in SKIP_PROJECTS_ON_WINDOWS:
        print((
            'Info: currently {0} is not supported on Windows and will not be tested/covered.'
            .format(pkg_dir)))
        return

    subprocess.check_call([sys.executable, '-m', 'pytest',
                           '--cov', pkg_dir, '--cov-append', '--cov-report=', pkg_dir])
    try:
        subprocess.check_call([
            sys.executable, '-m', 'coverage', 'report', '--fail-under',
            str(threshold), '--include', '{0}/*'.format(pkg_dir),
            '--show-missing'])
    except subprocess.CalledProcessError as err:
        print(err)
        print('Test coverage on', pkg_dir,
              'did not meet threshold of {0}%.'.format(threshold))
        sys.exit(1)


def main():
    description = """
This script is used by tox.ini (and thus by Travis CI and Azure Pipelines) in
order to generate separate stats for each package. It should be removed once
those packages are moved to a separate repo."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--packages', nargs='+')

    args = parser.parse_args()

    packages = args.packages or DEFAULT_PACKAGES

    # --cov-append is on, make sure stats are correct
    try:
        os.remove('.coverage')
    except OSError:
        pass

    for package in packages:
        cover(package)


if __name__ == '__main__':
    main()
