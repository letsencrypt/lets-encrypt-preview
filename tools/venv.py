#!/usr/bin/env python
# Developer virtualenv setup for Certbot client
import os

import _venv_common

REQUIREMENTS = [
    '-e acme[dev]',
    '-e .[dev,docs]',
    '-e certbot-apache',
    '-e certbot-dns-bookmyname',
    '-e certbot-dns-cloudflare',
    '-e certbot-dns-cloudxns',
    '-e certbot-dns-digitalocean',
    '-e certbot-dns-dnsimple',
    '-e certbot-dns-dnsmadeeasy',
    '-e certbot-dns-gehirn',
    '-e certbot-dns-google',
    '-e certbot-dns-linode',
    '-e certbot-dns-luadns',
    '-e certbot-dns-nsone',
    '-e certbot-dns-ovh',
    '-e certbot-dns-rfc2136',
    '-e certbot-dns-route53',
    '-e certbot-dns-sakuracloud',
    '-e certbot-nginx',
    '-e certbot-postfix',
    '-e letshelp-certbot',
    '-e certbot-compatibility-test',
]


def main():
    if os.name == 'nt':
        raise ValueError('Certbot for Windows is not supported on Python 2.x.')

    venv_args = '--python "{0}"'.format(_venv_common.find_python_executable(2))
    _venv_common.main('venv', venv_args, REQUIREMENTS)


if __name__ == '__main__':
    main()
