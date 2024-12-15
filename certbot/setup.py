import codecs
import os
import re

from setuptools import find_packages
from setuptools import setup

def read_file(filename, encoding='utf8'):
    """Read unicode from given file."""
    with codecs.open(filename, encoding=encoding) as fd:
        return fd.read()


here = os.path.abspath(os.path.dirname(__file__))

# read version number (and other metadata) from package init
init_fn = os.path.join(here, 'certbot', '__init__.py')
meta = dict(re.findall(r"""__([a-z]+)__ = '([^']+)""", read_file(init_fn)))

readme = read_file(os.path.join(here, 'README.rst'))
version = meta['version']

# This package relies on PyOpenSSL and requests, however, it isn't specified
# here to avoid masking the more specific request requirements in acme. See
# https://github.com/pypa/pip/issues/988 for more info.
install_requires = [
    # We specify the minimum acme version as the current Certbot version for
    # simplicity. See https://github.com/certbot/certbot/issues/8761 for more
    # info.
    f'acme>={version}',
    'ConfigArgParse>=1.5.3',
    'configobj>=5.0.6',
    'cryptography>=3.2.1',
    'distro>=1.0.1',
    'importlib_resources>=1.3.1; python_version < "3.9"',
    'importlib_metadata>=4.6; python_version < "3.10"',
    # Josepy 2+ may introduce backward incompatible changes by droping usage of
    # deprecated PyOpenSSL APIs.
    'josepy>=1.13.0, <2',
    'parsedatetime>=2.4',
    'pyrfc3339',
    'pytz>=2019.3',
    # This dependency needs to be added using environment markers to avoid its
    # installation on Linux.
    'pywin32>=300 ; sys_platform == "win32"',
]

dev_extras = [
    'azure-devops',
    'ipdb',
    # poetry 1.2.0+ is required for it to pin pip, setuptools, and wheel. See
    # https://github.com/python-poetry/poetry/issues/1584.
    'poetry>=1.2.0',
    # poetry-plugin-export>=1.1.0 is required to use the constraints.txt export
    # format. See
    # https://github.com/python-poetry/poetry-plugin-export/blob/efcfd34859e72f6a79a80398f197ce6eb2bbd7cd/CHANGELOG.md#added.
    'poetry-plugin-export>=1.1.0',
    'twine',
]

docs_extras = [
    # If you have Sphinx<1.5.1, you need docutils<0.13.1
    # https://github.com/sphinx-doc/sphinx/issues/3212
    'Sphinx>=1.2',  # Annotation support
    'sphinx_rtd_theme',
]

# Tools like pip, wheel, and tox are listed here to ensure they are properly
# pinned and installed during automated testing.
test_extras = [
    'coverage',
    'mypy',
    'pip',
    'pylint',
    'pytest',
    'pytest-cov',
    'pytest-xdist',
    'setuptools',
    'tox',
    'types-httplib2',
    'types-pyOpenSSL',
    'types-pyRFC3339',
    'types-pytz',
    'types-pywin32',
    'types-requests',
    'types-setuptools',
    'wheel',
]


all_extras = dev_extras + docs_extras + test_extras

setup(
    name='certbot',
    version=version,
    description="ACME client",
    long_description=readme,
    url='https://github.com/certbot/certbot',
    author="Certbot Project",
    author_email='certbot-dev@eff.org',
    license='Apache License 2.0',
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Environment :: Console :: Curses',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],

    packages=find_packages(exclude=['docs', 'examples', 'tests', 'venv']),
    include_package_data=True,

    install_requires=install_requires,
    extras_require={
        'all': all_extras,
        'dev': dev_extras,
        'docs': docs_extras,
        'test': test_extras,
    },

    entry_points={
        'console_scripts': [
            'certbot = certbot.main:main',
        ],
        'certbot.plugins': [
            'manual = certbot._internal.plugins.manual:Authenticator',
            'null = certbot._internal.plugins.null:Installer',
            'standalone = certbot._internal.plugins.standalone:Authenticator',
            'webroot = certbot._internal.plugins.webroot:Authenticator',
        ],
    },
)
