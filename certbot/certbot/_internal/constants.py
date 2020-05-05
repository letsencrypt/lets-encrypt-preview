"""Certbot constants."""
import logging

import distutils.version
import pkg_resources

from acme import challenges
from certbot.compat import misc
from certbot.compat import os

SETUPTOOLS_PLUGINS_ENTRY_POINT = "certbot.plugins"
"""Setuptools entry point group name for plugins."""

OLD_SETUPTOOLS_PLUGINS_ENTRY_POINT = "letsencrypt.plugins"
"""Plugins Setuptools entry point before rename."""

CLI_DEFAULTS = dict(
    config_files=[
        os.path.join(misc.get_default_folder('config'), 'cli.ini'),
        # http://freedesktop.org/wiki/Software/xdg-user-dirs/
        os.path.join(os.environ.get("XDG_CONFIG_HOME", "~/.config"),
                     "letsencrypt", "cli.ini"),
    ],

    # Main parser
    verbose_count=-int(logging.INFO / 10),
    text_mode=False,
    max_log_backups=1000,
    noninteractive_mode=False,
    force_interactive=False,
    domains=[],
    certname=None,
    dry_run=False,
    register_unsafely_without_email=False,
    email=None,
    eff_email=None,
    reinstall=False,
    expand=False,
    renew_by_default=False,
    renew_with_new_domains=False,
    autorenew=True,
    allow_subset_of_names=False,
    tos=False,
    account=None,
    duplicate=False,
    os_packages_only=False,
    no_self_upgrade=False,
    no_permissions_check=False,
    no_bootstrap=False,
    quiet=False,
    staging=False,
    debug=False,
    debug_challenges=False,
    no_verify_ssl=False,
    http01_port=challenges.HTTP01Response.PORT,
    http01_address="",
    https_port=443,
    break_my_certs=False,
    rsa_key_size=2048,
    must_staple=False,
    redirect=None,
    auto_hsts=False,
    hsts=None,
    uir=None,
    staple=None,
    strict_permissions=False,
    pref_challs=[],
    validate_hooks=True,
    directory_hooks=True,
    reuse_key=False,
    disable_renew_updates=False,
    random_sleep_on_renew=True,
    eab_hmac_key=None,
    eab_kid=None,

    # Subparsers
    num=None,
    user_agent=None,
    user_agent_comment=None,
    csr=None,
    reason=0,
    delete_after_revoke=None,
    rollback_checkpoints=1,
    init=False,
    prepare=False,
    ifaces=None,

    # Path parsers
    auth_cert_path="./cert.pem",
    auth_chain_path="./chain.pem",
    key_path=None,
    config_dir=misc.get_default_folder('config'),
    work_dir=misc.get_default_folder('work'),
    logs_dir=misc.get_default_folder('logs'),
    server="https://acme-v02.api.letsencrypt.org/directory",

    # Plugins parsers
    configurator=None,
    authenticator=None,
    installer=None,
    apache=False,
    nginx=False,
    standalone=False,
    manual=False,
    webroot=False,
    dns_cloudflare=False,
    dns_cloudxns=False,
    dns_digitalocean=False,
    dns_dnsimple=False,
    dns_dnsmadeeasy=False,
    dns_gehirn=False,
    dns_google=False,
    dns_linode=False,
    dns_luadns=False,
    dns_nsone=False,
    dns_ovh=False,
    dns_rfc2136=False,
    dns_route53=False,
    dns_sakuracloud=False

)
STAGING_URI = "https://acme-staging-v02.api.letsencrypt.org/directory"

# The set of reasons for revoking a certificate is defined in RFC 5280 in
# section 5.3.1. The reasons that users are allowed to submit are restricted to
# those accepted by the ACME server implementation. They are listed in
# `letsencrypt.boulder.revocation.reasons.go`.
REVOCATION_REASONS = {
    "unspecified": 0,
    "keycompromise": 1,
    "affiliationchanged": 3,
    "superseded": 4,
    "cessationofoperation": 5}

"""Defaults for CLI flags and `.IConfig` attributes."""

QUIET_LOGGING_LEVEL = logging.WARNING
"""Logging level to use in quiet mode."""

RENEWER_DEFAULTS = dict(
    renewer_enabled="yes",
    renew_before_expiry="30 days",
    # This value should ensure that there is never a deployment delay by
    # default.
    deploy_before_expiry="99 years",
)
"""Defaults for renewer script."""

ARCHIVE_DIR = "archive"
"""Archive directory, relative to `IConfig.config_dir`."""

CONFIG_DIRS_MODE = 0o755
"""Directory mode for ``.IConfig.config_dir`` et al."""

ACCOUNTS_DIR = "accounts"
"""Directory where all accounts are saved."""

LE_REUSE_SERVERS = {
    os.path.normpath('acme-v02.api.letsencrypt.org/directory'):
        os.path.normpath('acme-v01.api.letsencrypt.org/directory'),
    os.path.normpath('acme-staging-v02.api.letsencrypt.org/directory'):
        os.path.normpath('acme-staging.api.letsencrypt.org/directory')
}
"""Servers that can reuse accounts from other servers."""

BACKUP_DIR = "backups"
"""Directory (relative to `IConfig.work_dir`) where backups are kept."""

CSR_DIR = "csr"
"""See `.IConfig.csr_dir`."""

IN_PROGRESS_DIR = "IN_PROGRESS"
"""Directory used before a permanent checkpoint is finalized (relative to
`IConfig.work_dir`)."""

KEY_DIR = "keys"
"""Directory (relative to `IConfig.config_dir`) where keys are saved."""

LIVE_DIR = "live"
"""Live directory, relative to `IConfig.config_dir`."""

TEMP_CHECKPOINT_DIR = "temp_checkpoint"
"""Temporary checkpoint directory (relative to `IConfig.work_dir`)."""

RENEWAL_CONFIGS_DIR = "renewal"
"""Renewal configs directory, relative to `IConfig.config_dir`."""

RENEWAL_HOOKS_DIR = "renewal-hooks"
"""Basename of directory containing hooks to run with the renew command."""

RENEWAL_PRE_HOOKS_DIR = "pre"
"""Basename of directory containing pre-hooks to run with the renew command."""

RENEWAL_DEPLOY_HOOKS_DIR = "deploy"
"""Basename of directory containing deploy-hooks to run with the renew command."""

RENEWAL_POST_HOOKS_DIR = "post"
"""Basename of directory containing post-hooks to run with the renew command."""

FORCE_INTERACTIVE_FLAG = "--force-interactive"
"""Flag to disable TTY checking in IDisplay."""

EFF_SUBSCRIBE_URI = "https://supporters.eff.org/subscribe/certbot"
"""EFF URI used to submit the e-mail address of users who opt-in."""

SSL_DHPARAMS_DEST = "ssl-dhparams.pem"
"""Name of the ssl_dhparams file as saved in `IConfig.config_dir`."""

SSL_DHPARAMS_SRC = pkg_resources.resource_filename(
    "certbot", "ssl-dhparams.pem")
"""Path to the nginx ssl_dhparams file found in the Certbot distribution."""

UPDATED_SSL_DHPARAMS_DIGEST = ".updated-ssl-dhparams-pem-digest.txt"
"""Name of the hash of the updated or informed ssl_dhparams as saved in `IConfig.config_dir`."""

ALL_SSL_DHPARAMS_HASHES = [
    '9ba6429597aeed2d8617a7705b56e96d044f64b07971659382e426675105654b',
]
"""SHA256 hashes of the contents of all versions of SSL_DHPARAMS_SRC"""

PKFC_VERSION = distutils.version.StrictVersion('1.4.0a1')
"""Version of certbot that introduced the privkey_fullchain lineage item."""
