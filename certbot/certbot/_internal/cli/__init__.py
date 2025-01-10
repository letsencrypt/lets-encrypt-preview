"""Certbot command line argument & config processing."""
# pylint: disable=too-many-lines
import argparse
import logging.handlers
import sys  # noqa
from typing import Any
from typing import List
from typing import Optional
from typing import Type

import certbot
from certbot.configuration import NamespaceConfig
from certbot._internal import constants
from certbot._internal.cli.cli_constants import ARGPARSE_PARAMS_TO_REMOVE
from certbot._internal.cli.cli_constants import cli_command
from certbot._internal.cli.cli_constants import COMMAND_OVERVIEW
from certbot._internal.cli.cli_constants import DEPRECATED_OPTIONS
from certbot._internal.cli.cli_constants import EXIT_ACTIONS
from certbot._internal.cli.cli_constants import HELP_AND_VERSION_USAGE
from certbot._internal.cli.cli_constants import SHORT_USAGE
from certbot._internal.cli.cli_constants import VAR_MODIFIERS
from certbot._internal.cli.cli_constants import ZERO_ARG_ACTIONS
from certbot._internal.cli.cli_utils import _DeployHookAction
from certbot._internal.cli.cli_utils import _DomainsAction
from certbot._internal.cli.cli_utils import _EncodeReasonAction
from certbot._internal.cli.cli_utils import _PrefChallAction
from certbot._internal.cli.cli_utils import _RenewHookAction
from certbot._internal.cli.cli_utils import _user_agent_comment_type
from certbot._internal.cli.cli_utils import add_domains
from certbot._internal.cli.cli_utils import CaseInsensitiveList
from certbot._internal.cli.cli_utils import config_help
from certbot._internal.cli.cli_utils import CustomHelpFormatter
from certbot._internal.cli.cli_utils import flag_default
from certbot._internal.cli.cli_utils import HelpfulArgumentGroup
from certbot._internal.cli.cli_utils import nonnegative_int
from certbot._internal.cli.cli_utils import parse_preferred_challenges
from certbot._internal.cli.cli_utils import read_file
from certbot._internal.cli.cli_utils import set_test_server_options
from certbot._internal.cli.group_adder import _add_all_groups
from certbot._internal.cli.helpful import HelpfulArgumentParser
from certbot._internal.cli.paths_parser import _paths_parser
from certbot._internal.cli.plugins_parsing import _plugins_parsing
from certbot._internal.cli.subparsers import _create_subparsers
from certbot._internal.cli.verb_help import VERB_HELP
from certbot._internal.cli.verb_help import VERB_HELP_MAP
from certbot._internal.plugins import disco as plugins_disco
import certbot._internal.plugins.selection as plugin_selection  # noqa

from certbot.plugins import enhancements

logger = logging.getLogger(__name__)


# Global, to save us from a lot of argument passing within the scope of this module
helpful_parser: Optional[HelpfulArgumentParser] = None


def prepare_and_parse_args(plugins: plugins_disco.PluginsRegistry, args: List[str]
                           ) -> NamespaceConfig:
    """Returns parsed command line arguments.

    :param .PluginsRegistry plugins: available plugins
    :param list args: command line arguments with the program name removed

    :returns: parsed command line arguments
    :rtype: configuration.NamespaceConfig

    """

    helpful = HelpfulArgumentParser(args, plugins)
    _add_all_groups(helpful)

    # --help is automatically provided by argparse
    helpful.add(
        None, "-v", "--verbose", dest="verbose_count", action="count",
        default=flag_default("verbose_count"), help="This flag can be used "
        "multiple times to incrementally increase the verbosity of output, "
        "e.g. -vvv.")
    # This is for developers to set the level in the cli.ini, and overrides
    # the --verbose flag
    helpful.add(
        None, "--verbose-level", dest="verbose_level",
        default=flag_default("verbose_level"), help=argparse.SUPPRESS)
    helpful.add(
        None, "-t", "--text", dest="text_mode", action="store_true",
        default=flag_default("text_mode"), help=argparse.SUPPRESS)
    helpful.add(
        None, "--max-log-backups", type=nonnegative_int,
        default=flag_default("max_log_backups"),
        help="Specifies the maximum number of backup logs that should "
             "be kept by Certbot's built in log rotation. Setting this "
             "flag to 0 disables log rotation entirely, causing "
             "Certbot to always append to the same log file.")
    helpful.add(
        None, "--preconfigured-renewal", dest="preconfigured_renewal",
        action="store_true", default=flag_default("preconfigured_renewal"),
        help=argparse.SUPPRESS
    )
    helpful.add(
        [None, "automation", "run", "certonly", "enhance"],
        "-n", "--non-interactive", "--noninteractive",
        dest="noninteractive_mode", action="store_true",
        default=flag_default("noninteractive_mode"),
        help="Run without ever asking for user input. This may require "
              "additional command line flags; the client will try to explain "
              "which ones are required if it finds one missing")
    helpful.add(
        [None, "register", "run", "certonly", "enhance"],
        constants.FORCE_INTERACTIVE_FLAG, action="store_true",
        default=flag_default("force_interactive"),
        help="Force Certbot to be interactive even if it detects it's not "
             "being run in a terminal. This flag cannot be used with the "
             "renew subcommand.")
    helpful.add(
        [None, "run", "certonly", "certificates", "enhance"],
        "-d", "--domains", "--domain", dest="domains",
        metavar="DOMAIN", action=_DomainsAction,
        default=flag_default("domains"),
        help="Domain names to include. For multiple domains you can use multiple -d flags "
             "or enter a comma separated list of domains as a parameter. All domains will "
             "be included as Subject Alternative Names on the certificate. The first domain "
             "will be used as the certificate name, unless otherwise specified or if you "
             "already have a certificate with the same name. In the case of a name conflict, "
             "a number like -0001 will be appended to the certificate name. (default: Ask)")
    helpful.add(
        [None, "run", "certonly", "register"],
        "--eab-kid", dest="eab_kid",
        metavar="EAB_KID",
        help="Key Identifier for External Account Binding"
    )
    helpful.add(
        [None, "run", "certonly", "register"],
        "--eab-hmac-key", dest="eab_hmac_key",
        metavar="EAB_HMAC_KEY",
        help="HMAC key for External Account Binding"
    )
    helpful.add(
        [None, "run", "certonly", "manage", "delete", "certificates",
         "renew", "enhance", "reconfigure"], "--cert-name", dest="certname",
        metavar="CERTNAME", default=flag_default("certname"),
        help="Certificate name to apply. This name is used by Certbot for housekeeping "
             "and in file paths; it doesn't affect the content of the certificate itself. "
             "Certificate name cannot contain filepath separators (i.e. '/' or '\\', depending "
             "on the platform). "
             "To see certificate names, run 'certbot certificates'. "
             "When creating a new certificate, specifies the new certificate's name. "
             "(default: the first provided domain or the name of an existing "
             "certificate on your system for the same domains)")
    helpful.add(
        [None, "testing", "renew", "certonly"],
        "--dry-run", action="store_true", dest="dry_run",
        default=flag_default("dry_run"),
        help="Perform a test run against the Let's Encrypt staging server, obtaining test"
             " (invalid) certificates but not saving them to disk. This can only be used with the"
             " 'certonly' and 'renew' subcommands. It may trigger webserver reloads to "
             " temporarily modify & roll back configuration files."
             " --pre-hook and --post-hook commands run by default."
             " --deploy-hook commands do not run, unless enabled by --run-deploy-hooks."
             " The test server may be overridden with --server.")
    helpful.add(
        ["testing", "renew", "certonly", "reconfigure"],
        "--run-deploy-hooks", action="store_true", dest="run_deploy_hooks",
        default=flag_default("run_deploy_hooks"),
        help="When performing a test run using `--dry-run` or `reconfigure`, run any applicable"
             " deploy hooks. This includes hooks set on the command line, saved in the"
             " certificate's renewal configuration file, or present in the renewal-hooks directory."
             " To exclude directory hooks, use --no-directory-hooks. The hook(s) will only"
             " be run if the dry run succeeds, and will use the current active certificate, not"
             " the temporary test certificate acquired during the dry run. This flag is recommended"
             " when modifying the deploy hook using `reconfigure`.")
    helpful.add(
        ["register", "automation"], "--register-unsafely-without-email", action="store_true",
        default=flag_default("register_unsafely_without_email"),
        help="Specifying this flag enables registering an account with no "
             "email address. This is strongly discouraged, because you will be "
             "unable to receive notice about impending expiration or "
             "revocation of your certificates or problems with your Certbot "
             "installation that will lead to failure to renew.")
    helpful.add(
        ["register", "update_account", "unregister", "automation"], "-m", "--email",
        default=flag_default("email"),
        help=config_help("email"))
    helpful.add(["register", "update_account", "automation"], "--eff-email", action="store_true",
                default=flag_default("eff_email"), dest="eff_email",
                help="Share your e-mail address with EFF")
    helpful.add(["register", "update_account", "automation"], "--no-eff-email",
                action="store_false", default=flag_default("eff_email"), dest="eff_email",
                help="Don't share your e-mail address with EFF")
    helpful.add(
        ["automation", "certonly", "run"],
        "--keep-until-expiring", "--keep", "--reinstall",
        dest="reinstall", action="store_true", default=flag_default("reinstall"),
        help="If the requested certificate matches an existing certificate, always keep the "
             "existing one until it is due for renewal (for the "
             "'run' subcommand this means reinstall the existing certificate). (default: Ask)")
    helpful.add(
        "automation", "--expand", action="store_true", default=flag_default("expand"),
        help="If an existing certificate is a strict subset of the requested names, "
             "always expand and replace it with the additional names. (default: Ask)")
    helpful.add(
        "automation", "--version", action="version",
        version="%(prog)s {0}".format(certbot.__version__),
        help="show program's version number and exit")
    helpful.add(
        ["automation", "renew"],
        "--force-renewal", "--renew-by-default", dest="renew_by_default",
        action="store_true", default=flag_default("renew_by_default"),
        help="If a certificate "
             "already exists for the requested domains, renew it now, "
             "regardless of whether it is near expiry. (Often "
             "--keep-until-expiring is more appropriate). Also implies "
             "--expand.")
    helpful.add(
        "automation", "--renew-with-new-domains", dest="renew_with_new_domains",
        action="store_true", default=flag_default("renew_with_new_domains"),
        help="If a "
             "certificate already exists for the requested certificate name "
             "but does not match the requested domains, renew it now, "
             "regardless of whether it is near expiry.")
    helpful.add(
        "automation", "--reuse-key", dest="reuse_key",
        action="store_true", default=flag_default("reuse_key"),
        help="When renewing, use the same private key as the existing "
             "certificate.")
    helpful.add(
        "automation", "--no-reuse-key", dest="reuse_key",
        action="store_false", default=flag_default("reuse_key"),
        help="When renewing, do not use the same private key as the existing "
             "certificate. Not reusing private keys is the default behavior of "
             "Certbot. This option may be used to unset --reuse-key on an "
             "existing certificate.")
    helpful.add(
        "automation", "--new-key",
        dest="new_key", action="store_true", default=flag_default("new_key"),
        help="When renewing or replacing a certificate, generate a new private key, "
             "even if --reuse-key is set on the existing certificate. Combining "
             "--new-key and --reuse-key will result in the private key being replaced and "
             "then reused in future renewals.")

    helpful.add(
        ["automation", "renew", "certonly"],
        "--allow-subset-of-names", action="store_true",
        default=flag_default("allow_subset_of_names"),
        help="When performing domain validation, do not consider it a failure "
             "if authorizations can not be obtained for a strict subset of "
             "the requested domains. This may be useful for allowing renewals for "
             "multiple domains to succeed even if some domains no longer point "
             "at this system. This option cannot be used with --csr.")
    helpful.add(
        "automation", "--agree-tos", dest="tos", action="store_true",
        default=flag_default("tos"),
        help="Agree to the ACME Subscriber Agreement (default: Ask)")
    helpful.add(
        ["unregister", "automation"], "--account", metavar="ACCOUNT_ID",
        default=flag_default("account"),
        help="Account ID to use")
    helpful.add(
        "automation", "--duplicate", dest="duplicate", action="store_true",
        default=flag_default("duplicate"),
        help="Allow making a certificate lineage that duplicates an existing one "
             "(both can be renewed in parallel)")
    helpful.add(
        ["automation", "renew", "certonly", "run"],
        "-q", "--quiet", dest="quiet", action="store_true",
        default=flag_default("quiet"),
        help="Silence all output except errors. Useful for automation via cron."
             " Implies --non-interactive.")
    # overwrites server, handled in HelpfulArgumentParser.parse_args()
    helpful.add(["testing", "revoke", "run"], "--test-cert", "--staging",
        dest="staging", action="store_true", default=flag_default("staging"),
        help="Use the Let's Encrypt staging server to obtain or revoke test (invalid) "
             "certificates; equivalent to --server " + constants.STAGING_URI)
    helpful.add(
        "testing", "--debug", action="store_true", default=flag_default("debug"),
        help="Show tracebacks in case of errors")
    helpful.add(
        [None, "certonly", "run"], "--debug-challenges", action="store_true",
        default=flag_default("debug_challenges"),
        help="After setting up challenges, wait for user input before "
             "submitting to CA. When used in combination with the `-v` "
             "option, the challenge URLs or FQDNs and their expected "
             "return values are shown.")
    helpful.add(
        "testing", "--no-verify-ssl", action="store_true",
        help=config_help("no_verify_ssl"),
        default=flag_default("no_verify_ssl"))
    helpful.add(
        ["testing", "standalone", "manual"], "--http-01-port", type=int,
        dest="http01_port",
        default=flag_default("http01_port"), help=config_help("http01_port"))
    helpful.add(
        ["testing", "standalone"], "--http-01-address",
        dest="http01_address",
        default=flag_default("http01_address"), help=config_help("http01_address"))
    helpful.add(
        ["testing", "nginx"], "--https-port", type=int,
        default=flag_default("https_port"),
        help=config_help("https_port"))
    helpful.add(
        "testing", "--break-my-certs", action="store_true",
        default=flag_default("break_my_certs"),
        help="Be willing to replace or renew valid certificates with invalid "
             "(testing/staging) certificates")
    helpful.add(
        "security", "--rsa-key-size", type=int, metavar="N",
        default=flag_default("rsa_key_size"), help=config_help("rsa_key_size"))
    helpful.add(
        "security", "--key-type", choices=['rsa', 'ecdsa'], type=str,
        default=flag_default("key_type"), help=config_help("key_type"))
    helpful.add(
        "security", "--elliptic-curve", type=str, choices=[
            'secp256r1',
            'secp384r1',
            'secp521r1',
        ], metavar="N",
        default=flag_default("elliptic_curve"), help=config_help("elliptic_curve"))
    helpful.add(
        "security", "--must-staple", action="store_true",
        dest="must_staple", default=flag_default("must_staple"),
        help=config_help("must_staple"))
    helpful.add(
        ["security", "enhance"],
        "--redirect", action="store_true", dest="redirect",
        default=flag_default("redirect"),
        help="Automatically redirect all HTTP traffic to HTTPS for the newly "
             "authenticated vhost. (default: redirect enabled for install and run, "
             "disabled for enhance)")
    helpful.add(
        "security", "--no-redirect", action="store_false", dest="redirect",
        default=flag_default("redirect"),
        help="Do not automatically redirect all HTTP traffic to HTTPS for the newly "
             "authenticated vhost. (default: redirect enabled for install and run, "
             "disabled for enhance)")
    helpful.add(
        ["security", "enhance"],
        "--hsts", action="store_true", dest="hsts", default=flag_default("hsts"),
        help="Add the Strict-Transport-Security header to every HTTP response."
             " Forcing browser to always use SSL for the domain."
             " Defends against SSL Stripping.")
    helpful.add(
        "security", "--no-hsts", action="store_false", dest="hsts",
        default=flag_default("hsts"), help=argparse.SUPPRESS)
    helpful.add(
        ["security", "enhance"],
        "--uir", action="store_true", dest="uir", default=flag_default("uir"),
        help='Add the "Content-Security-Policy: upgrade-insecure-requests"'
             ' header to every HTTP response. Forcing the browser to use'
             ' https:// for every http:// resource.')
    helpful.add(
        "security", "--no-uir", action="store_false", dest="uir", default=flag_default("uir"),
        help=argparse.SUPPRESS)
    helpful.add(
        "security", "--staple-ocsp", action="store_true", dest="staple",
        default=flag_default("staple"),
        help="Enables OCSP Stapling. A valid OCSP response is stapled to"
        " the certificate that the server offers during TLS.")
    helpful.add(
        "security", "--no-staple-ocsp", action="store_false", dest="staple",
        default=flag_default("staple"), help=argparse.SUPPRESS)
    helpful.add(
        "security", "--strict-permissions", action="store_true",
        default=flag_default("strict_permissions"),
        help="Require that all configuration files are owned by the current "
             "user; only needed if your config is somewhere unsafe like /tmp/")
    helpful.add(
        [None, "certonly", "renew", "run"],
        "--preferred-chain", dest="preferred_chain",
        default=flag_default("preferred_chain"), help=config_help("preferred_chain")
    )
    helpful.add(
        ["manual", "standalone", "certonly", "renew"],
        "--preferred-challenges", dest="pref_challs",
        action=_PrefChallAction, default=flag_default("pref_challs"),
        help='A sorted, comma delimited list of the preferred challenge to '
             'use during authorization with the most preferred challenge '
             'listed first (Eg, "dns" or "http,dns"). '
             'Not all plugins support all challenges. See '
             'https://certbot.eff.org/docs/using.html#plugins for details. '
             'ACME Challenges are versioned, but if you pick "http" rather '
             'than "http-01", Certbot will select the latest version '
             'automatically.')
    helpful.add(
        [None, "certonly", "run"], "--issuance-timeout", type=nonnegative_int,
        dest="issuance_timeout",
        default=flag_default("issuance_timeout"),
        help=config_help("issuance_timeout"))
    helpful.add(
        ["renew", "reconfigure"], "--pre-hook",
        help="Command to be run in a shell before obtaining any certificates."
        " Unless --disable-hook-validation is used, the command’s first word"
        " must be the absolute pathname of an executable or one found via the"
        " PATH environment variable."
        " Intended primarily for renewal, where it can be used to temporarily"
        " shut down a webserver that might conflict with the standalone"
        " plugin. This will only be called if a certificate is actually to be"
        " obtained/renewed. When renewing several certificates that have"
        " identical pre-hooks, only the first will be executed.")
    helpful.add(
        ["renew", "reconfigure"], "--post-hook",
        help="Command to be run in a shell after attempting to obtain/renew"
        " certificates."
        " Unless --disable-hook-validation is used, the command’s first word"
        " must be the absolute pathname of an executable or one found via the"
        " PATH environment variable."
        " Can be used to deploy renewed certificates, or to"
        " restart any servers that were stopped by --pre-hook. This is only"
        " run if an attempt was made to obtain/renew a certificate. If"
        " multiple renewed certificates have identical post-hooks, only"
        " one will be run.")
    helpful.add(["renew", "reconfigure"], "--renew-hook",
                action=_RenewHookAction, help=argparse.SUPPRESS)
    helpful.add(
        "renew", "--no-random-sleep-on-renew", action="store_false",
        default=flag_default("random_sleep_on_renew"), dest="random_sleep_on_renew",
        help=argparse.SUPPRESS)
    helpful.add(
        ["renew", "reconfigure"], "--deploy-hook", action=_DeployHookAction,
        help='Command to be run in a shell once for each successfully'
        ' issued certificate.'
        ' Unless --disable-hook-validation is used, the command’s first word'
        ' must be the absolute pathname of an executable or one found via the'
        ' PATH environment variable.'
        ' For this command, the shell variable'
        ' $RENEWED_LINEAGE will point to the config live subdirectory'
        ' (for example, "/etc/letsencrypt/live/example.com") containing'
        ' the new certificates and keys; the shell variable'
        ' $RENEWED_DOMAINS will contain a space-delimited list of'
        ' renewed certificate domains (for example, "example.com'
        ' www.example.com")')
    helpful.add(
        "renew", "--disable-hook-validation",
        action="store_false", dest="validate_hooks",
        default=flag_default("validate_hooks"),
        help="Ordinarily the commands specified for"
        " --pre-hook/--post-hook/--deploy-hook will be checked for"
        " validity, to see if the programs being run are in the $PATH,"
        " so that mistakes can be caught early, even when the hooks"
        " aren't being run just yet. The validation is rather"
        " simplistic and fails if you use more advanced shell"
        " constructs, so you can use this switch to disable it."
        " (default: False)")
    helpful.add(
        "renew", "--no-directory-hooks", action="store_false",
        default=flag_default("directory_hooks"), dest="directory_hooks",
        help="Disable running executables found in Certbot's hook directories"
        " during renewal. (default: False)")
    helpful.add(
        "renew", "--disable-renew-updates", action="store_true",
        default=flag_default("disable_renew_updates"), dest="disable_renew_updates",
        help="Disable automatic updates to your server configuration that"
        " would otherwise be done by the selected installer plugin, and triggered"
        " when the user executes \"certbot renew\", regardless of if the certificate"
        " is renewed. This setting does not apply to important TLS configuration"
        " updates.")
    helpful.add(
        "renew", "--no-autorenew", action="store_false",
        default=flag_default("autorenew"), dest="autorenew",
        help="Disable auto renewal of certificates. (default: False)")

    # Deprecated arguments
    helpful.add_deprecated_argument("--os-packages-only", 0)
    helpful.add_deprecated_argument("--no-self-upgrade", 0)
    helpful.add_deprecated_argument("--no-bootstrap", 0)
    helpful.add_deprecated_argument("--no-permissions-check", 0)

    # Populate the command line parameters for new style enhancements
    enhancements.populate_cli(helpful.add)

    _create_subparsers(helpful)
    _paths_parser(helpful)
    # _plugins_parsing should be the last thing to act upon the main
    # parser (--help should display plugin-specific options last)
    _plugins_parsing(helpful, plugins)

    global helpful_parser # pylint: disable=global-statement
    helpful_parser = helpful
    return helpful.parse_args()


def argparse_type(variable: Any) -> Type:
    """Return our argparse type function for a config variable (default: str)"""
    # pylint: disable=protected-access
    if helpful_parser is not None:
        for action in helpful_parser.actions:
            if action.type is not None and action.dest == variable:
                return action.type
    return str
