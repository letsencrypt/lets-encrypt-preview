"""Let's Encrypt command line argument & config processing."""
from __future__ import print_function
import argparse
import glob
import logging
import logging.handlers
import os
import sys
import traceback

import configargparse
import OpenSSL
import six

import letsencrypt

from letsencrypt import constants
from letsencrypt import crypto_util
from letsencrypt import errors
from letsencrypt import hooks
from letsencrypt import interfaces
from letsencrypt import le_util
from letsencrypt import help_short_usage

from letsencrypt.plugins import disco as plugins_disco
import letsencrypt.plugins.selection as plugin_selection

logger = logging.getLogger(__name__)

# Global, to save us from a lot of argument passing within the scope of this module
helpful_parser = None

cli_command = help_short_usage.cli_command
SHORT_USAGE = help_short_usage.SHORT_USAGE

# This is the short help for letsencrypt --help, where we disable argparse
# altogether
USAGE = SHORT_USAGE + """Choice of server plugins for obtaining and installing cert:

  %s
  --standalone      Run a standalone webserver for authentication
  %s
  --webroot         Place files in a server's webroot folder for authentication

OR use different plugins to obtain (authenticate) the cert and then install it:

  --authenticator standalone --installer apache

More detailed help:

  -h, --help [topic]    print this message, or detailed help on a topic;
                        the available topics are:

   all, automation, paths, security, testing, or any of the subcommands or
   plugins (certonly, install, nginx, apache, standalone, webroot, etc)
"""


# These argparse parameters should be removed when detecting defaults.
ARGPARSE_PARAMS_TO_REMOVE = ("const", "nargs", "type",)


# These sets are used when to help detect options set by the user.
EXIT_ACTIONS = set(("help", "version",))


ZERO_ARG_ACTIONS = set(("store_const", "store_true",
                        "store_false", "append_const", "count",))


# Maps a config option to a set of config options that may have modified it.
# This dictionary is used recursively, so if A modifies B and B modifies C,
# it is determined that C was modified by the user if A was modified.
VAR_MODIFIERS = {"account": set(("server",)),
                 "server": set(("dry_run", "staging",)),
                 "webroot_map": set(("webroot_path",))}


def report_config_interaction(modified, modifiers):
    """Registers config option interaction to be checked by set_by_cli.

    This function can be called by during the __init__ or
    add_parser_arguments methods of plugins to register interactions
    between config options.

    :param modified: config options that can be modified by modifiers
    :type modified: iterable or str
    :param modifiers: config options that modify modified
    :type modifiers: iterable or str

    """
    if isinstance(modified, str):
        modified = (modified,)
    if isinstance(modifiers, str):
        modifiers = (modifiers,)

    for var in modified:
        VAR_MODIFIERS.setdefault(var, set()).update(modifiers)


def usage_strings(plugins):
    """Make usage strings late so that plugins can be initialised late"""
    if "nginx" in plugins:
        nginx_doc = "--nginx           Use the Nginx plugin for authentication & installation"
    else:
        nginx_doc = "(nginx support is experimental, buggy, and not installed by default)"
    if "apache" in plugins:
        apache_doc = "--apache          Use the Apache plugin for authentication & installation"
    else:
        apache_doc = "(the apache plugin is not installed)"
    return USAGE % (apache_doc, nginx_doc), SHORT_USAGE


class _Default(object):
    """A class to use as a default to detect if a value is set by a user"""

    def __bool__(self):
        return False

    def __eq__(self, other):
        return isinstance(other, _Default)

    def __hash__(self):
        return id(_Default)

    def __nonzero__(self):
        return self.__bool__()


def set_by_cli(var):
    """
    Return True if a particular config variable has been set by the user
    (CLI or config file) including if the user explicitly set it to the
    default.  Returns False if the variable was assigned a default value.
    """
    detector = set_by_cli.detector
    if detector is None:
        # Setup on first run: `detector` is a weird version of config in which
        # the default value of every attribute is wrangled to be boolean-false
        plugins = plugins_disco.PluginsRegistry.find_all()
        # reconstructed_args == sys.argv[1:], or whatever was passed to main()
        reconstructed_args = helpful_parser.args + [helpful_parser.verb]
        detector = set_by_cli.detector = prepare_and_parse_args(
            plugins, reconstructed_args, detect_defaults=True)
        # propagate plugin requests: eg --standalone modifies config.authenticator
        detector.authenticator, detector.installer = (
            plugin_selection.cli_plugin_requests(detector))
        logger.debug("Default Detector is %r", detector)

    if not isinstance(getattr(detector, var), _Default):
        return True

    for modifier in VAR_MODIFIERS.get(var, []):
        if set_by_cli(modifier):
            return True

    return False
# static housekeeping var
set_by_cli.detector = None


def argparse_type(variable):
    "Return our argparse type function for a config variable (default: str)"
    # pylint: disable=protected-access
    for action in helpful_parser.parser._actions:
        if action.type is not None and action.dest == variable:
            return action.type
    return str

def read_file(filename, mode="rb"):
    """Returns the given file's contents.

    :param str filename: path to file
    :param str mode: open mode (see `open`)

    :returns: absolute path of filename and its contents
    :rtype: tuple

    :raises argparse.ArgumentTypeError: File does not exist or is not readable.

    """
    try:
        filename = os.path.abspath(filename)
        return filename, open(filename, mode).read()
    except IOError as exc:
        raise argparse.ArgumentTypeError(exc.strerror)


def flag_default(name):
    """Default value for CLI flag."""
    # XXX: this is an internal housekeeping notion of defaults before
    # argparse has been set up; it is not accurate for all flags.  Call it
    # with caution.  Plugin defaults are missing, and some things are using
    # defaults defined in this file, not in constants.py :(
    return constants.CLI_DEFAULTS[name]


def config_help(name, hidden=False):
    """Extract the help message for an `.IConfig` attribute."""
    if hidden:
        return argparse.SUPPRESS
    else:
        return interfaces.IConfig[name].__doc__


class HelpfulArgumentGroup(object):
    """Emulates an argparse group for use with HelpfulArgumentParser.

    This class is used in the add_group method of HelpfulArgumentParser.
    Command line arguments can be added to the group, but help
    suppression and default detection is applied by
    HelpfulArgumentParser when necessary.

    """
    def __init__(self, helpful_arg_parser, topic):
        self._parser = helpful_arg_parser
        self._topic = topic

    def add_argument(self, *args, **kwargs):
        """Add a new command line argument to the argument group."""
        self._parser.add(self._topic, *args, **kwargs)


class HelpfulArgumentParser(object):
    """Argparse Wrapper.

    This class wraps argparse, adding the ability to make --help less
    verbose, and request help on specific subcategories at a time, eg
    'letsencrypt --help security' for security options.

    """

    def __init__(self, args, plugins, detect_defaults=False):
        from letsencrypt import main
        self.VERBS = {"auth": main.obtain_cert, "certonly": main.obtain_cert,
                      "config_changes": main.config_changes, "run": main.run,
                      "install": main.install, "plugins": main.plugins_cmd,
                      "renew": main.renew, "revoke": main.revoke,
                      "rollback": main.rollback, "everything": main.run}

        # List of topics for which additional help can be provided
        HELP_TOPICS = ["all", "security", "paths", "automation", "testing"] + list(self.VERBS)

        plugin_names = list(plugins)
        self.help_topics = HELP_TOPICS + plugin_names + [None]
        usage, short_usage = usage_strings(plugins)
        self.parser = configargparse.ArgParser(
            usage=short_usage,
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            args_for_setting_config_path=["-c", "--config"],
            default_config_files=flag_default("config_files"))

        # This is the only way to turn off overly verbose config flag documentation
        self.parser._add_config_file_help = False  # pylint: disable=protected-access

        self.detect_defaults = detect_defaults

        self.args = args
        self.determine_verb()
        help1 = self.prescan_for_flag("-h", self.help_topics)
        help2 = self.prescan_for_flag("--help", self.help_topics)
        assert max(True, "a") == "a", "Gravity changed direction"
        self.help_arg = max(help1, help2)
        if self.help_arg is True:
            # just --help with no topic; avoid argparse altogether
            print(usage)
            sys.exit(0)
        self.visible_topics = self.determine_help_topics(self.help_arg)
        self.groups = {}       # elements are added by .add_group()

    def parse_args(self):
        """Parses command line arguments and returns the result.

        :returns: parsed command line arguments
        :rtype: argparse.Namespace

        """
        parsed_args = self.parser.parse_args(self.args)
        parsed_args.func = self.VERBS[self.verb]
        parsed_args.verb = self.verb

        if self.detect_defaults:
            return parsed_args

        # Do any post-parsing homework here

        if parsed_args.staging or parsed_args.dry_run:
            if parsed_args.server not in (flag_default("server"), constants.STAGING_URI):
                conflicts = ["--staging"] if parsed_args.staging else []
                conflicts += ["--dry-run"] if parsed_args.dry_run else []
                raise errors.Error("--server value conflicts with {0}".format(
                    " and ".join(conflicts)))

            parsed_args.server = constants.STAGING_URI

            if parsed_args.dry_run:
                if self.verb not in ["certonly", "renew"]:
                    raise errors.Error("--dry-run currently only works with the "
                                       "'certonly' or 'renew' subcommands (%r)" % self.verb)
                parsed_args.break_my_certs = parsed_args.staging = True
                if glob.glob(os.path.join(parsed_args.config_dir, constants.ACCOUNTS_DIR, "*")):
                    # The user has a prod account, but might not have a staging
                    # one; we don't want to start trying to perform interactive registration
                    parsed_args.tos = True
                    parsed_args.register_unsafely_without_email = True

        if parsed_args.csr:
            if parsed_args.allow_subset_of_names:
                raise errors.Error("--allow-subset-of-names "
                                   "cannot be used with --csr")
            self.handle_csr(parsed_args)

        hooks.validate_hooks(parsed_args)

        return parsed_args

    def handle_csr(self, parsed_args):
        """Process a --csr flag."""
        if parsed_args.verb != "certonly":
            raise errors.Error("Currently, a CSR file may only be specified "
                               "when obtaining a new or replacement "
                               "via the certonly command. Please try the "
                               "certonly command instead.")

        try:
            csr = le_util.CSR(file=parsed_args.csr[0], data=parsed_args.csr[1], form="der")
            typ = OpenSSL.crypto.FILETYPE_ASN1
            domains = crypto_util.get_sans_from_csr(csr.data, OpenSSL.crypto.FILETYPE_ASN1)
        except OpenSSL.crypto.Error:
            try:
                e1 = traceback.format_exc()
                typ = OpenSSL.crypto.FILETYPE_PEM
                csr = le_util.CSR(file=parsed_args.csr[0], data=parsed_args.csr[1], form="pem")
                domains = crypto_util.get_sans_from_csr(csr.data, typ)
            except OpenSSL.crypto.Error:
                logger.debug("DER CSR parse error %s", e1)
                logger.debug("PEM CSR parse error %s", traceback.format_exc())
                raise errors.Error("Failed to parse CSR file: {0}".format(parsed_args.csr[0]))

        # This is not necessary for webroot to work, however,
        # obtain_certificate_from_csr requires parsed_args.domains to be set
        for domain in domains:
            add_domains(parsed_args, domain)

        if not domains:
            # TODO: add CN to domains instead:
            raise errors.Error(
                "Unfortunately, your CSR %s needs to have a SubjectAltName for every domain"
                % parsed_args.csr[0])

        parsed_args.actual_csr = (csr, typ)
        csr_domains, config_domains = set(domains), set(parsed_args.domains)
        if csr_domains != config_domains:
            raise errors.ConfigurationError(
                "Inconsistent domain requests:\nFrom the CSR: {0}\nFrom command line/config: {1}"
                .format(", ".join(csr_domains), ", ".join(config_domains)))


    def determine_verb(self):
        """Determines the verb/subcommand provided by the user.

        This function works around some of the limitations of argparse.

        """
        if "-h" in self.args or "--help" in self.args:
            # all verbs double as help arguments; don't get them confused
            self.verb = "help"
            return

        for i, token in enumerate(self.args):
            if token in self.VERBS:
                verb = token
                if verb == "auth":
                    verb = "certonly"
                if verb == "everything":
                    verb = "run"
                self.verb = verb
                self.args.pop(i)
                return

        self.verb = "run"

    def prescan_for_flag(self, flag, possible_arguments):
        """Checks cli input for flags.

        Check for a flag, which accepts a fixed set of possible arguments, in
        the command line; we will use this information to configure argparse's
        help correctly.  Return the flag's argument, if it has one that matches
        the sequence @possible_arguments; otherwise return whether the flag is
        present.

        """
        if flag not in self.args:
            return False
        pos = self.args.index(flag)
        try:
            nxt = self.args[pos + 1]
            if nxt in possible_arguments:
                return nxt
        except IndexError:
            pass
        return True

    def add(self, topic, *args, **kwargs):
        """Add a new command line argument.

        :param str: help topic this should be listed under, can be None for
                    "always documented"
        :param list *args: the names of this argument flag
        :param dict **kwargs: various argparse settings for this argument

        """

        if self.detect_defaults:
            kwargs = self.modify_kwargs_for_default_detection(**kwargs)

        if self.visible_topics[topic]:
            if topic in self.groups:
                group = self.groups[topic]
                group.add_argument(*args, **kwargs)
            else:
                self.parser.add_argument(*args, **kwargs)
        else:
            kwargs["help"] = argparse.SUPPRESS
            self.parser.add_argument(*args, **kwargs)

    def modify_kwargs_for_default_detection(self, **kwargs):
        """Modify an arg so we can check if it was set by the user.

        Changes the parameters given to argparse when adding an argument
        so we can properly detect if the value was set by the user.

        :param dict kwargs: various argparse settings for this argument

        :returns: a modified versions of kwargs
        :rtype: dict

        """
        action = kwargs.get("action", None)
        if action not in EXIT_ACTIONS:
            kwargs["action"] = ("store_true" if action in ZERO_ARG_ACTIONS else
                                "store")
            kwargs["default"] = _Default()
            for param in ARGPARSE_PARAMS_TO_REMOVE:
                kwargs.pop(param, None)

        return kwargs

    def add_deprecated_argument(self, argument_name, num_args):
        """Adds a deprecated argument with the name argument_name.

        Deprecated arguments are not shown in the help. If they are used
        on the command line, a warning is shown stating that the
        argument is deprecated and no other action is taken.

        :param str argument_name: Name of deprecated argument.
        :param int nargs: Number of arguments the option takes.

        """
        le_util.add_deprecated_argument(
            self.parser.add_argument, argument_name, num_args)

    def add_group(self, topic, **kwargs):
        """Create a new argument group.

        This method must be called once for every topic, however, calls
        to this function are left next to the argument definitions for
        clarity.

        :param str topic: Name of the new argument group.

        :returns: The new argument group.
        :rtype: `HelpfulArgumentGroup`

        """
        if self.visible_topics[topic]:
            self.groups[topic] = self.parser.add_argument_group(topic, **kwargs)

        return HelpfulArgumentGroup(self, topic)

    def add_plugin_args(self, plugins):
        """

        Let each of the plugins add its own command line arguments, which
        may or may not be displayed as help topics.

        """
        for name, plugin_ep in six.iteritems(plugins):
            parser_or_group = self.add_group(name, description=plugin_ep.description)
            plugin_ep.plugin_cls.inject_parser_options(parser_or_group, name)

    def determine_help_topics(self, chosen_topic):
        """

        The user may have requested help on a topic, return a dict of which
        topics to display. @chosen_topic has prescan_for_flag's return type

        :returns: dict

        """
        # topics maps each topic to whether it should be documented by
        # argparse on the command line
        if chosen_topic == "auth":
            chosen_topic = "certonly"
        if chosen_topic == "everything":
            chosen_topic = "run"
        if chosen_topic == "all":
            return dict([(t, True) for t in self.help_topics])
        elif not chosen_topic:
            return dict([(t, False) for t in self.help_topics])
        else:
            return dict([(t, t == chosen_topic) for t in self.help_topics])


def prepare_and_parse_args(plugins, args, detect_defaults=False):
    """Returns parsed command line arguments.

    :param .PluginsRegistry plugins: available plugins
    :param list args: command line arguments with the program name removed

    :returns: parsed command line arguments
    :rtype: argparse.Namespace

    """
    helpful = HelpfulArgumentParser(args, plugins, detect_defaults)

    # --help is automatically provided by argparse
    helpful.add(
        None, "-v", "--verbose", dest="verbose_count", action="count",
        default=flag_default("verbose_count"), help="This flag can be used "
        "multiple times to incrementally increase the verbosity of output, "
        "e.g. -vvv.")
    helpful.add(
        None, "-t", "--text", dest="text_mode", action="store_true",
        help="Use the text output instead of the curses UI.")
    helpful.add(
        None, "-n", "--non-interactive", "--noninteractive",
        dest="noninteractive_mode", action="store_true",
        help="Run without ever asking for user input. This may require "
              "additional command line flags; the client will try to explain "
              "which ones are required if it finds one missing")
    helpful.add(
        None, "--dry-run", action="store_true", dest="dry_run",
        help="Perform a test run of the client, obtaining test (invalid) certs"
             " but not saving them to disk. This can currently only be used"
             " with the 'certonly' and 'renew' subcommands. \nNote: Although --dry-run"
             " tries to avoid making any persistent changes on a system, it "
             " is not completely side-effect free: if used with webserver authenticator plugins"
             " like apache and nginx, it makes and then reverts temporary config changes"
             " in order to obtain test certs, and reloads webservers to deploy and then"
             " roll back those changes.  It also calls --pre-hook and --post-hook commands"
             " if they are defined because they may be necessary to accurately simulate"
             " renewal. --renew-hook commands are not called.")
    helpful.add(
        None, "--register-unsafely-without-email", action="store_true",
        help="Specifying this flag enables registering an account with no "
             "email address. This is strongly discouraged, because in the "
             "event of key loss or account compromise you will irrevocably "
             "lose access to your account. You will also be unable to receive "
             "notice about impending expiration or revocation of your "
             "certificates. Updates to the Subscriber Agreement will still "
             "affect you, and will be effective 14 days after posting an "
             "update to the web site.")
    helpful.add(None, "-m", "--email", help=config_help("email"))
    # positional arg shadows --domains, instead of appending, and
    # --domains is useful, because it can be stored in config
    #for subparser in parser_run, parser_auth, parser_install:
    #    subparser.add_argument("domains", nargs="*", metavar="domain")
    helpful.add(None, "-d", "--domains", "--domain", dest="domains",
                metavar="DOMAIN", action=_DomainsAction, default=[],
                help="Domain names to apply. For multiple domains you can use "
                "multiple -d flags or enter a comma separated list of domains "
                "as a parameter.")
    helpful.add_group(
        "automation",
        description="Arguments for automating execution & other tweaks")
    helpful.add(
        "automation", "--keep-until-expiring", "--keep", "--reinstall",
        dest="reinstall", action="store_true",
        help="If the requested cert matches an existing cert, always keep the "
             "existing one until it is due for renewal (for the "
             "'run' subcommand this means reinstall the existing cert)")
    helpful.add(
        "automation", "--expand", action="store_true",
        help="If an existing cert covers some subset of the requested names, "
             "always expand and replace it with the additional names.")
    helpful.add(
        "automation", "--version", action="version",
        version="%(prog)s {0}".format(letsencrypt.__version__),
        help="show program's version number and exit")
    helpful.add(
        "automation", "--force-renewal", "--renew-by-default",
        action="store_true", dest="renew_by_default", help="If a certificate "
             "already exists for the requested domains, renew it now, "
             "regardless of whether it is near expiry. (Often "
             "--keep-until-expiring is more appropriate). Also implies "
             "--expand.")
    helpful.add(
        "automation", "--allow-subset-of-names", action="store_true",
        help="When performing domain validation, do not consider it a failure "
             "if authorizations can not be obtained for a strict subset of "
             "the requested domains. This may be useful for allowing renewals for "
             "multiple domains to succeed even if some domains no longer point "
             "at this system. This option cannot be used with --csr.")
    helpful.add(
        "automation", "--agree-tos", dest="tos", action="store_true",
        help="Agree to the Let's Encrypt Subscriber Agreement")
    helpful.add(
        "automation", "--account", metavar="ACCOUNT_ID",
        help="Account ID to use")
    helpful.add(
        "automation", "--duplicate", dest="duplicate", action="store_true",
        help="Allow making a certificate lineage that duplicates an existing one "
             "(both can be renewed in parallel)")
    helpful.add(
        "automation", "--os-packages-only", action="store_true",
        help="(letsencrypt-auto only) install OS package dependencies and then stop")
    helpful.add(
        "automation", "--no-self-upgrade", action="store_true",
        help="(letsencrypt-auto only) prevent the letsencrypt-auto script from"
             " upgrading itself to newer released versions")
    helpful.add(
        "automation", "-q", "--quiet", dest="quiet", action="store_true",
        help="Silence all output except errors. Useful for automation via cron."
             " Implies --non-interactive.")

    helpful.add_group(
        "testing", description="The following flags are meant for "
        "testing purposes only! Do NOT change them, unless you "
        "really know what you're doing!")
    helpful.add(
        "testing", "--debug", action="store_true",
        help="Show tracebacks in case of errors, and allow letsencrypt-auto "
             "execution on experimental platforms")
    helpful.add(
        "testing", "--no-verify-ssl", action="store_true",
        help=config_help("no_verify_ssl"),
        default=flag_default("no_verify_ssl"))
    helpful.add(
        "testing", "--tls-sni-01-port", type=int,
        default=flag_default("tls_sni_01_port"),
        help=config_help("tls_sni_01_port"))
    helpful.add(
        "testing", "--http-01-port", type=int, dest="http01_port",
        default=flag_default("http01_port"), help=config_help("http01_port"))
    helpful.add(
        "testing", "--break-my-certs", action="store_true",
        help="Be willing to replace or renew valid certs with invalid "
             "(testing/staging) certs")
    helpful.add_group(
        "security", description="Security parameters & server settings")
    helpful.add(
        "security", "--rsa-key-size", type=int, metavar="N",
        default=flag_default("rsa_key_size"), help=config_help("rsa_key_size"))
    helpful.add(
        "security", "--redirect", action="store_true",
        help="Automatically redirect all HTTP traffic to HTTPS for the newly "
             "authenticated vhost.", dest="redirect", default=None)
    helpful.add(
        "security", "--no-redirect", action="store_false",
        help="Do not automatically redirect all HTTP traffic to HTTPS for the newly "
             "authenticated vhost.", dest="redirect", default=None)
    helpful.add(
        "security", "--hsts", action="store_true",
        help="Add the Strict-Transport-Security header to every HTTP response."
             " Forcing browser to use always use SSL for the domain."
             " Defends against SSL Stripping.", dest="hsts", default=False)
    helpful.add(
        "security", "--no-hsts", action="store_false",
        help="Do not automatically add the Strict-Transport-Security header"
             " to every HTTP response.", dest="hsts", default=False)
    helpful.add(
        "security", "--uir", action="store_true",
        help="Add the \"Content-Security-Policy: upgrade-insecure-requests\""
             " header to every HTTP response. Forcing the browser to use"
             " https:// for every http:// resource.", dest="uir", default=None)
    helpful.add(
        "security", "--no-uir", action="store_false",
        help=" Do not automatically set the \"Content-Security-Policy:"
        " upgrade-insecure-requests\" header to every HTTP response.",
        dest="uir", default=None)
    helpful.add(
        "security", "--strict-permissions", action="store_true",
        help="Require that all configuration files are owned by the current "
             "user; only needed if your config is somewhere unsafe like /tmp/")

    helpful.add_group(
        "renew", description="The 'renew' subcommand will attempt to renew all"
        " certificates (or more precisely, certificate lineages) you have"
        " previously obtained if they are close to expiry, and print a"
        " summary of the results. By default, 'renew' will reuse the options"
        " used to create obtain or most recently successfully renew each"
        " certificate lineage. You can try it with `--dry-run` first. For"
        " more fine-grained control, you can renew individual lineages with"
        " the `certonly` subcommand. Hooks are available to run commands "
        " before and after renewal; see XXX for more information on these.")

    helpful.add(
        "renew", "--pre-hook",
        help="Command to be run in a shell before obtaining any certificates. Intended"
        " primarily for renewal, where it can be used to temporarily shut down a"
        " webserver that might conflict with the standalone plugin. This will "
        " only be called if a certificate is actually to be obtained/renewed. ")
    helpful.add(
        "renew", "--post-hook",
        help="Command to be run in a shell after attempting to obtain/renew "
        " certificates. Can be used to deploy renewed certificates, or to restart"
        " any servers that were stopped by --pre-hook.")
    helpful.add(
        "renew", "--renew-hook",
        help="Command to be run in a shell once for each successfully renewed certificate."
        "For this command, the shell variable $RENEWED_LINEAGE will point to the"
        "config live subdirectory containing the new certs and keys; the shell variable "
        "$RENEWED_DOMAINS will contain a space-delimited list of renewed cert domains")

    helpful.add_deprecated_argument("--agree-dev-preview", 0)

    _create_subparsers(helpful)
    _paths_parser(helpful)
    # _plugins_parsing should be the last thing to act upon the main
    # parser (--help should display plugin-specific options last)
    _plugins_parsing(helpful, plugins)

    if not detect_defaults:
        global helpful_parser # pylint: disable=global-statement
        helpful_parser = helpful
    return helpful.parse_args()


def _create_subparsers(helpful):
    helpful.add_group("certonly", description="Options for modifying how a cert is obtained")
    helpful.add_group("install", description="Options for modifying how a cert is deployed")
    helpful.add_group("revoke", description="Options for revocation of certs")
    helpful.add_group("rollback", description="Options for reverting config changes")
    helpful.add_group("plugins", description="Plugin options")
    helpful.add_group("config_changes",
                      description="Options for showing a history of config changes")
    helpful.add("config_changes", "--num", type=int,
                help="How many past revisions you want to be displayed")
    helpful.add(
        None, "--user-agent", default=None,
        help="Set a custom user agent string for the client. User agent strings allow "
             "the CA to collect high level statistics about success rates by OS and "
             "plugin. If you wish to hide your server OS version from the Let's "
             'Encrypt server, set this to "".')
    helpful.add("certonly",
                "--csr", type=read_file,
                help="Path to a Certificate Signing Request (CSR) in DER"
                " format; note that the .csr file *must* contain a Subject"
                " Alternative Name field for each domain you want certified."
                " Currently --csr only works with the 'certonly' subcommand'")
    helpful.add("rollback",
                "--checkpoints", type=int, metavar="N",
                default=flag_default("rollback_checkpoints"),
                help="Revert configuration N number of checkpoints.")
    helpful.add("plugins",
                "--init", action="store_true", help="Initialize plugins.")
    helpful.add("plugins",
                "--prepare", action="store_true", help="Initialize and prepare plugins.")
    helpful.add("plugins",
                "--authenticators", action="append_const", dest="ifaces",
                const=interfaces.IAuthenticator, help="Limit to authenticator plugins only.")
    helpful.add("plugins",
                "--installers", action="append_const", dest="ifaces",
                const=interfaces.IInstaller, help="Limit to installer plugins only.")


def _paths_parser(helpful):
    add = helpful.add
    verb = helpful.verb
    if verb == "help":
        verb = helpful.help_arg
    helpful.add_group(
        "paths", description="Arguments changing execution paths & servers")

    cph = "Path to where cert is saved (with auth --csr), installed from or revoked."
    section = "paths"
    if verb in ("install", "revoke", "certonly"):
        section = verb
    if verb == "certonly":
        add(section, "--cert-path", type=os.path.abspath,
            default=flag_default("auth_cert_path"), help=cph)
    elif verb == "revoke":
        add(section, "--cert-path", type=read_file, required=True, help=cph)
    else:
        add(section, "--cert-path", type=os.path.abspath,
            help=cph, required=(verb == "install"))

    section = "paths"
    if verb in ("install", "revoke"):
        section = verb
    # revoke --key-path reads a file, install --key-path takes a string
    add(section, "--key-path", required=(verb == "install"),
        type=((verb == "revoke" and read_file) or os.path.abspath),
        help="Path to private key for cert installation "
             "or revocation (if account key is missing)")

    default_cp = None
    if verb == "certonly":
        default_cp = flag_default("auth_chain_path")
    add("paths", "--fullchain-path", default=default_cp, type=os.path.abspath,
        help="Accompanying path to a full certificate chain (cert plus chain).")
    add("paths", "--chain-path", default=default_cp, type=os.path.abspath,
        help="Accompanying path to a certificate chain.")
    add("paths", "--config-dir", default=flag_default("config_dir"),
        help=config_help("config_dir"))
    add("paths", "--work-dir", default=flag_default("work_dir"),
        help=config_help("work_dir"))
    add("paths", "--logs-dir", default=flag_default("logs_dir"),
        help="Logs directory.")
    add("paths", "--server", default=flag_default("server"),
        help=config_help("server"))
    # overwrites server, handled in HelpfulArgumentParser.parse_args()
    add("testing", "--test-cert", "--staging", action='store_true', dest='staging',
        help='Use the staging server to obtain test (invalid) certs; equivalent'
             ' to --server ' + constants.STAGING_URI)


def _plugins_parsing(helpful, plugins):
    helpful.add_group(
        "plugins", description="Let's Encrypt client supports an "
        "extensible plugins architecture. See '%(prog)s plugins' for a "
        "list of all installed plugins and their names. You can force "
        "a particular plugin by setting options provided below. Running "
        "--help <plugin_name> will list flags specific to that plugin.")
    helpful.add(
        "plugins", "-a", "--authenticator", help="Authenticator plugin name.")
    helpful.add(
        "plugins", "-i", "--installer", help="Installer plugin name (also used to find domains).")
    helpful.add(
        "plugins", "--configurator", help="Name of the plugin that is "
        "both an authenticator and an installer. Should not be used "
        "together with --authenticator or --installer.")
    helpful.add("plugins", "--apache", action="store_true",
                help="Obtain and install certs using Apache")
    helpful.add("plugins", "--nginx", action="store_true",
                help="Obtain and install certs using Nginx")
    helpful.add("plugins", "--standalone", action="store_true",
                help='Obtain certs using a "standalone" webserver.')
    helpful.add("plugins", "--manual", action="store_true",
                help='Provide laborious manual instructions for obtaining a cert')
    helpful.add("plugins", "--webroot", action="store_true",
                help='Obtain certs by placing files in a webroot directory.')

    # things should not be reorder past/pre this comment:
    # plugins_group should be displayed in --help before plugin
    # specific groups (so that plugins_group.description makes sense)

    helpful.add_plugin_args(plugins)


class _DomainsAction(argparse.Action):
    """Action class for parsing domains."""

    def __call__(self, parser, namespace, domain, option_string=None):
        """Just wrap add_domains in argparseese."""
        add_domains(namespace, domain)


def add_domains(args_or_config, domains):
    """Registers new domains to be used during the current client run.

    Domains are not added to the list of requested domains if they have
    already been registered.

    :param args_or_config: parsed command line arguments
    :type args_or_config: argparse.Namespace or
        configuration.NamespaceConfig
    :param str domain: one or more comma separated domains

    :returns: domains after they have been normalized and validated
    :rtype: `list` of `str`

    """
    validated_domains = []
    for domain in domains.split(","):
        domain = le_util.enforce_domain_sanity(domain.strip())
        validated_domains.append(domain)
        if domain not in args_or_config.domains:
            args_or_config.domains.append(domain)

    return validated_domains
