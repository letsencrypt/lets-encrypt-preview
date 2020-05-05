"""Certbot client interfaces."""
import abc

import six
import zope.interface

# pylint: disable=no-self-argument,no-method-argument,inherit-non-class


@six.add_metaclass(abc.ABCMeta)
class AccountStorage(object):
    """Accounts storage interface."""

    @abc.abstractmethod
    def find_all(self):  # pragma: no cover
        """Find all accounts.

        :returns: All found accounts.
        :rtype: list

        """
        raise NotImplementedError()

    @abc.abstractmethod
    def load(self, account_id):  # pragma: no cover
        """Load an account by its id.

        :raises .AccountNotFound: if account could not be found
        :raises .AccountStorageError: if account could not be loaded

        """
        raise NotImplementedError()

    @abc.abstractmethod
    def save(self, account, client):  # pragma: no cover
        """Save account.

        :raises .AccountStorageError: if account could not be saved

        """
        raise NotImplementedError()


class IPluginFactory(zope.interface.Interface):
    """IPlugin factory.

    Objects providing this interface will be called without satisfying
    any entry point "extras" (extra dependencies) you might have defined
    for your plugin, e.g (excerpt from ``setup.py`` script)::

      setup(
          ...
          entry_points={
              'certbot.plugins': [
                  'name=example_project.plugin[plugin_deps]',
              ],
          },
          extras_require={
              'plugin_deps': ['dep1', 'dep2'],
          }
      )

    Therefore, make sure such objects are importable and usable without
    extras. This is necessary, because CLI does the following operations
    (in order):

      - loads an entry point,
      - calls `inject_parser_options`,
      - requires an entry point,
      - creates plugin instance (`__call__`).

    """

    description = zope.interface.Attribute("Short plugin description")

    def __call__(config, name):  # pylint: disable=signature-differs
        """Create new `IPlugin`.

        :param IConfig config: Configuration.
        :param str name: Unique plugin name.

        """

    def inject_parser_options(parser, name):
        """Inject argument parser options (flags).

        1. Be nice and prepend all options and destinations with
        `~.common.option_namespace` and `~common.dest_namespace`.

        2. Inject options (flags) only. Positional arguments are not
        allowed, as this would break the CLI.

        :param ArgumentParser parser: (Almost) top-level CLI parser.
        :param str name: Unique plugin name.

        """


class IPlugin(zope.interface.Interface):
    """Certbot plugin."""

    def prepare():  # type: ignore
        """Prepare the plugin.

        Finish up any additional initialization.

        :raises .PluginError:
            when full initialization cannot be completed.
        :raises .MisconfigurationError:
            when full initialization cannot be completed. Plugin will
            be displayed on a list of available plugins.
        :raises .NoInstallationError:
            when the necessary programs/files cannot be located. Plugin
            will NOT be displayed on a list of available plugins.
        :raises .NotSupportedError:
            when the installation is recognized, but the version is not
            currently supported.

        """

    def more_info():  # type: ignore
        """Human-readable string to help the user.

        Should describe the steps taken and any relevant info to help the user
        decide which plugin to use.

        :rtype str:

        """


class IAuthenticator(IPlugin):
    """Generic Certbot Authenticator.

    Class represents all possible tools processes that have the
    ability to perform challenges and attain a certificate.

    """

    def get_chall_pref(domain):
        """Return `collections.Iterable` of challenge preferences.

        :param str domain: Domain for which challenge preferences are sought.

        :returns: `collections.Iterable` of challenge types (subclasses of
            :class:`acme.challenges.Challenge`) with the most
            preferred challenges first. If a type is not specified, it means the
            Authenticator cannot perform the challenge.
        :rtype: `collections.Iterable`

        """

    def perform(achalls):
        """Perform the given challenge.

        :param list achalls: Non-empty (guaranteed) list of
            :class:`~certbot.achallenges.AnnotatedChallenge`
            instances, such that it contains types found within
            :func:`get_chall_pref` only.

        :returns: `collections.Iterable` of ACME
            :class:`~acme.challenges.ChallengeResponse` instances corresponding to each provided
            :class:`~acme.challenges.Challenge`.
        :rtype: :class:`collections.Iterable` of
            :class:`acme.challenges.ChallengeResponse`,
            where responses are required to be returned in
            the same order as corresponding input challenges

        :raises .PluginError: If some or all challenges cannot be performed

        """

    def cleanup(achalls):
        """Revert changes and shutdown after challenges complete.

        This method should be able to revert all changes made by
        perform, even if perform exited abnormally.

        :param list achalls: Non-empty (guaranteed) list of
            :class:`~certbot.achallenges.AnnotatedChallenge`
            instances, a subset of those previously passed to :func:`perform`.

        :raises PluginError: if original configuration cannot be restored

        """


class IConfig(zope.interface.Interface):
    """Certbot user-supplied configuration.

    .. warning:: The values stored in the configuration have not been
        filtered, stripped or sanitized.

    """
    server = zope.interface.Attribute("ACME Directory Resource URI.")
    email = zope.interface.Attribute(
        "Email used for registration and recovery contact. Use comma to "
        "register multiple emails, ex: u1@example.com,u2@example.com. "
        "(default: Ask).")
    rsa_key_size = zope.interface.Attribute("Size of the RSA key.")
    must_staple = zope.interface.Attribute(
        "Adds the OCSP Must Staple extension to the certificate. "
        "Autoconfigures OCSP Stapling for supported setups "
        "(Apache version >= 2.3.3 ).")

    config_dir = zope.interface.Attribute("Configuration directory.")
    work_dir = zope.interface.Attribute("Working directory.")

    accounts_dir = zope.interface.Attribute(
        "Directory where all account information is stored.")
    backup_dir = zope.interface.Attribute("Configuration backups directory.")
    csr_dir = zope.interface.Attribute(
        "Directory where newly generated Certificate Signing Requests "
        "(CSRs) are saved.")
    in_progress_dir = zope.interface.Attribute(
        "Directory used before a permanent checkpoint is finalized.")
    key_dir = zope.interface.Attribute("Keys storage.")
    temp_checkpoint_dir = zope.interface.Attribute(
        "Temporary checkpoint directory.")

    no_verify_ssl = zope.interface.Attribute(
        "Disable verification of the ACME server's certificate.")

    http01_port = zope.interface.Attribute(
        "Port used in the http-01 challenge. "
        "This only affects the port Certbot listens on. "
        "A conforming ACME server will still attempt to connect on port 80.")

    http01_address = zope.interface.Attribute(
        "The address the server listens to during http-01 challenge.")

    https_port = zope.interface.Attribute(
        "Port used to serve HTTPS. "
        "This affects which port Nginx will listen on after a LE certificate "
        "is installed.")

    pref_challs = zope.interface.Attribute(
        "Sorted user specified preferred challenges"
        "type strings with the most preferred challenge listed first")

    allow_subset_of_names = zope.interface.Attribute(
        "When performing domain validation, do not consider it a failure "
        "if authorizations can not be obtained for a strict subset of "
        "the requested domains. This may be useful for allowing renewals for "
        "multiple domains to succeed even if some domains no longer point "
        "at this system. This is a boolean")

    strict_permissions = zope.interface.Attribute(
        "Require that all configuration files are owned by the current "
        "user; only needed if your config is somewhere unsafe like /tmp/."
        "This is a boolean")

    disable_renew_updates = zope.interface.Attribute(
        "If updates provided by installer enhancements when Certbot is being run"
        " with \"renew\" verb should be disabled.")

class IInstaller(IPlugin):
    """Generic Certbot Installer Interface.

    Represents any server that an X509 certificate can be placed.

    It is assumed that :func:`save` is the only method that finalizes a
    checkpoint. This is important to ensure that checkpoints are
    restored in a consistent manner if requested by the user or in case
    of an error.

    Using :class:`certbot.reverter.Reverter` to implement checkpoints,
    rollback, and recovery can dramatically simplify plugin development.

    """

    def get_all_names():  # type: ignore
        """Returns all names that may be authenticated.

        :rtype: `collections.Iterable` of `str`

        """

    def deploy_cert(domain, cert_path, key_path, chain_path, fullchain_path,
                    privkey_fullchain_path):
        """Deploy certificate.

        :param str domain: domain to deploy certificate file
        :param str cert_path: absolute path to the certificate file
        :param str key_path: absolute path to the private key file
        :param str chain_path: absolute path to the certificate chain file
        :param str fullchain_path: absolute path to the certificate fullchain
            file (cert plus chain)
        :param str fullchain_path: absolute path to the file wih the private key
            and the certificate fullchain

        :raises .PluginError: when cert cannot be deployed

        """

    def enhance(domain, enhancement, options=None):
        """Perform a configuration enhancement.

        :param str domain: domain for which to provide enhancement
        :param str enhancement: An enhancement as defined in
            :const:`~certbot.plugins.enhancements.ENHANCEMENTS`
        :param options: Flexible options parameter for enhancement.
            Check documentation of
            :const:`~certbot.plugins.enhancements.ENHANCEMENTS`
            for expected options for each enhancement.

        :raises .PluginError: If Enhancement is not supported, or if
            an error occurs during the enhancement.

        """

    def supported_enhancements():  # type: ignore
        """Returns a `collections.Iterable` of supported enhancements.

        :returns: supported enhancements which should be a subset of
            :const:`~certbot.plugins.enhancements.ENHANCEMENTS`
        :rtype: :class:`collections.Iterable` of :class:`str`

        """

    def save(title=None, temporary=False):
        """Saves all changes to the configuration files.

        Both title and temporary are needed because a save may be
        intended to be permanent, but the save is not ready to be a full
        checkpoint.

        It is assumed that at most one checkpoint is finalized by this
        method. Additionally, if an exception is raised, it is assumed a
        new checkpoint was not finalized.

        :param str title: The title of the save. If a title is given, the
            configuration will be saved as a new checkpoint and put in a
            timestamped directory. `title` has no effect if temporary is true.

        :param bool temporary: Indicates whether the changes made will
            be quickly reversed in the future (challenges)

        :raises .PluginError: when save is unsuccessful

        """

    def rollback_checkpoints(rollback=1):
        """Revert `rollback` number of configuration checkpoints.

        :raises .PluginError: when configuration cannot be fully reverted

        """

    def recovery_routine():  # type: ignore
        """Revert configuration to most recent finalized checkpoint.

        Remove all changes (temporary and permanent) that have not been
        finalized. This is useful to protect against crashes and other
        execution interruptions.

        :raises .errors.PluginError: If unable to recover the configuration

        """

    def config_test():  # type: ignore
        """Make sure the configuration is valid.

        :raises .MisconfigurationError: when the config is not in a usable state

        """

    def restart():  # type: ignore
        """Restart or refresh the server content.

        :raises .PluginError: when server cannot be restarted

        """


class IDisplay(zope.interface.Interface):
    """Generic display."""
    # see https://github.com/certbot/certbot/issues/3915

    def notification(message, pause, wrap=True, force_interactive=False):
        """Displays a string message

        :param str message: Message to display
        :param bool pause: Whether or not the application should pause for
            confirmation (if available)
        :param bool wrap: Whether or not the application should wrap text
        :param bool force_interactive: True if it's safe to prompt the user
            because it won't cause any workflow regressions

        """

    def menu(message, choices, ok_label=None,
             cancel_label=None, help_label=None,
             default=None, cli_flag=None, force_interactive=False):
        """Displays a generic menu.

        When not setting force_interactive=True, you must provide a
        default value.

        :param str message: message to display

        :param choices: choices
        :type choices: :class:`list` of :func:`tuple` or :class:`str`

        :param str ok_label: label for OK button (UNUSED)
        :param str cancel_label: label for Cancel button (UNUSED)
        :param str help_label: label for Help button (UNUSED)
        :param int default: default (non-interactive) choice from the menu
        :param str cli_flag: to automate choice from the menu, eg "--keep"
        :param bool force_interactive: True if it's safe to prompt the user
            because it won't cause any workflow regressions

        :returns: tuple of (`code`, `index`) where
            `code` - str display exit code
            `index` - int index of the user's selection

        :raises errors.MissingCommandlineFlag: if called in non-interactive
            mode without a default set

        """

    def input(message, default=None, cli_args=None, force_interactive=False):
        """Accept input from the user.

        When not setting force_interactive=True, you must provide a
        default value.

        :param str message: message to display to the user
        :param str default: default (non-interactive) response to prompt
        :param bool force_interactive: True if it's safe to prompt the user
            because it won't cause any workflow regressions

        :returns: tuple of (`code`, `input`) where
            `code` - str display exit code
            `input` - str of the user's input
        :rtype: tuple

        :raises errors.MissingCommandlineFlag: if called in non-interactive
            mode without a default set

        """

    def yesno(message, yes_label="Yes", no_label="No", default=None,
              cli_args=None, force_interactive=False):
        """Query the user with a yes/no question.

        Yes and No label must begin with different letters.

        When not setting force_interactive=True, you must provide a
        default value.

        :param str message: question for the user
        :param str default: default (non-interactive) choice from the menu
        :param str cli_flag: to automate choice from the menu, eg "--redirect / --no-redirect"
        :param bool force_interactive: True if it's safe to prompt the user
            because it won't cause any workflow regressions

        :returns: True for "Yes", False for "No"
        :rtype: bool

        :raises errors.MissingCommandlineFlag: if called in non-interactive
            mode without a default set

        """

    def checklist(message, tags, default=None, cli_args=None, force_interactive=False):
        """Allow for multiple selections from a menu.

        When not setting force_interactive=True, you must provide a
        default value.

        :param str message: message to display to the user
        :param list tags: where each is of type :class:`str` len(tags) > 0
        :param str default: default (non-interactive) state of the checklist
        :param str cli_flag: to automate choice from the menu, eg "--domains"
        :param bool force_interactive: True if it's safe to prompt the user
            because it won't cause any workflow regressions

        :returns: tuple of the form (code, list_tags) where
            `code` - int display exit code
            `list_tags` - list of str tags selected by the user
        :rtype: tuple

        :raises errors.MissingCommandlineFlag: if called in non-interactive
            mode without a default set

        """

    def directory_select(self, message, default=None,
                         cli_flag=None, force_interactive=False):
        """Display a directory selection screen.

        When not setting force_interactive=True, you must provide a
        default value.

        :param str message: prompt to give the user
        :param default: the default value to return, if one exists, when
            using the NoninteractiveDisplay
        :param str cli_flag: option used to set this value with the CLI,
            if one exists, to be included in error messages given by
            NoninteractiveDisplay
        :param bool force_interactive: True if it's safe to prompt the user
            because it won't cause any workflow regressions

        :returns: tuple of the form (`code`, `string`) where
            `code` - int display exit code
            `string` - input entered by the user

        """


class IReporter(zope.interface.Interface):
    """Interface to collect and display information to the user."""

    HIGH_PRIORITY = zope.interface.Attribute(
        "Used to denote high priority messages")
    MEDIUM_PRIORITY = zope.interface.Attribute(
        "Used to denote medium priority messages")
    LOW_PRIORITY = zope.interface.Attribute(
        "Used to denote low priority messages")

    def add_message(self, msg, priority, on_crash=True):
        """Adds msg to the list of messages to be printed.

        :param str msg: Message to be displayed to the user.

        :param int priority: One of HIGH_PRIORITY, MEDIUM_PRIORITY, or
            LOW_PRIORITY.

        :param bool on_crash: Whether or not the message should be printed if
            the program exits abnormally.

        """

    def print_messages(self):
        """Prints messages to the user and clears the message queue."""


@six.add_metaclass(abc.ABCMeta)
class RenewableCert(object):
    """Interface to a certificate lineage."""

    @abc.abstractproperty
    def cert_path(self):
        """Path to the certificate file.

        :rtype: str

        """

    @abc.abstractproperty
    def key_path(self):
        """Path to the private key file.

        :rtype: str

        """

    @abc.abstractproperty
    def chain_path(self):
        """Path to the certificate chain file.

        :rtype: str

        """

    @abc.abstractproperty
    def fullchain_path(self):
        """Path to the full chain file.

        The full chain is the certificate file plus the chain file.

        :rtype: str

        """

    @abc.abstractproperty
    def privkey_fullchain_path(self):
        """Path to the file containing the private key and the full chain.

        The full chain is the certificate file plus the chain file.

        :rtype: str

        """

    @abc.abstractproperty
    def lineagename(self):
        """Name given to the certificate lineage.

        :rtype: str

        """

    @abc.abstractmethod
    def names(self):
        """What are the subject names of this certificate?

        :returns: the subject names
        :rtype: `list` of `str`
        :raises .CertStorageError: if could not find cert file.

        """

# Updater interfaces
#
# When "certbot renew" is run, Certbot will iterate over each lineage and check
# if the selected installer for that lineage is a subclass of each updater
# class. If it is and the update of that type is configured to be run for that
# lineage, the relevant update function will be called for it. These functions
# are never called for other subcommands, so if an installer wants to perform
# an update during the run or install subcommand, it should do so when
# :func:`IInstaller.deploy_cert` is called.

@six.add_metaclass(abc.ABCMeta)
class GenericUpdater(object):
    """Interface for update types not currently specified by Certbot.

    This class allows plugins to perform types of updates that Certbot hasn't
    defined (yet).

    To make use of this interface, the installer should implement the interface
    methods, and interfaces.GenericUpdater.register(InstallerClass) should
    be called from the installer code.

    The plugins implementing this enhancement are responsible of handling
    the saving of configuration checkpoints as well as other calls to
    interface methods of `interfaces.IInstaller` such as prepare() and restart()
    """

    @abc.abstractmethod
    def generic_updates(self, lineage, *args, **kwargs):
        """Perform any update types defined by the installer.

        If an installer is a subclass of the class containing this method, this
        function will always be called when "certbot renew" is run. If the
        update defined by the installer should be run conditionally, the
        installer needs to handle checking the conditions itself.

        This method is called once for each lineage.

        :param lineage: Certificate lineage object
        :type lineage: RenewableCert

        """


@six.add_metaclass(abc.ABCMeta)
class RenewDeployer(object):
    """Interface for update types run when a lineage is renewed

    This class allows plugins to perform types of updates that need to run at
    lineage renewal that Certbot hasn't defined (yet).

    To make use of this interface, the installer should implement the interface
    methods, and interfaces.RenewDeployer.register(InstallerClass) should
    be called from the installer code.
    """

    @abc.abstractmethod
    def renew_deploy(self, lineage, *args, **kwargs):
        """Perform updates defined by installer when a certificate has been renewed

        If an installer is a subclass of the class containing this method, this
        function will always be called when a certficate has been renewed by
        running "certbot renew". For example if a plugin needs to copy a
        certificate over, or change configuration based on the new certificate.

        This method is called once for each lineage renewed

        :param lineage: Certificate lineage object
        :type lineage: RenewableCert

        """
