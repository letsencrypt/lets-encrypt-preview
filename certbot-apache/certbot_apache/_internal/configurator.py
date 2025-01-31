"""Apache Configurator."""
# pylint: disable=too-many-lines
from collections import defaultdict
import copy
import fnmatch
import logging
import re
import socket
import time
from typing import Any
from typing import Callable
from typing import cast
from typing import DefaultDict
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence
from typing import Set
from typing import Tuple
from typing import Type
from typing import Union

from acme import challenges
from certbot import achallenges
from certbot import errors
from certbot import util
from certbot.compat import filesystem
from certbot.compat import os
from certbot.display import util as display_util
from certbot.interfaces import RenewableCert
from certbot.plugins import common
from certbot.plugins.enhancements import AutoHSTSEnhancement
from certbot.plugins.util import path_surgery
from certbot_apache._internal import apache_util
from certbot_apache._internal import assertions
from certbot_apache._internal import constants
from certbot_apache._internal import display_ops
from certbot_apache._internal import dualparser
from certbot_apache._internal import http_01
from certbot_apache._internal import obj
from certbot_apache._internal import parser
from certbot_apache._internal.apacheparser import ApacheBlockNode

try:
    import apacheconfig
    HAS_APACHECONFIG = True
except ImportError:  # pragma: no cover
    HAS_APACHECONFIG = False


logger = logging.getLogger(__name__)


class OsOptions:
    """
    Dedicated class to describe the OS specificities (eg. paths, binary names)
    that the Apache configurator needs to be aware to operate properly.
    """
    def __init__(self,
                 server_root: str = "/etc/apache2",
                 vhost_root: str = "/etc/apache2/sites-available",
                 vhost_files: str = "*",
                 logs_root: str = "/var/log/apache2",
                 ctl: str = "apache2ctl",
                 version_cmd: Optional[List[str]] = None,
                 restart_cmd: Optional[List[str]] = None,
                 restart_cmd_alt: Optional[List[str]] = None,
                 conftest_cmd: Optional[List[str]] = None,
                 enmod: Optional[str] = None,
                 dismod: Optional[str] = None,
                 le_vhost_ext: str = "-le-ssl.conf",
                 handle_modules: bool = False,
                 handle_sites: bool = False,
                 challenge_location: str = "/etc/apache2",
                 apache_bin: Optional[str] = None,
                 ) -> None:
        self.server_root = server_root
        self.vhost_root = vhost_root
        self.vhost_files = vhost_files
        self.logs_root = logs_root
        self.ctl = ctl
        self.version_cmd = ['apache2ctl', '-v'] if not version_cmd else version_cmd
        self.restart_cmd = ['apache2ctl', 'graceful'] if not restart_cmd else restart_cmd
        self.restart_cmd_alt = restart_cmd_alt
        self.conftest_cmd = ['apache2ctl', 'configtest'] if not conftest_cmd else conftest_cmd
        syntax_tests_cmd_base = [ctl, '-t', '-D']
        self.get_defines_cmd = syntax_tests_cmd_base + ['DUMP_RUN_CFG']
        self.get_includes_cmd = syntax_tests_cmd_base + ['DUMP_INCLUDES']
        self.get_modules_cmd = syntax_tests_cmd_base + ['DUMP_MODULES']
        self.enmod = enmod
        self.dismod = dismod
        self.le_vhost_ext = le_vhost_ext
        self.handle_modules = handle_modules
        self.handle_sites = handle_sites
        self.challenge_location = challenge_location
        self.bin = apache_bin


# TODO: Augeas sections ie. <VirtualHost>, <IfModule> beginning and closing
# tags need to be the same case, otherwise Augeas doesn't recognize them.
# This is not able to be completely remedied by regular expressions because
# Augeas views <VirtualHost> </Virtualhost> as an error. This will just
# require another check_parsing_errors() after all files are included...
# (after a find_directive search is executed currently). It can be a one
# time check however because all of LE's transactions will ensure
# only properly formed sections are added.

# Note: This protocol works for filenames with spaces in it, the sites are
# properly set up and directives are changed appropriately, but Apache won't
# recognize names in sites-enabled that have spaces. These are not added to the
# Apache configuration. It may be wise to warn the user if they are trying
# to use vhost filenames that contain spaces and offer to change ' ' to '_'

# Note: FILEPATHS and changes to files are transactional.  They are copied
# over before the updates are made to the existing files. NEW_FILES is
# transactional due to the use of register_file_creation()


# TODO: Verify permissions on configuration root... it is easier than
#     checking permissions on each of the relative directories and less error
#     prone.
# TODO: Write a server protocol finder. Listen <port> <protocol> or
#     Protocol <protocol>.  This can verify partial setups are correct
# TODO: Add directives to sites-enabled... not sites-available.
#     sites-available doesn't allow immediate find_dir search even with save()
#     and load()
class ApacheConfigurator(common.Configurator):
    """Apache configurator.

    :ivar config: Configuration.
    :type config: certbot.configuration.NamespaceConfig

    :ivar parser: Handles low level parsing
    :type parser: :class:`~certbot_apache._internal.parser`

    :ivar tup version: version of Apache
    :ivar list vhosts: All vhosts found in the configuration
        (:class:`list` of :class:`~certbot_apache._internal.obj.VirtualHost`)

    :ivar dict assoc: Mapping between domains and vhosts

    """

    description: str = "Apache Web Server plugin"
    if os.environ.get("CERTBOT_DOCS") == "1":
        description += (  # pragma: no cover
            " (Please note that the default values of the Apache plugin options"
            " change depending on the operating system Certbot is run on.)"
        )

    OS_DEFAULTS: OsOptions = OsOptions()

    def pick_apache_config(self, warn_on_no_mod_ssl: bool = True) -> str:
        """
        Pick the appropriate TLS Apache configuration file for current version of Apache and OS.

        :param bool warn_on_no_mod_ssl: True if we should warn if mod_ssl is not found.

        :return: the path to the TLS Apache configuration file to use
        :rtype: str
        """
        # Disabling TLS session tickets is supported by Apache 2.4.11+ and OpenSSL 1.0.2l+.
        # So for old versions of Apache we pick a configuration without this option.
        min_openssl_version = util.parse_loose_version('1.0.2l')
        openssl_version = self.openssl_version(warn_on_no_mod_ssl)
        if self.version < (2, 4, 11) or not openssl_version or \
            util.parse_loose_version(openssl_version) < min_openssl_version:
            return apache_util.find_ssl_apache_conf("old")
        return apache_util.find_ssl_apache_conf("current")

    def _override_cmds(self) -> None:
        """
        Set our various command binaries to whatever the user has overridden for apachectl
        """
        self.options.version_cmd[0] = self.options.ctl
        self.options.restart_cmd[0] = self.options.ctl
        self.options.conftest_cmd[0] = self.options.ctl
        self.options.get_modules_cmd[0] = self.options.ctl
        self.options.get_includes_cmd[0] = self.options.ctl
        self.options.get_defines_cmd[0] = self.options.ctl

    def _prepare_options(self) -> None:
        """
        Set the values possibly changed by command line parameters to
        OS_DEFAULTS constant dictionary
        """
        opts = ["enmod", "dismod", "le_vhost_ext", "server_root", "vhost_root",
                "logs_root", "challenge_location", "handle_modules", "handle_sites",
                "ctl", "bin"]
        for o in opts:
            # Config options use dashes instead of underscores
            if self.conf(o.replace("_", "-")) is not None:
                setattr(self.options, o, self.conf(o.replace("_", "-")))
            else:
                setattr(self.options, o, getattr(self.OS_DEFAULTS, o))

        self._override_cmds()

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None]) -> None:
        # When adding, modifying or deleting command line arguments, be sure to
        # include the changes in the list used in method _prepare_options() to
        # ensure consistent behavior.

        # Respect CERTBOT_DOCS environment variable and use default values from
        # base class regardless of the underlying distribution (overrides).
        if os.environ.get("CERTBOT_DOCS") == "1":
            DEFAULTS = ApacheConfigurator.OS_DEFAULTS
        else:
            # cls.OS_DEFAULTS can be distribution specific, see override classes
            DEFAULTS = cls.OS_DEFAULTS
        add("enmod", default=DEFAULTS.enmod,
            help="Path to the Apache 'a2enmod' binary")
        add("dismod", default=DEFAULTS.dismod,
            help="Path to the Apache 'a2dismod' binary")
        add("le-vhost-ext", default=DEFAULTS.le_vhost_ext,
            help="SSL vhost configuration extension")
        add("server-root", default=DEFAULTS.server_root,
            help="Apache server root directory")
        add("vhost-root", default=None,
            help="Apache server VirtualHost configuration root")
        add("logs-root", default=DEFAULTS.logs_root,
            help="Apache server logs directory")
        add("challenge-location",
            default=DEFAULTS.challenge_location,
            help="Directory path for challenge configuration")
        add("handle-modules", default=DEFAULTS.handle_modules,
            help="Let installer handle enabling required modules for you " +
                 "(Only Ubuntu/Debian currently)")
        add("handle-sites", default=DEFAULTS.handle_sites,
            help="Let installer handle enabling sites for you " +
                 "(Only Ubuntu/Debian currently)")
        add("ctl", default=DEFAULTS.ctl,
            help="Full path to Apache control script")
        add("bin", default=DEFAULTS.bin,
            help="Full path to apache2/httpd binary")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize an Apache Configurator.

        :param tup version: version of Apache as a tuple (2, 4, 7)
            (used mostly for unittesting)

        """
        version = kwargs.pop("version", None)
        use_parsernode = kwargs.pop("use_parsernode", False)
        openssl_version = kwargs.pop("openssl_version", None)
        super().__init__(*args, **kwargs)

        # Add name_server association dict
        self.assoc: Dict[str, obj.VirtualHost] = {}
        # Outstanding challenges
        self._chall_out: Set[achallenges.AnnotatedChallenge] = set()
        # List of vhosts configured per wildcard domain on this run.
        # used by deploy_cert() and enhance()
        self._wildcard_vhosts: Dict[str, List[obj.VirtualHost]] = {}
        # Maps enhancements to vhosts we've enabled the enhancement for
        self._enhanced_vhosts: DefaultDict[str, Set[obj.VirtualHost]] = defaultdict(set)
        # Temporary state for AutoHSTS enhancement
        self._autohsts: Dict[str, Dict[str, Union[int, float]]] = {}
        # Reverter save notes
        self.save_notes: str = ""
        # Should we use ParserNode implementation instead of the old behavior
        self.USE_PARSERNODE = use_parsernode
        # Saves the list of file paths that were parsed initially, and
        # not added to parser tree by self.conf("vhost-root") for example.
        self.parsed_paths: List[str] = []
        # These will be set in the prepare function
        self._prepared: bool = False
        self.parser: parser.ApacheParser
        self.parser_root: Optional[dualparser.DualBlockNode] = None
        self.version = version
        self._openssl_version: Optional[str] = openssl_version
        self.vhosts: List[obj.VirtualHost]
        self.options = copy.deepcopy(self.OS_DEFAULTS)
        self._enhance_func: Dict[str, Callable[[obj.VirtualHost, Any], None]] = {
            "redirect": self._enable_redirect,
            "ensure-http-header": self._set_http_header,
            "staple-ocsp": self._enable_ocsp_stapling,
        }

    @property
    def mod_ssl_conf(self) -> str:
        """Full absolute path to SSL configuration file."""
        return os.path.join(self.config.config_dir, constants.MOD_SSL_CONF_DEST)

    @property
    def updated_mod_ssl_conf_digest(self) -> str:
        """Full absolute path to digest of updated SSL configuration file."""
        return os.path.join(self.config.config_dir, constants.UPDATED_MOD_SSL_CONF_DIGEST)

    def _open_module_file(self, ssl_module_location: str) -> Optional[bytes]:
        """Extract the open lines of openssl_version for testing purposes"""
        try:
            with open(ssl_module_location, mode="rb") as f:
                contents = f.read()
        except OSError as error:
            logger.debug(str(error), exc_info=True)
            return None
        return contents

    def openssl_version(self, warn_on_no_mod_ssl: bool = True) -> Optional[str]:
        """Lazily retrieve openssl version

        :param bool warn_on_no_mod_ssl: `True` if we should warn if mod_ssl is not found. Set to
            `False` when we know we'll try to enable mod_ssl later. This is currently debian/ubuntu,
            when called from `prepare`.

        :return: the OpenSSL version as a string, or None.
        :rtype: str or None
        """
        if self._openssl_version:
            return self._openssl_version
        # Step 1. Determine the location of ssl_module
        try:
            ssl_module_location = self.parser.modules['ssl_module']
        except KeyError:
            if warn_on_no_mod_ssl:
                logger.warning("Could not find ssl_module; not disabling session tickets.")
            return None
        if ssl_module_location:
            # Possibility A: ssl_module is a DSO
            ssl_module_location = self.parser.standard_path_from_server_root(ssl_module_location)
        else:
            # Possibility B: ssl_module is statically linked into Apache
            if self.options.bin:
                ssl_module_location = self.options.bin
            else:
                logger.warning("ssl_module is statically linked but --apache-bin is "
                               "missing; not disabling session tickets.")
                return None
        # Step 2. Grep in the binary for openssl version
        contents = self._open_module_file(ssl_module_location)
        if not contents:
            logger.warning("Unable to read ssl_module file; not disabling session tickets.")
            return None
        # looks like: OpenSSL 1.0.2s  28 May 2019
        matches = re.findall(br"OpenSSL ([0-9]\.[^ ]+) ", contents)
        if not matches:
            logger.warning("Could not find OpenSSL version; not disabling session tickets.")
            return None
        self._openssl_version = matches[0].decode('UTF-8')
        return self._openssl_version

    def prepare(self) -> None:
        """Prepare the authenticator/installer.

        :raises .errors.NoInstallationError: If Apache configs cannot be found
        :raises .errors.MisconfigurationError: If Apache is misconfigured
        :raises .errors.NotSupportedError: If Apache version is not supported
        :raises .errors.PluginError: If there is any other error

        """
        self._prepare_options()

        # Verify Apache is installed
        self._verify_exe_availability(self.options.ctl)

        # Make sure configuration is valid
        self.config_test()

        # Set Version
        if self.version is None:
            self.version = self.get_version()
            logger.debug('Apache version is %s',
                         '.'.join(str(i) for i in self.version))
        if self.version < (2, 4):
            raise errors.NotSupportedError(
                "Apache Version {0} not supported.".format(str(self.version)))

        # Recover from previous crash before Augeas initialization to have the
        # correct parse tree from the get go.
        self.recovery_routine()
        # Perform the actual Augeas initialization to be able to react
        self.parser = self.get_parser()

        # Set up ParserNode root
        pn_meta = {"augeasparser": self.parser,
                   "augeaspath": self.parser.get_root_augpath(),
                   "ac_ast": None}
        if self.USE_PARSERNODE:
            parser_root = self.get_parsernode_root(pn_meta)
            self.parser_root = parser_root
            self.parsed_paths = parser_root.parsed_paths()

        # Check for errors in parsing files with Augeas
        self.parser.check_parsing_errors("httpd.aug")

        # Get all of the available vhosts
        self.vhosts = self.get_virtual_hosts()

        # We may try to enable mod_ssl later. If so, we shouldn't warn if we can't find it now.
        # This is currently only true for debian/ubuntu.
        warn_on_no_mod_ssl = not self.options.handle_modules
        self.install_ssl_options_conf(self.mod_ssl_conf,
                                      self.updated_mod_ssl_conf_digest,
                                      warn_on_no_mod_ssl)

        # Prevent two Apache plugins from modifying a config at once
        try:
            util.lock_dir_until_exit(self.options.server_root)
        except (OSError, errors.LockError):
            logger.debug("Encountered error:", exc_info=True)
            raise errors.PluginError(
                "Unable to create a lock file in {0}. Are you running"
                " Certbot with sufficient privileges to modify your"
                " Apache configuration?".format(self.options.server_root))
        self._prepared = True

    def save(self, title: Optional[str] = None, temporary: bool = False) -> None:
        """Saves all changes to the configuration files.

        This function first checks for save errors, if none are found,
        all configuration changes made will be saved. According to the
        function parameters. If an exception is raised, a new checkpoint
        was not created.

        :param str title: The title of the save. If a title is given, the
            configuration will be saved as a new checkpoint and put in a
            timestamped directory.

        :param bool temporary: Indicates whether the changes made will
            be quickly reversed in the future (ie. challenges)

        """
        save_files = self.parser.unsaved_files()
        if save_files:
            self.add_to_checkpoint(save_files,
                                   self.save_notes, temporary=temporary)
        # Handle the parser specific tasks
        self.parser.save(save_files)
        if title and not temporary:
            self.finalize_checkpoint(title)

    def recovery_routine(self) -> None:
        """Revert all previously modified files.

        Reverts all modified files that have not been saved as a checkpoint

        :raises .errors.PluginError: If unable to recover the configuration

        """
        super().recovery_routine()
        # Reload configuration after these changes take effect if needed
        # ie. ApacheParser has been initialized.
        if hasattr(self, "parser"):
            # TODO: wrap into non-implementation specific  parser interface
            self.parser.aug.load()

    def revert_challenge_config(self) -> None:
        """Used to cleanup challenge configurations.

        :raises .errors.PluginError: If unable to revert the challenge config.

        """
        self.revert_temporary_config()
        self.parser.aug.load()

    def rollback_checkpoints(self, rollback: int = 1) -> None:
        """Rollback saved checkpoints.

        :param int rollback: Number of checkpoints to revert

        :raises .errors.PluginError: If there is a problem with the input or
            the function is unable to correctly revert the configuration

        """
        super().rollback_checkpoints(rollback)
        self.parser.aug.load()

    def _verify_exe_availability(self, exe: str) -> None:
        """Checks availability of Apache executable"""
        if not util.exe_exists(exe):
            if not path_surgery(exe):
                raise errors.NoInstallationError(
                    'Cannot find Apache executable {0}'.format(exe))

    def get_parser(self) -> parser.ApacheParser:
        """Initializes the ApacheParser"""
        # If user provided vhost_root value in command line, use it
        return parser.ApacheParser(
            self.options.server_root, self, self.conf("vhost-root"), version=self.version)

    def get_parsernode_root(self, metadata: Dict[str, Any]) -> dualparser.DualBlockNode:
        """Initializes the ParserNode parser root instance."""

        if HAS_APACHECONFIG:
            apache_vars = {
                "defines": apache_util.parse_defines(self.options.get_defines_cmd),
                "includes": apache_util.parse_includes(self.options.get_includes_cmd),
                "modules": apache_util.parse_modules(self.options.get_modules_cmd),
            }
            metadata["apache_vars"] = apache_vars

            with open(self.parser.loc["root"]) as f:
                with apacheconfig.make_loader(writable=True,
                                              **apacheconfig.flavors.NATIVE_APACHE) as loader:
                    metadata["ac_ast"] = loader.loads(f.read())

        return dualparser.DualBlockNode(
            name=assertions.PASS,
            ancestor=None,
            filepath=self.parser.loc["root"],
            metadata=metadata,
        )

    def deploy_cert(
        self, domain: str, cert_path: str, key_path: str,
        chain_path: Optional[str] = None, fullchain_path: Optional[str] = None
    ) -> None:
        """Deploys certificate to specified virtual host.

        Currently tries to find the last directives to deploy the certificate
        in the VHost associated with the given domain. If it can't find the
        directives, it searches the "included" confs. The function verifies
        that it has located the three directives and finally modifies them
        to point to the correct destination. After the certificate is
        installed, the VirtualHost is enabled if it isn't already.

        .. todo:: Might be nice to remove chain directive if none exists
                  This shouldn't happen within certbot though

        :raises errors.PluginError: When unable to deploy certificate due to
            a lack of directives

        """
        vhosts = self.choose_vhosts(domain)
        for vhost in vhosts:
            self._deploy_cert(vhost, cert_path, key_path, chain_path, fullchain_path)
            display_util.notify("Successfully deployed certificate for {} to {}"
                                .format(domain, vhost.filep))

    def choose_vhosts(self, domain: str, create_if_no_ssl: bool = True) -> List[obj.VirtualHost]:
        """
        Finds VirtualHosts that can be used with the provided domain

        :param str domain: Domain name to match VirtualHosts to
        :param bool create_if_no_ssl: If found VirtualHost doesn't have a HTTPS
            counterpart, should one get created

        :returns: List of VirtualHosts or None
        :rtype: `list` of :class:`~certbot_apache._internal.obj.VirtualHost`
        """

        if util.is_wildcard_domain(domain):
            if domain in self._wildcard_vhosts:
                # Vhosts for a wildcard domain were already selected
                return self._wildcard_vhosts[domain]
            # Ask user which VHosts to support.
            # Returned objects are guaranteed to be ssl vhosts
            return self._choose_vhosts_wildcard(domain, create_if_no_ssl)
        else:
            return [self.choose_vhost(domain, create_if_no_ssl)]

    def _vhosts_for_wildcard(self, domain: str) -> List[obj.VirtualHost]:
        """
        Get VHost objects for every VirtualHost that the user wants to handle
        with the wildcard certificate.
        """

        # Collect all vhosts that match the name
        matched: Set[obj.VirtualHost] = set()
        for vhost in self.vhosts:
            for name in vhost.get_names():
                if self._in_wildcard_scope(name, domain):
                    matched.add(vhost)

        return list(matched)

    def _generate_no_suitable_vhost_error(self, target_name: str) -> errors.PluginError:
        """
        Prepare an error to notify the user that Certbot could not find a vhost
        to secure.
        :param str target_name: The server name that could not be mapped
        :return: An instance of PluginError
        :rtype: errors.PluginError
        """
        return errors.PluginError(
            "Certbot could not find a VirtualHost for {0} in the Apache "
            "configuration. Please create a VirtualHost with a ServerName "
            "matching {0} and try again.".format(target_name)
        )

    def _in_wildcard_scope(self, name: str, domain: str) -> Optional[bool]:
        """
        Helper method for _vhosts_for_wildcard() that makes sure that the domain
        is in the scope of wildcard domain.

        eg. in scope: domain = *.wild.card, name = 1.wild.card
        not in scope: domain = *.wild.card, name = 1.2.wild.card
        """
        if len(name.split(".")) == len(domain.split(".")):
            return fnmatch.fnmatch(name, domain)
        return None

    def _choose_vhosts_wildcard(self, domain: str, create_ssl: bool = True
                                ) -> List[obj.VirtualHost]:
        """Prompts user to choose vhosts to install a wildcard certificate for"""

        # Get all vhosts that are covered by the wildcard domain
        vhosts: List[obj.VirtualHost] = self._vhosts_for_wildcard(domain)

        # Go through the vhosts, making sure that we cover all the names
        # present, but preferring the SSL vhosts
        filtered_vhosts = {}
        for vhost in vhosts:
            for name in vhost.get_names():
                if vhost.ssl:
                    # Always prefer SSL vhosts
                    filtered_vhosts[name] = vhost
                elif name not in filtered_vhosts and create_ssl:
                    # Add if not in list previously
                    filtered_vhosts[name] = vhost

        # Only unique VHost objects
        dialog_input = set(filtered_vhosts.values())

        # Ask the user which of names to enable, expect list of names back
        dialog_output = display_ops.select_vhost_multiple(list(dialog_input))

        if not dialog_output:
            raise self._generate_no_suitable_vhost_error(domain)

        # Make sure we create SSL vhosts for the ones that are HTTP only
        # if requested.
        return_vhosts = []
        for vhost in dialog_output:
            if not vhost.ssl:
                return_vhosts.append(self.make_vhost_ssl(vhost))
            else:
                return_vhosts.append(vhost)

        self._wildcard_vhosts[domain] = return_vhosts
        return return_vhosts

    def _deploy_cert(
        self, vhost: obj.VirtualHost, cert_path: str, key_path: str,
        chain_path: Optional[str] = None, fullchain_path: Optional[str] = None,
    ) -> None:
        """
        Helper function for deploy_cert() that handles the actual deployment
        this exists because we might want to do multiple deployments per
        domain originally passed for deploy_cert(). This is especially true
        with wildcard certificates
        """
        # This is done first so that ssl module is enabled and cert_path,
        # cert_key... can all be parsed appropriately
        self.prepare_server_https("443")

        # If we haven't managed to enable mod_ssl by this point, error out
        if "ssl_module" not in self.parser.modules:
            raise errors.MisconfigurationError("Could not find ssl_module; "
                                               "not installing certificate.")

        # Add directives and remove duplicates
        self._add_dummy_ssl_directives(vhost.path)
        self._clean_vhost(vhost)

        path: Dict[str, Any] = {
            "cert_path": self.parser.find_dir("SSLCertificateFile", None, vhost.path),
            "cert_key": self.parser.find_dir("SSLCertificateKeyFile", None, vhost.path),
        }

        # Only include if a certificate chain is specified
        if chain_path is not None:
            path["chain_path"] = self.parser.find_dir(
                "SSLCertificateChainFile", None, vhost.path)

        logger.info("Deploying Certificate to VirtualHost %s", vhost.filep)

        if self.version < (2, 4, 8) or (chain_path and not fullchain_path):
            # install SSLCertificateFile, SSLCertificateKeyFile,
            # and SSLCertificateChainFile directives
            set_cert_path = cert_path
            self.parser.aug.set(path["cert_path"][-1], cert_path)
            self.parser.aug.set(path["cert_key"][-1], key_path)
            if chain_path is not None:
                self.parser.add_dir(vhost.path,
                                    "SSLCertificateChainFile", chain_path)
            else:
                raise errors.PluginError("--chain-path is required for your "
                                         "version of Apache")
        else:
            if not fullchain_path:
                raise errors.PluginError("Please provide the --fullchain-path "
                                         "option pointing to your full chain file")
            set_cert_path = fullchain_path
            self.parser.aug.set(path["cert_path"][-1], fullchain_path)
            self.parser.aug.set(path["cert_key"][-1], key_path)

        # Enable the new vhost if needed
        if not vhost.enabled:
            self.enable_site(vhost)

        # Save notes about the transaction that took place
        self.save_notes += ("Changed vhost at %s with addresses of %s\n"
                            "\tSSLCertificateFile %s\n"
                            "\tSSLCertificateKeyFile %s\n" %
                            (vhost.filep,
                             ", ".join(str(addr) for addr in vhost.addrs),
                             set_cert_path, key_path))
        if chain_path is not None:
            self.save_notes += "\tSSLCertificateChainFile %s\n" % chain_path

    def choose_vhost(self, target_name: str, create_if_no_ssl: bool = True) -> obj.VirtualHost:
        """Chooses a virtual host based on the given domain name.

        If there is no clear virtual host to be selected, the user is prompted
        with all available choices.

        The returned vhost is guaranteed to have TLS enabled unless
        create_if_no_ssl is set to False, in which case there is no such guarantee
        and the result is not cached.

        :param str target_name: domain name
        :param bool create_if_no_ssl: If found VirtualHost doesn't have a HTTPS
            counterpart, should one get created

        :returns: vhost associated with name
        :rtype: :class:`~certbot_apache._internal.obj.VirtualHost`

        :raises .errors.PluginError: If no vhost is available or chosen

        """
        # Allows for domain names to be associated with a virtual host
        if target_name in self.assoc:
            return self.assoc[target_name]

        # Try to find a reasonable vhost
        vhost = self._find_best_vhost(target_name)
        if vhost is not None:
            if not create_if_no_ssl:
                return vhost
            if not vhost.ssl:
                vhost = self.make_vhost_ssl(vhost)

            self._add_servername_alias(target_name, vhost)
            self.assoc[target_name] = vhost
            return vhost

        # Negate create_if_no_ssl value to indicate if we want a SSL vhost
        # to get created if a non-ssl vhost is selected.
        return self._choose_vhost_from_list(target_name, temp=not create_if_no_ssl)

    def _choose_vhost_from_list(self, target_name: str,
                                temp: bool = False) -> obj.VirtualHost:
        # Select a vhost from a list
        vhost = display_ops.select_vhost(target_name, self.vhosts)
        if vhost is None:
            raise self._generate_no_suitable_vhost_error(target_name)
        if temp:
            return vhost
        if not vhost.ssl:
            addrs = self._get_proposed_addrs(vhost, "443")
            # TODO: Conflicts is too conservative
            if not any(one_vhost.enabled and one_vhost.conflicts(addrs) for
                       one_vhost in self.vhosts):
                vhost = self.make_vhost_ssl(vhost)
            else:
                logger.error(
                    "The selected vhost would conflict with other HTTPS "
                    "VirtualHosts within Apache. Please select another "
                    "vhost or add ServerNames to your configuration.")
                raise errors.PluginError("VirtualHost not able to be selected.")

        self._add_servername_alias(target_name, vhost)
        self.assoc[target_name] = vhost
        return vhost

    def domain_in_names(self, names: Iterable[str], target_name: str) -> bool:
        """Checks if target domain is covered by one or more of the provided
        names. The target name is matched by wildcard as well as exact match.

        :param names: server aliases
        :type names: `collections.Iterable` of `str`
        :param str target_name: name to compare with wildcards

        :returns: True if target_name is covered by a wildcard,
            otherwise, False
        :rtype: bool

        """
        # use lowercase strings because fnmatch can be case sensitive
        target_name = target_name.lower()
        for name in names:
            name = name.lower()
            # fnmatch treats "[seq]" specially and [ or ] characters aren't
            # valid in Apache but Apache doesn't error out if they are present
            if "[" not in name and fnmatch.fnmatch(target_name, name):
                return True
        return False

    def find_best_http_vhost(
        self, target: str, filter_defaults: bool, port: str = "80"
    ) -> Optional[obj.VirtualHost]:
        """Returns non-HTTPS vhost objects found from the Apache config

        :param str target: Domain name of the desired VirtualHost
        :param bool filter_defaults: whether _default_ vhosts should be
            included if it is the best match
        :param str port: port number the vhost should be listening on

        :returns: VirtualHost object that's the best match for target name
        :rtype: `obj.VirtualHost` or None
        """
        filtered_vhosts = []
        for vhost in self.vhosts:
            if any(a.is_wildcard() or a.get_port() == port for a in vhost.addrs) and not vhost.ssl:
                filtered_vhosts.append(vhost)
        return self._find_best_vhost(target, filtered_vhosts, filter_defaults)

    def _find_best_vhost(
        self, target_name: str, vhosts: Optional[List[obj.VirtualHost]] = None,
        filter_defaults: bool = True
    ) -> Optional[obj.VirtualHost]:
        """Finds the best vhost for a target_name.

        This does not upgrade a vhost to HTTPS... it only finds the most
        appropriate vhost for the given target_name.

        :param str target_name: domain handled by the desired vhost
        :param vhosts: vhosts to consider
        :type vhosts: `collections.Iterable` of :class:`~certbot_apache._internal.obj.VirtualHost`
        :param bool filter_defaults: whether a vhost with a _default_
            addr is acceptable

        :returns: VHost or None

        """
        # Points 6 - Servername SSL
        # Points 5 - Wildcard SSL
        # Points 4 - Address name with SSL
        # Points 3 - Servername no SSL
        # Points 2 - Wildcard no SSL
        # Points 1 - Address name with no SSL
        best_candidate: Optional[obj.VirtualHost] = None
        best_points: int = 0

        if vhosts is None:
            vhosts = self.vhosts

        for vhost in vhosts:
            if vhost.modmacro is True:
                continue
            names = vhost.get_names()
            if target_name in names:
                points = 3
            elif self.domain_in_names(names, target_name):
                points = 2
            elif any(addr.get_addr() == target_name for addr in vhost.addrs):
                points = 1
            else:
                # No points given if names can't be found.
                # This gets hit but doesn't register
                continue  # pragma: no cover

            if vhost.ssl:
                points += 3

            if points > best_points:
                best_points = points
                best_candidate = vhost

        # No winners here... is there only one reasonable vhost?
        if best_candidate is None:
            if filter_defaults:
                vhosts = self._non_default_vhosts(vhosts)
            # remove mod_macro hosts from reasonable vhosts
            reasonable_vhosts = [vh for vh
                                 in vhosts if vh.modmacro is False]
            if len(reasonable_vhosts) == 1:
                best_candidate = reasonable_vhosts[0]

        return best_candidate

    def _non_default_vhosts(self, vhosts: List[obj.VirtualHost]) -> List[obj.VirtualHost]:
        """Return all non _default_ only vhosts."""
        return [vh for vh in vhosts if not all(
            addr.get_addr() == "_default_" for addr in vh.addrs
        )]

    def get_all_names(self) -> Set[str]:
        """Returns all names found in the Apache Configuration.

        :returns: All ServerNames, ServerAliases, and reverse DNS entries for
                  virtual host addresses
        :rtype: set

        """
        all_names: Set[str] = set()

        vhost_macro = []

        for vhost in self.vhosts:
            all_names.update(vhost.get_names())
            if vhost.modmacro:
                vhost_macro.append(vhost.filep)

            for addr in vhost.addrs:
                if common.hostname_regex.match(addr.get_addr()):
                    all_names.add(addr.get_addr())
                else:
                    name = self.get_name_from_ip(addr)
                    if name:
                        all_names.add(name)

        if vhost_macro:
            display_util.notification(
                "Apache mod_macro seems to be in use in file(s):\n{0}"
                "\n\nUnfortunately mod_macro is not yet supported".format(
                    "\n  ".join(vhost_macro)), force_interactive=True)

        return util.get_filtered_names(all_names)

    def get_name_from_ip(self, addr: obj.Addr) -> str:
        """Returns a reverse dns name if available.

        :param addr: IP Address
        :type addr: ~.common.Addr

        :returns: name or empty string if name cannot be determined
        :rtype: str

        """
        # If it isn't a private IP, do a reverse DNS lookup
        if not common.private_ips_regex.match(addr.get_addr()):
            try:
                socket.inet_aton(addr.get_addr())
                return socket.gethostbyaddr(addr.get_addr())[0]
            except (OSError, socket.herror, socket.timeout):
                pass

        return ""

    def _get_vhost_names(self, path: Optional[str]) -> Tuple[Optional[str], List[Optional[str]]]:
        """Helper method for getting the ServerName and
        ServerAlias values from vhost in path

        :param path: Path to read ServerName and ServerAliases from

        :returns: Tuple including ServerName and `list` of ServerAlias strings
        """

        servername_match = self.parser.find_dir(
            "ServerName", None, start=path, exclude=False)
        serveralias_match = self.parser.find_dir(
            "ServerAlias", None, start=path, exclude=False)

        serveraliases = []
        for alias in serveralias_match:
            serveralias = self.parser.get_arg(alias)
            serveraliases.append(serveralias)

        servername = None
        if servername_match:
            # Get last ServerName as each overwrites the previous
            servername = self.parser.get_arg(servername_match[-1])

        return servername, serveraliases

    def _add_servernames(self, host: obj.VirtualHost) -> None:
        """Helper function for get_virtual_hosts().

        :param host: In progress vhost whose names will be added
        :type host: :class:`~certbot_apache._internal.obj.VirtualHost`

        """

        servername, serveraliases = self._get_vhost_names(host.path)

        for alias in serveraliases:
            if not host.modmacro and alias is not None:
                host.aliases.add(alias)

        if not host.modmacro:
            host.name = servername

    def _create_vhost(self, path: str) -> Optional[obj.VirtualHost]:
        """Used by get_virtual_hosts to create vhost objects

        :param str path: Augeas path to virtual host

        :returns: newly created vhost
        :rtype: :class:`~certbot_apache._internal.obj.VirtualHost`

        """
        addrs: Set[obj.Addr] = set()
        try:
            args = self.parser.aug.match(path + "/arg")
        except RuntimeError:
            logger.warning("Encountered a problem while parsing file: %s, skipping", path)
            return None
        for arg in args:
            arg_value = self.parser.get_arg(arg)
            if arg_value is not None:
                addrs.add(obj.Addr.fromstring(arg_value))
        is_ssl = False

        if self.parser.find_dir("SSLEngine", "on", start=path, exclude=False):
            is_ssl = True

        # "SSLEngine on" might be set outside of <VirtualHost>
        # Treat vhosts with port 443 as ssl vhosts
        for addr in addrs:
            if addr.get_port() == "443":
                is_ssl = True

        filename = apache_util.get_file_path(
            self.parser.aug.get(f"/augeas/files{apache_util.get_file_path(path)}/path"))
        if filename is None:
            return None

        macro = False
        if "/macro/" in path.lower():
            macro = True

        vhost_enabled = self.parser.parsed_in_original(filename)

        vhost = obj.VirtualHost(filename, path, addrs, is_ssl,
                                vhost_enabled, modmacro=macro)
        self._add_servernames(vhost)
        return vhost

    def get_virtual_hosts(self) -> List[obj.VirtualHost]:
        """
        Temporary wrapper for legacy and ParserNode version for
        get_virtual_hosts. This should be replaced with the ParserNode
        implementation when ready.
        """

        v1_vhosts = self.get_virtual_hosts_v1()
        if self.USE_PARSERNODE and HAS_APACHECONFIG:
            v2_vhosts = self.get_virtual_hosts_v2()

            for v1_vh in v1_vhosts:
                found = False
                for v2_vh in v2_vhosts:
                    if assertions.isEqualVirtualHost(v1_vh, v2_vh):
                        found = True
                        break
                if not found:
                    raise AssertionError("Equivalent for {} was not found".format(v1_vh.path))

            return v2_vhosts
        return v1_vhosts

    def get_virtual_hosts_v1(self) -> List[obj.VirtualHost]:
        """Returns list of virtual hosts found in the Apache configuration.

        :returns: List of :class:`~certbot_apache._internal.obj.VirtualHost`
            objects found in configuration
        :rtype: list

        """
        # Search base config, and all included paths for VirtualHosts
        file_paths: Dict[str, str] = {}
        internal_paths: DefaultDict[str, Set[str]] = defaultdict(set)
        vhs = []
        # Make a list of parser paths because the parser_paths
        # dictionary may be modified during the loop.
        for vhost_path in list(self.parser.parser_paths):
            paths = self.parser.aug.match(
                ("/files%s//*[label()=~regexp('%s')]" %
                 (vhost_path, parser.case_i("VirtualHost"))))
            paths = [path for path in paths if
                     "virtualhost" in os.path.basename(path).lower()]
            for path in paths:
                new_vhost = self._create_vhost(path)
                if not new_vhost:
                    continue
                internal_path = apache_util.get_internal_aug_path(new_vhost.path)
                realpath = filesystem.realpath(new_vhost.filep)
                if realpath not in file_paths:
                    file_paths[realpath] = new_vhost.filep
                    internal_paths[realpath].add(internal_path)
                    vhs.append(new_vhost)
                elif (realpath == new_vhost.filep and
                      realpath != file_paths[realpath]):
                    # Prefer "real" vhost paths instead of symlinked ones
                    # ex: sites-enabled/vh.conf -> sites-available/vh.conf

                    # remove old (most likely) symlinked one
                    new_vhs = []
                    for v in vhs:
                        if v.filep == file_paths[realpath]:
                            internal_paths[realpath].remove(
                                apache_util.get_internal_aug_path(v.path))
                        else:
                            new_vhs.append(v)
                    vhs = new_vhs

                    file_paths[realpath] = realpath
                    internal_paths[realpath].add(internal_path)
                    vhs.append(new_vhost)
                elif internal_path not in internal_paths[realpath]:
                    internal_paths[realpath].add(internal_path)
                    vhs.append(new_vhost)
        return vhs

    def get_virtual_hosts_v2(self) -> List[obj.VirtualHost]:
        """Returns list of virtual hosts found in the Apache configuration using
        ParserNode interface.
        :returns: List of :class:`~certbot_apache.obj.VirtualHost`
            objects found in configuration
        :rtype: list
        """

        if not self.parser_root:
            raise errors.Error("This ApacheConfigurator instance is not"  # pragma: no cover
                               " configured to use a node parser.")
        vhs = []
        vhosts = self.parser_root.find_blocks("VirtualHost", exclude=False)
        for vhblock in vhosts:
            vhs.append(self._create_vhost_v2(cast(ApacheBlockNode, vhblock)))
        return vhs

    def _create_vhost_v2(self, node: ApacheBlockNode) -> obj.VirtualHost:
        """Used by get_virtual_hosts_v2 to create vhost objects using ParserNode
        interfaces.
        :param ApacheBlockNode node: The BlockNode object of VirtualHost block
        :returns: newly created vhost
        :rtype: :class:`~certbot_apache.obj.VirtualHost`
        """
        addrs = set()
        for param in node.parameters:
            addrs.add(obj.Addr.fromstring(param))

        is_ssl = False
        # Exclusion to match the behavior in get_virtual_hosts_v2
        sslengine = node.find_directives("SSLEngine", exclude=False)
        if sslengine:
            for directive in sslengine:
                if directive.parameters[0].lower() == "on":
                    is_ssl = True
                    break

        # "SSLEngine on" might be set outside of <VirtualHost>
        # Treat vhosts with port 443 as ssl vhosts
        for addr in addrs:
            if addr.get_port() == "443":
                is_ssl = True

        if node.filepath is None:
            raise errors.Error("Node filepath cannot be None.")  # pragma: no cover

        enabled = apache_util.included_in_paths(node.filepath, self.parsed_paths)

        macro = False
        # Check if the VirtualHost is contained in a mod_macro block
        if node.find_ancestors("Macro"):
            macro = True
        # VirtualHost V2 is part of migration to the pure-Python Apache parser project. It is not
        # used on production as of now.
        # TODO: Use a meaning full value for augeas path instead of an empty string
        vhost = obj.VirtualHost(
            node.filepath, "", addrs, is_ssl, enabled, modmacro=macro, node=node
        )
        self._populate_vhost_names_v2(vhost)
        return vhost

    def _populate_vhost_names_v2(self, vhost: obj.VirtualHost) -> None:
        """Helper function that populates the VirtualHost names.
        :param host: In progress vhost whose names will be added
        :type host: :class:`~certbot_apache.obj.VirtualHost`
        """
        if not vhost.node:
            raise errors.PluginError("Current VirtualHost has no node.")  # pragma: no cover

        servername_match = vhost.node.find_directives("ServerName", exclude=False)
        serveralias_match = vhost.node.find_directives("ServerAlias", exclude=False)

        servername = None
        if servername_match:
            servername = servername_match[-1].parameters[-1]

        if not vhost.modmacro:
            for alias in serveralias_match:
                for serveralias in alias.parameters:
                    vhost.aliases.add(serveralias)
            vhost.name = servername

    def prepare_server_https(self, port: str, temp: bool = False) -> None:
        """Prepare the server for HTTPS.

        Make sure that the ssl_module is loaded and that the server
        is appropriately listening on port.

        :param str port: Port to listen on
        :param bool temp: If this is just temporary
        """

        self.prepare_https_modules(temp)
        self.ensure_listen(port, https=True)

    def ensure_listen(self, port: str, https: bool = False) -> None:
        """Make sure that Apache is listening on the port. Checks if the
        Listen statement for the port already exists, and adds it to the
        configuration if necessary.

        :param str port: Port number to check and add Listen for if not in
            place already
        :param bool https: If the port will be used for HTTPS

        """

        # If HTTPS requested for nonstandard port, add service definition
        if https and port != "443":
            port_service = f"{port} https"
        else:
            port_service = port

        # Check for Listen <port>
        # Note: This could be made to also look for ip:443 combo
        directives = [self.parser.get_arg(x) for x in self.parser.find_dir("Listen")]
        listens = [directive.split()[0] for directive in directives if directive]

        # Listen already in place
        if self._has_port_already(listens, port):
            return

        listen_dirs = set(listens)

        if not listens:
            listen_dirs.add(port_service)

        for listen in listens:
            # For any listen statement, check if the machine also listens on
            # the given port. If not, add such a listen statement.
            if len(listen.split(":")) == 1:
                # Its listening to all interfaces
                if port not in listen_dirs and port_service not in listen_dirs:
                    listen_dirs.add(port_service)
            else:
                # The Listen statement specifies an ip
                _, ip = listen[::-1].split(":", 1)
                ip = ip[::-1]
                if "%s:%s" % (ip, port_service) not in listen_dirs and (
                    "%s:%s" % (ip, port_service) not in listen_dirs):
                    listen_dirs.add("%s:%s" % (ip, port_service))
        if https:
            self._add_listens_https(listen_dirs, listens, port)
        else:
            self._add_listens_http(listen_dirs, listens, port)

    def _add_listens_http(self, listens: Set[str], listens_orig: List[str], port: str) -> None:
        """Helper method for ensure_listen to figure out which new
        listen statements need adding for listening HTTP on port

        :param set listens: Set of all needed Listen statements
        :param list listens_orig: List of existing listen statements
        :param string port: Port number we're adding
        """

        new_listens = listens.difference(listens_orig)

        if port in new_listens:
            # We have wildcard, skip the rest
            self.parser.add_dir(parser.get_aug_path(self.parser.loc["listen"]),
                                "Listen", port)
            self.save_notes += (
                f"Added Listen {port} directive to {self.parser.loc['listen']}\n"
            )
        else:
            for listen in new_listens:
                self.parser.add_dir(parser.get_aug_path(
                    self.parser.loc["listen"]), "Listen", listen.split(" "))
                self.save_notes += (f"Added Listen {listen} directive to "
                                    f"{self.parser.loc['listen']}\n")

    def _add_listens_https(self, listens: Set[str], listens_orig: List[str], port: str) -> None:
        """Helper method for ensure_listen to figure out which new
        listen statements need adding for listening HTTPS on port

        :param set listens: Set of all needed Listen statements
        :param list listens_orig: List of existing listen statements
        :param string port: Port number we're adding
        """

        # Add service definition for non-standard ports
        if port != "443":
            port_service = f"{port} https"
        else:
            port_service = port

        new_listens = listens.difference(listens_orig)

        if port in new_listens or port_service in new_listens:
            # We have wildcard, skip the rest
            self.parser.add_dir_to_ifmodssl(
                parser.get_aug_path(self.parser.loc["listen"]),
                "Listen", port_service.split(" "))
            self.save_notes += (
                f"Added Listen {port_service} directive to {self.parser.loc['listen']}\n"
            )
        else:
            for listen in new_listens:
                self.parser.add_dir_to_ifmodssl(
                    parser.get_aug_path(self.parser.loc["listen"]),
                    "Listen", listen.split(" "))
                self.save_notes += (f"Added Listen {listen} directive to "
                                    f"{self.parser.loc['listen']}\n")

    def _has_port_already(self, listens: List[str], port: str) -> Optional[bool]:
        """Helper method for prepare_server_https to find out if user
        already has an active Listen statement for the port we need

        :param list listens: List of listen variables
        :param string port: Port in question
        """

        if port in listens:
            return True
        # Check if Apache is already listening on a specific IP
        for listen in listens:
            if len(listen.split(":")) > 1:
                # Ugly but takes care of protocol def, eg: 1.1.1.1:443 https
                if listen.split(":")[-1].split(" ")[0] == port:
                    return True
        return None

    def prepare_https_modules(self, temp: bool) -> None:
        """Helper method for prepare_server_https, taking care of enabling
        needed modules

        :param boolean temp: If the change is temporary
        """

        if self.options.handle_modules:
            if "socache_shmcb_module" not in self.parser.modules:
                self.enable_mod("socache_shmcb", temp=temp)
            if "ssl_module" not in self.parser.modules:
                self.enable_mod("ssl", temp=temp)
                # Make sure we're not throwing away any unwritten changes to the config
                self.parser.ensure_augeas_state()
                self.parser.aug.load()
                self.parser.reset_modules() # Reset to load the new ssl_module path
                # Call again because now we can gate on openssl version
                self.install_ssl_options_conf(self.mod_ssl_conf,
                                              self.updated_mod_ssl_conf_digest,
                                              warn_on_no_mod_ssl=True)

    def make_vhost_ssl(self, nonssl_vhost: obj.VirtualHost) -> obj.VirtualHost:
        """Makes an ssl_vhost version of a nonssl_vhost.

        Duplicates vhost and adds default ssl options
        New vhost will reside as (nonssl_vhost.path) +
        ``self.options.le_vhost_ext``

        .. note:: This function saves the configuration

        :param nonssl_vhost: Valid VH that doesn't have SSLEngine on
        :type nonssl_vhost: :class:`~certbot_apache._internal.obj.VirtualHost`

        :returns: SSL vhost
        :rtype: :class:`~certbot_apache._internal.obj.VirtualHost`

        :raises .errors.PluginError: If more than one virtual host is in
            the file or if plugin is unable to write/read vhost files.

        """
        avail_fp = nonssl_vhost.filep
        ssl_fp = self._get_ssl_vhost_path(avail_fp)

        orig_matches = self.parser.aug.match("/files%s//* [label()=~regexp('%s')]" %
                                             (self._escape(ssl_fp),
                                              parser.case_i("VirtualHost")))

        self._copy_create_ssl_vhost_skeleton(nonssl_vhost, ssl_fp)

        # Reload augeas to take into account the new vhost
        self.parser.aug.load()
        # Get Vhost augeas path for new vhost
        new_matches = self.parser.aug.match("/files%s//* [label()=~regexp('%s')]" %
                                            (self._escape(ssl_fp),
                                             parser.case_i("VirtualHost")))

        vh_p = self._get_new_vh_path(orig_matches, new_matches)

        if not vh_p:
            # The vhost was not found on the currently parsed paths
            # Make Augeas aware of the new vhost
            self.parser.parse_file(ssl_fp)
            # Try to search again
            new_matches = self.parser.aug.match(
                "/files%s//* [label()=~regexp('%s')]" %
                (self._escape(ssl_fp),
                 parser.case_i("VirtualHost")))
            vh_p = self._get_new_vh_path(orig_matches, new_matches)
            if not vh_p:
                raise errors.PluginError(
                    "Could not reverse map the HTTPS VirtualHost to the original")

        # Update Addresses
        self._update_ssl_vhosts_addrs(vh_p)

        # Log actions and create save notes
        logger.info("Created an SSL vhost at %s", ssl_fp)
        self.save_notes += "Created ssl vhost at %s\n" % ssl_fp
        self.save()

        # We know the length is one because of the assertion above
        # Create the Vhost object
        vhost = self._create_vhost(vh_p)
        if not vhost:
            raise errors.Error("Could not create a vhost")  # pragma: no cover
        ssl_vhost: obj.VirtualHost = vhost
        ssl_vhost.ancestor = nonssl_vhost

        self.vhosts.append(ssl_vhost)

        # NOTE: Searches through Augeas seem to ruin changes to directives
        #       The configuration must also be saved before being searched
        #       for the new directives; For these reasons... this is tacked
        #       on after fully creating the new vhost

        return ssl_vhost

    def _get_new_vh_path(self, orig_matches: List[str], new_matches: List[str]) -> Optional[str]:
        """ Helper method for make_vhost_ssl for matching augeas paths. Returns
        VirtualHost path from new_matches that's not present in orig_matches.

        Paths are normalized, because augeas leaves indices out for paths
        with only single directive with a similar key """

        orig_matches = [i.replace("[1]", "") for i in orig_matches]
        for match in new_matches:
            if match.replace("[1]", "") not in orig_matches:
                # Return the unmodified path
                return match
        return None

    def _get_ssl_vhost_path(self, non_ssl_vh_fp: str) -> str:
        """ Get a file path for SSL vhost, uses user defined path as priority,
        but if the value is invalid or not defined, will fall back to non-ssl
        vhost filepath.

        :param str non_ssl_vh_fp: Filepath of non-SSL vhost

        :returns: Filepath for SSL vhost
        :rtype: str
        """

        if self.conf("vhost-root") and os.path.exists(self.conf("vhost-root")):
            fp = os.path.join(filesystem.realpath(self.options.vhost_root),
                              os.path.basename(non_ssl_vh_fp))
        else:
            # Use non-ssl filepath
            fp = filesystem.realpath(non_ssl_vh_fp)

        if fp.endswith(".conf"):
            return fp[:-(len(".conf"))] + self.options.le_vhost_ext
        return fp + self.options.le_vhost_ext

    def _sift_rewrite_rule(self, line: str) -> bool:
        """Decides whether a line should be copied to a SSL vhost.

        A canonical example of when sifting a line is required:
        When the http vhost contains a RewriteRule that unconditionally
        redirects any request to the https version of the same site.
        e.g:
        RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [L,QSA,R=permanent]
        Copying the above line to the ssl vhost would cause a
        redirection loop.

        :param str line: a line extracted from the http vhost.

        :returns: True - don't copy line from http vhost to SSL vhost.
        :rtype: bool

        """
        if not line.lower().lstrip().startswith("rewriterule"):
            return False

        # According to: https://httpd.apache.org/docs/2.4/rewrite/flags.html
        # The syntax of a RewriteRule is:
        # RewriteRule pattern target [Flag1,Flag2,Flag3]
        # i.e. target is required, so it must exist.
        target = line.split()[2].strip()

        # target may be surrounded with quotes
        if target[0] in ("'", '"') and target[0] == target[-1]:
            target = target[1:-1]

        # Sift line if it redirects the request to a HTTPS site
        return target.startswith("https://")

    def _copy_create_ssl_vhost_skeleton(self, vhost: obj.VirtualHost, ssl_fp: str) -> None:
        """Copies over existing Vhost with IfModule mod_ssl.c> skeleton.

        :param obj.VirtualHost vhost: Original VirtualHost object
        :param str ssl_fp: Full path where the new ssl_vhost will reside.

        A new file is created on the filesystem.

        """
        # First register the creation so that it is properly removed if
        # configuration is rolled back
        if os.path.exists(ssl_fp):
            notes = "Appended new VirtualHost directive to file %s" % ssl_fp
            files = set()
            files.add(ssl_fp)
            self.reverter.add_to_checkpoint(files, notes)
        else:
            self.reverter.register_file_creation(False, ssl_fp)
        sift: bool

        try:
            orig_contents = self._get_vhost_block(vhost)
            ssl_vh_contents, sift = self._sift_rewrite_rules(orig_contents)

            with open(ssl_fp, "a") as new_file:
                new_file.write("<IfModule mod_ssl.c>\n")
                new_file.write("\n".join(ssl_vh_contents))
                # The content does not include the closing tag, so add it
                new_file.write("</VirtualHost>\n")
                new_file.write("</IfModule>\n")
            # Add new file to augeas paths if we're supposed to handle
            # activation (it's not included as default)
            if not self.parser.parsed_in_current(ssl_fp):
                self.parser.parse_file(ssl_fp)
        except OSError:
            logger.critical("Error writing/reading to file in make_vhost_ssl", exc_info=True)
            raise errors.PluginError("Unable to write/read in make_vhost_ssl")

        if sift:
            display_util.notify(
                f"Some rewrite rules copied from {vhost.filep} were disabled in the "
                f"vhost for your HTTPS site located at {ssl_fp} because they have "
                "the potential to create redirection loops."
            )
        self.parser.aug.set("/augeas/files%s/mtime" % (self._escape(ssl_fp)), "0")
        self.parser.aug.set("/augeas/files%s/mtime" % (self._escape(vhost.filep)), "0")

    def _sift_rewrite_rules(self, contents: Iterable[str]) -> Tuple[List[str], bool]:
        """ Helper function for _copy_create_ssl_vhost_skeleton to prepare the
        new HTTPS VirtualHost contents. Currently disabling the rewrites """

        result: List[str] = []
        sift: bool = False
        contents = iter(contents)

        comment = ("# Some rewrite rules in this file were "
                   "disabled on your HTTPS site,\n"
                   "# because they have the potential to create "
                   "redirection loops.\n")

        for line in contents:
            A = line.lower().lstrip().startswith("rewritecond")
            B = line.lower().lstrip().startswith("rewriterule")

            if not (A or B):
                result.append(line)
                continue

            # A RewriteRule that doesn't need filtering
            if B and not self._sift_rewrite_rule(line):
                result.append(line)
                continue

            # A RewriteRule that does need filtering
            if B and self._sift_rewrite_rule(line):
                if not sift:
                    result.append(comment)
                    sift = True
                result.append("# " + line)
                continue

            # We save RewriteCond(s) and their corresponding
            # RewriteRule in 'chunk'.
            # We then decide whether we comment out the entire
            # chunk based on its RewriteRule.
            chunk = []
            if A:
                chunk.append(line)
                line = next(contents)

                # RewriteCond(s) must be followed by one RewriteRule
                while not line.lower().lstrip().startswith("rewriterule"):
                    chunk.append(line)
                    line = next(contents)

                # Now, current line must start with a RewriteRule
                chunk.append(line)

                if self._sift_rewrite_rule(line):
                    if not sift:
                        result.append(comment)
                        sift = True

                    result.append('\n'.join('# ' + l for l in chunk))
                else:
                    result.append('\n'.join(chunk))
        return result, sift

    def _get_vhost_block(self, vhost: obj.VirtualHost) -> List[str]:
        """ Helper method to get VirtualHost contents from the original file.
        This is done with help of augeas span, which returns the span start and
        end positions

        :returns: `list` of VirtualHost block content lines without closing tag
        """

        try:
            span_val = self.parser.aug.span(vhost.path)
        except ValueError:
            logger.critical("Error while reading the VirtualHost %s from "
                            "file %s", vhost.name, vhost.filep, exc_info=True)
            raise errors.PluginError("Unable to read VirtualHost from file")
        span_filep = span_val[0]
        span_start = span_val[5]
        span_end = span_val[6]
        with open(span_filep, 'r') as fh:
            fh.seek(span_start)
            vh_contents = fh.read(span_end-span_start).split("\n")
        self._remove_closing_vhost_tag(vh_contents)
        return vh_contents

    def _remove_closing_vhost_tag(self, vh_contents: List[str]) -> None:
        """Removes the closing VirtualHost tag if it exists.

        This method modifies vh_contents directly to remove the closing
        tag. If the closing vhost tag is found, everything on the line
        after it is also removed. Whether or not this tag is included
        in the result of span depends on the Augeas version.

        :param list vh_contents: VirtualHost block contents to check

        """
        for offset, line in enumerate(reversed(vh_contents)):
            if line:
                line_index = line.lower().find("</virtualhost>")
                if line_index != -1:
                    content_index = len(vh_contents) - offset - 1
                    vh_contents[content_index] = line[:line_index]
                break

    def _update_ssl_vhosts_addrs(self, vh_path: str) -> Set[obj.Addr]:
        ssl_addrs: Set[obj.Addr] = set()
        ssl_addr_p: List[str] = self.parser.aug.match(vh_path + "/arg")

        for addr in ssl_addr_p:
            old_addr = obj.Addr.fromstring(
                str(self.parser.get_arg(addr)))
            ssl_addr = old_addr.get_addr_obj("443")
            self.parser.aug.set(addr, str(ssl_addr))
            ssl_addrs.add(ssl_addr)

        return ssl_addrs

    def _clean_vhost(self, vhost: obj.VirtualHost) -> None:
        # remove duplicated or conflicting ssl directives
        self._deduplicate_directives(vhost.path,
                                     ["SSLCertificateFile",
                                      "SSLCertificateKeyFile"])
        # remove all problematic directives
        self._remove_directives(vhost.path, ["SSLCertificateChainFile"])

    def _deduplicate_directives(self, vh_path: Optional[str], directives: List[str]) -> None:
        for directive in directives:
            while len(self.parser.find_dir(directive, None,
                                           vh_path, False)) > 1:
                directive_path = self.parser.find_dir(directive, None,
                                                      vh_path, False)
                self.parser.aug.remove(re.sub(r"/\w*$", "", directive_path[0]))

    def _remove_directives(self, vh_path: Optional[str], directives: List[str]) -> None:
        for directive in directives:
            while self.parser.find_dir(directive, None, vh_path, False):
                directive_path = self.parser.find_dir(directive, None,
                                                      vh_path, False)
                self.parser.aug.remove(re.sub(r"/\w*$", "", directive_path[0]))

    def _add_dummy_ssl_directives(self, vh_path: str) -> None:
        self.parser.add_dir(vh_path, "SSLCertificateFile",
                            "insert_cert_file_path")
        self.parser.add_dir(vh_path, "SSLCertificateKeyFile",
                            "insert_key_file_path")
        # Only include the TLS configuration if not already included
        existing_inc = self.parser.find_dir("Include", self.mod_ssl_conf, vh_path)
        if not existing_inc:
            self.parser.add_dir(vh_path, "Include", self.mod_ssl_conf)

    def _add_servername_alias(self, target_name: str, vhost: obj.VirtualHost) -> None:
        vh_path = vhost.path
        sname, saliases = self._get_vhost_names(vh_path)
        if target_name == sname or target_name in saliases:
            return
        if self._has_matching_wildcard(vh_path, target_name):
            return
        if not self.parser.find_dir("ServerName", None,
                                    start=vh_path, exclude=False):
            self.parser.add_dir(vh_path, "ServerName", target_name)
        else:
            self.parser.add_dir(vh_path, "ServerAlias", target_name)
        self._add_servernames(vhost)

    def _has_matching_wildcard(self, vh_path: str, target_name: str) -> bool:
        """Is target_name already included in a wildcard in the vhost?

        :param str vh_path: Augeas path to the vhost
        :param str target_name: name to compare with wildcards

        :returns: True if there is a wildcard covering target_name in
            the vhost in vhost_path, otherwise, False
        :rtype: bool

        """
        matches = self.parser.find_dir(
            "ServerAlias", start=vh_path, exclude=False)
        aliases = (self.parser.aug.get(match) for match in matches)
        return self.domain_in_names(aliases, target_name)

    def find_vhost_by_id(self, id_str: str) -> obj.VirtualHost:
        """
        Searches through VirtualHosts and tries to match the id in a comment

        :param str id_str: Id string for matching

        :returns: The matched VirtualHost
        :rtype: :class:`~certbot_apache._internal.obj.VirtualHost`

        :raises .errors.PluginError: If no VirtualHost is found
        """

        for vh in self.vhosts:
            if self._find_vhost_id(vh) == id_str:
                return vh
        msg = "No VirtualHost with ID {} was found.".format(id_str)
        logger.warning(msg)
        raise errors.PluginError(msg)

    def _find_vhost_id(self, vhost: obj.VirtualHost) -> Optional[str]:
        """Tries to find the unique ID from the VirtualHost comments. This is
        used for keeping track of VirtualHost directive over time.

        :param vhost: Virtual host to add the id
        :type vhost: :class:`~certbot_apache._internal.obj.VirtualHost`

        :returns: The unique ID or None
        :rtype: str or None
        """

        # Strip the {} off from the format string
        search_comment = constants.MANAGED_COMMENT_ID.format("")

        id_comment = self.parser.find_comments(search_comment, vhost.path)
        if id_comment:
            # Use the first value, multiple ones shouldn't exist
            comment = self.parser.get_arg(id_comment[0])
            return comment.split(" ")[-1] if comment else None
        return None

    def add_vhost_id(self, vhost: obj.VirtualHost) -> Optional[str]:
        """Adds an unique ID to the VirtualHost as a comment for mapping back
        to it on later invocations, as the config file order might have changed.
        If ID already exists, returns that instead.

        :param vhost: Virtual host to add or find the id
        :type vhost: :class:`~certbot_apache._internal.obj.VirtualHost`

        :returns: The unique ID for vhost
        :rtype: str or None
        """

        vh_id = self._find_vhost_id(vhost)
        if vh_id:
            return vh_id

        id_string = apache_util.unique_id()
        comment: str = constants.MANAGED_COMMENT_ID.format(id_string)
        self.parser.add_comment(vhost.path, comment)
        return id_string

    def _escape(self, fp: str) -> str:
        fp = fp.replace(",", "\\,")
        fp = fp.replace("[", "\\[")
        fp = fp.replace("]", "\\]")
        fp = fp.replace("|", "\\|")
        fp = fp.replace("=", "\\=")
        fp = fp.replace("(", "\\(")
        fp = fp.replace(")", "\\)")
        fp = fp.replace("!", "\\!")
        return fp

    ######################################################################
    # Enhancements
    ######################################################################
    def supported_enhancements(self) -> List[str]:
        """Returns currently supported enhancements."""
        return ["redirect", "ensure-http-header", "staple-ocsp"]

    def enhance(self, domain: str, enhancement: str,
                options: Optional[Union[List[str], str]] = None) -> None:
        """Enhance configuration.

        :param str domain: domain to enhance
        :param str enhancement: enhancement type defined in
            :const:`~certbot.plugins.enhancements.ENHANCEMENTS`
        :param options: options for the enhancement
            See :const:`~certbot.plugins.enhancements.ENHANCEMENTS`
            documentation for appropriate parameter.

        :raises .errors.PluginError: If Enhancement is not supported, or if
            there is any other problem with the enhancement.

        """
        try:
            func = self._enhance_func[enhancement]
        except KeyError:
            raise errors.PluginError(
                "Unsupported enhancement: {0}".format(enhancement))

        matched_vhosts = self.choose_vhosts(domain, create_if_no_ssl=False)
        # We should be handling only SSL vhosts for enhancements
        vhosts = [vhost for vhost in matched_vhosts if vhost.ssl]

        if not vhosts:
            msg_tmpl = ("Certbot was not able to find SSL VirtualHost for a "
                        "domain {0} for enabling enhancement \"{1}\". The requested "
                        "enhancement was not configured.")
            msg_enhancement = enhancement
            if options:
                msg_enhancement += ": " + str(options)
            msg = msg_tmpl.format(domain, msg_enhancement)
            logger.error(msg)
            raise errors.PluginError(msg)
        try:
            for vhost in vhosts:
                func(vhost, options)
        except errors.PluginError:
            logger.error("Failed %s for %s", enhancement, domain)
            raise

    def _autohsts_increase(
        self, vhost: obj.VirtualHost, id_str: str, nextstep: int
    ) -> None:
        """Increase the AutoHSTS max-age value

        :param vhost: Virtual host object to modify
        :type vhost: :class:`~certbot_apache._internal.obj.VirtualHost`

        :param str id_str: The unique ID string of VirtualHost

        :param int nextstep: Next AutoHSTS max-age value index

        """
        nextstep_value = constants.AUTOHSTS_STEPS[nextstep]
        self._autohsts_write(vhost, nextstep_value)
        self._autohsts[id_str] = {"laststep": nextstep, "timestamp": time.time()}

    def _autohsts_write(self, vhost: obj.VirtualHost, nextstep_value: float) -> None:
        """
        Write the new HSTS max-age value to the VirtualHost file
        """

        hsts_dirpath = None
        header_path = self.parser.find_dir("Header", None, vhost.path)
        if header_path:
            pat = '(?:[ "]|^)(strict-transport-security)(?:[ "]|$)'
            for match in header_path:
                if re.search(pat, self.parser.aug.get(match).lower()):
                    hsts_dirpath = match
        if not hsts_dirpath:
            err_msg = ("Certbot was unable to find the existing HSTS header "
                       "from the VirtualHost at path {0}.").format(vhost.filep)
            raise errors.PluginError(err_msg)

        # Prepare the HSTS header value
        hsts_maxage = "\"max-age={0}\"".format(nextstep_value)

        # Update the header
        # Our match statement was for string strict-transport-security, but
        # we need to update the value instead. The next index is for the value
        hsts_dirpath = hsts_dirpath.replace("arg[3]", "arg[4]")
        self.parser.aug.set(hsts_dirpath, hsts_maxage)
        note_msg = ("Increasing HSTS max-age value to {0} for VirtualHost "
                    "in {1}\n".format(nextstep_value, vhost.filep))
        logger.debug(note_msg)
        self.save_notes += note_msg
        self.save(note_msg)

    def _autohsts_fetch_state(self) -> None:
        """
        Populates the AutoHSTS state from the pluginstorage
        """
        try:
            self._autohsts = self.storage.fetch("autohsts")
        except KeyError:
            self._autohsts = {}

    def _autohsts_save_state(self) -> None:
        """
        Saves the state of AutoHSTS object to pluginstorage
        """
        self.storage.put("autohsts", self._autohsts)
        self.storage.save()

    def _autohsts_vhost_in_lineage(
        self, vhost: obj.VirtualHost, lineage: RenewableCert
    ) -> bool:
        """
        Searches AutoHSTS managed VirtualHosts that belong to the lineage.
        Matches the private key path.
        """
        return bool(self.parser.find_dir("SSLCertificateKeyFile", lineage.key_path, vhost.path))

    def _enable_ocsp_stapling(self, ssl_vhost: obj.VirtualHost, unused_options: Any) -> None:
        """Enables OCSP Stapling

        In OCSP, each client (e.g. browser) would have to query the
        OCSP Responder to validate that the site certificate was not revoked.

        Enabling OCSP Stapling, would allow the web-server to query the OCSP
        Responder, and staple its response to the offered certificate during
        TLS. i.e. clients would not have to query the OCSP responder.

        OCSP Stapling enablement on Apache implicitly depends on
        SSLCertificateChainFile being set by other code.

        .. note:: This function saves the configuration

        :param ssl_vhost: Destination of traffic, an ssl enabled vhost
        :type ssl_vhost: :class:`~certbot_apache._internal.obj.VirtualHost`

        :param unused_options: Not currently used
        :type unused_options: Not Available
        """
        if "socache_shmcb_module" not in self.parser.modules:
            self.enable_mod("socache_shmcb")

        # Check if there's an existing SSLUseStapling directive on.
        use_stapling_aug_path = self.parser.find_dir("SSLUseStapling",
                                                     "on", start=ssl_vhost.path)
        if not use_stapling_aug_path:
            self.parser.add_dir(ssl_vhost.path, "SSLUseStapling", "on")

        ssl_vhost_aug_path = self._escape(parser.get_aug_path(ssl_vhost.filep))

        # Check if there's an existing SSLStaplingCache directive.
        stapling_cache_aug_path = self.parser.find_dir('SSLStaplingCache',
                                                       None, ssl_vhost_aug_path)

        # We'll simply delete the directive, so that we'll have a
        # consistent OCSP cache path.
        if stapling_cache_aug_path:
            self.parser.aug.remove(
                re.sub(r"/\w*$", "", stapling_cache_aug_path[0]))

        self.parser.add_dir_to_ifmodssl(ssl_vhost_aug_path,
                                        "SSLStaplingCache",
                                        ["shmcb:/var/run/apache2/stapling_cache(128000)"])

        msg = "OCSP Stapling was enabled on SSL Vhost: %s.\n"%(
            ssl_vhost.filep)
        self.save_notes += msg
        self.save()
        logger.info(msg)

    def _set_http_header(self, ssl_vhost: obj.VirtualHost, header_substring: str) -> None:
        """Enables header that is identified by header_substring on ssl_vhost.

        If the header identified by header_substring is not already set,
        a new Header directive is placed in ssl_vhost's configuration with
        arguments from: constants.HTTP_HEADER[header_substring]

        .. note:: This function saves the configuration

        :param ssl_vhost: Destination of traffic, an ssl enabled vhost
        :type ssl_vhost: :class:`~certbot_apache._internal.obj.VirtualHost`

        :param header_substring: string that uniquely identifies a header.
                e.g: Strict-Transport-Security, Upgrade-Insecure-Requests.
        :type str

        :raises .errors.PluginError: If no viable HTTP host can be created or
            set with header header_substring.

        """
        if "headers_module" not in self.parser.modules:
            self.enable_mod("headers")

        # Check if selected header is already set
        self._verify_no_matching_http_header(ssl_vhost, header_substring)

        # Add directives to server
        self.parser.add_dir(ssl_vhost.path, "Header",
                            constants.HEADER_ARGS[header_substring])

        self.save_notes += ("Adding %s header to ssl vhost in %s\n" %
                            (header_substring, ssl_vhost.filep))

        self.save()
        logger.info("Adding %s header to ssl vhost in %s", header_substring,
                    ssl_vhost.filep)

    def _verify_no_matching_http_header(
        self, ssl_vhost: obj.VirtualHost, header_substring: str
    ) -> None:
        """Checks to see if there is an existing Header directive that
        contains the string header_substring.

        :param ssl_vhost: vhost to check
        :type vhost: :class:`~certbot_apache._internal.obj.VirtualHost`

        :param header_substring: string that uniquely identifies a header.
                e.g: Strict-Transport-Security, Upgrade-Insecure-Requests.
        :type str

        :returns: boolean
        :rtype: (bool)

        :raises errors.PluginEnhancementAlreadyPresent When header
                header_substring exists

        """
        header_path = self.parser.find_dir("Header", None,
                                           start=ssl_vhost.path)
        if header_path:
            # "Existing Header directive for virtualhost"
            pat = '(?:[ "]|^)(%s)(?:[ "]|$)' % (header_substring.lower())
            for match in header_path:
                if re.search(pat, self.parser.aug.get(match).lower()):
                    raise errors.PluginEnhancementAlreadyPresent(
                        "Existing %s header" % header_substring)

    def _enable_redirect(self, ssl_vhost: obj.VirtualHost, unused_options: Any) -> None:
        """Redirect all equivalent HTTP traffic to ssl_vhost.

        .. todo:: This enhancement should be rewritten and will
           unfortunately require lots of debugging by hand.

        Adds Redirect directive to the port 80 equivalent of ssl_vhost
        First the function attempts to find the vhost with equivalent
        ip addresses that serves on non-ssl ports
        The function then adds the directive

        .. note:: This function saves the configuration

        :param ssl_vhost: Destination of traffic, an ssl enabled vhost
        :type ssl_vhost: :class:`~certbot_apache._internal.obj.VirtualHost`

        :param unused_options: Not currently used
        :type unused_options: Not Available

        :raises .errors.PluginError: If no viable HTTP host can be created or
            used for the redirect.

        """
        if "rewrite_module" not in self.parser.modules:
            self.enable_mod("rewrite")
        general_vh = self._get_http_vhost(ssl_vhost)

        if general_vh is None:
            # Add virtual_server with redirect
            logger.debug("Did not find http version of ssl virtual host "
                         "attempting to create")
            redirect_addrs = self._get_proposed_addrs(ssl_vhost)
            for vhost in self.vhosts:
                if vhost.enabled and vhost.conflicts(redirect_addrs):
                    raise errors.PluginError(
                        "Unable to find corresponding HTTP vhost; "
                        "Unable to create one as intended addresses conflict; "
                        "Current configuration does not support automated "
                        "redirection")
            self._create_redirect_vhost(ssl_vhost)
        else:
            if general_vh in self._enhanced_vhosts["redirect"]:
                logger.debug("Already enabled redirect for this vhost")
                return

            # Check if Certbot redirection already exists
            self._verify_no_certbot_redirect(general_vh)

            # Note: if code flow gets here it means we didn't find the exact
            # certbot RewriteRule config for redirection. Finding
            # another RewriteRule is likely to be fine in most or all cases,
            # but redirect loops are possible in very obscure cases; see #1620
            # for reasoning.
            if self._is_rewrite_exists(general_vh):
                logger.warning("Added an HTTP->HTTPS rewrite in addition to "
                               "other RewriteRules; you may wish to check for "
                               "overall consistency.")

            # Add directives to server
            # Note: These are not immediately searchable in sites-enabled
            #     even with save() and load()
            if not self._is_rewrite_engine_on(general_vh):
                self.parser.add_dir(general_vh.path, "RewriteEngine", "on")

            names = ssl_vhost.get_names()
            for idx, name in enumerate(names):
                args = ["%{SERVER_NAME}", "={0}".format(name), "[OR]"]
                if idx == len(names) - 1:
                    args.pop()
                self.parser.add_dir(general_vh.path, "RewriteCond", args)

            self._set_https_redirection_rewrite_rule(general_vh)

            self.save_notes += ("Redirecting host in %s to ssl vhost in %s\n" %
                                (general_vh.filep, ssl_vhost.filep))
            self.save()

            self._enhanced_vhosts["redirect"].add(general_vh)
            logger.info("Redirecting vhost in %s to ssl vhost in %s",
                        general_vh.filep, ssl_vhost.filep)

    def _set_https_redirection_rewrite_rule(self, vhost: obj.VirtualHost) -> None:
        self.parser.add_dir(vhost.path, "RewriteRule", constants.REWRITE_HTTPS_ARGS)

    def _verify_no_certbot_redirect(self, vhost: obj.VirtualHost) -> None:
        """Checks to see if a redirect was already installed by certbot.

        Checks to see if virtualhost already contains a rewrite rule that is
        identical to Certbot's redirection rewrite rule.

        For graceful transition to new rewrite rules for HTTPS redireciton we
        delete certbot's old rewrite rules and set the new one instead.

        :param vhost: vhost to check
        :type vhost: :class:`~certbot_apache._internal.obj.VirtualHost`

        :raises errors.PluginEnhancementAlreadyPresent: When the exact
                certbot redirection WriteRule exists in virtual host.
        """
        rewrite_path = self.parser.find_dir(
            "RewriteRule", None, start=vhost.path)

        # There can be other RewriteRule directive lines in vhost config.
        # rewrite_args_dict keys are directive ids and the corresponding value
        # for each is a list of arguments to that directive.
        rewrite_args_dict: DefaultDict[str, List[str]] = defaultdict(list)
        pat = r'(.*directive\[\d+\]).*'
        for match in rewrite_path:
            m = re.match(pat, match)
            if m:
                dir_path = m.group(1)
                rewrite_args_dict[dir_path].append(match)

        if rewrite_args_dict:
            for dir_path, args_paths in rewrite_args_dict.items():
                arg_vals = [self.parser.aug.get(x) for x in args_paths]

                # Search for past redirection rule, delete it, set the new one
                if arg_vals in constants.OLD_REWRITE_HTTPS_ARGS:
                    self.parser.aug.remove(dir_path)
                    self._set_https_redirection_rewrite_rule(vhost)
                    self.save()
                    raise errors.PluginEnhancementAlreadyPresent(
                        "Certbot has already enabled redirection")

                if arg_vals == constants.REWRITE_HTTPS_ARGS:
                    raise errors.PluginEnhancementAlreadyPresent(
                        "Certbot has already enabled redirection")

    def _is_rewrite_exists(self, vhost: obj.VirtualHost) -> bool:
        """Checks if there exists a RewriteRule directive in vhost

        :param vhost: vhost to check
        :type vhost: :class:`~certbot_apache._internal.obj.VirtualHost`

        :returns: True if a RewriteRule directive exists.
        :rtype: bool

        """
        rewrite_path = self.parser.find_dir(
            "RewriteRule", None, start=vhost.path)
        return bool(rewrite_path)

    def _is_rewrite_engine_on(self, vhost: obj.VirtualHost) -> Optional[Union[str, bool]]:
        """Checks if a RewriteEngine directive is on

        :param vhost: vhost to check
        :type vhost: :class:`~certbot_apache._internal.obj.VirtualHost`

        """
        rewrite_engine_path_list = self.parser.find_dir("RewriteEngine", "on", start=vhost.path)
        if rewrite_engine_path_list:
            for re_path in rewrite_engine_path_list:
                # A RewriteEngine directive may also be included in per
                # directory .htaccess files. We only care about the VirtualHost.
                if 'virtualhost' in re_path.lower():
                    return self.parser.get_arg(re_path)
        return False

    def _create_redirect_vhost(self, ssl_vhost: obj.VirtualHost) -> None:
        """Creates an http_vhost specifically to redirect for the ssl_vhost.

        :param ssl_vhost: ssl vhost
        :type ssl_vhost: :class:`~certbot_apache._internal.obj.VirtualHost`
        """
        text = self._get_redirect_config_str(ssl_vhost)

        redirect_filepath = self._write_out_redirect(ssl_vhost, text)

        self.parser.aug.load()
        # Make a new vhost data structure and add it to the lists
        new_vhost = self._create_vhost(parser.get_aug_path(
            self._escape(redirect_filepath))
        )
        if new_vhost is None:
            raise errors.Error("Could not create a new vhost")  # pragma: no cover
        self.vhosts.append(new_vhost)
        self._enhanced_vhosts["redirect"].add(new_vhost)

        # Finally create documentation for the change
        self.save_notes += ("Created a port 80 vhost, %s, for redirection to "
                            "ssl vhost %s\n" %
                            (new_vhost.filep, ssl_vhost.filep))

    def _get_redirect_config_str(self, ssl_vhost: obj.VirtualHost) -> str:
        # get servernames and serveraliases
        serveralias = ""
        servername = ""

        if ssl_vhost.name is not None:
            servername = "ServerName " + ssl_vhost.name
        if ssl_vhost.aliases:
            serveralias = "ServerAlias " + " ".join(ssl_vhost.aliases)

        return (
            f"<VirtualHost {' '.join(str(addr) for addr in self._get_proposed_addrs(ssl_vhost))}>\n"
            f"{servername} \n"
            f"{serveralias} \n"
            f"ServerSignature Off\n"
            f"\n"
            f"RewriteEngine On\n"
            f"RewriteRule {' '.join(constants.REWRITE_HTTPS_ARGS)}\n"
            "\n"
            f"ErrorLog {self.options.logs_root}/redirect.error.log\n"
            f"LogLevel warn\n"
            f"</VirtualHost>\n"
        )

    def _write_out_redirect(self, ssl_vhost: obj.VirtualHost, text: str) -> str:
        # This is the default name
        redirect_filename = "le-redirect.conf"

        # See if a more appropriate name can be applied
        if ssl_vhost.name is not None:
            # make sure servername doesn't exceed filename length restriction
            if len(ssl_vhost.name) < (255 - (len(redirect_filename) + 1)):
                redirect_filename = "le-redirect-%s.conf" % ssl_vhost.name

        redirect_filepath = os.path.join(self.options.vhost_root,
                                         redirect_filename)

        # Register the new file that will be created
        # Note: always register the creation before writing to ensure file will
        # be removed in case of unexpected program exit
        self.reverter.register_file_creation(False, redirect_filepath)

        # Write out file
        with open(redirect_filepath, "w") as redirect_file:
            redirect_file.write(text)

        # Add new include to configuration if it doesn't exist yet
        if not self.parser.parsed_in_current(redirect_filepath):
            self.parser.parse_file(redirect_filepath)

        logger.info("Created redirect file: %s", redirect_filename)

        return redirect_filepath

    def _get_http_vhost(self, ssl_vhost: obj.VirtualHost) -> Optional[obj.VirtualHost]:
        """Find appropriate HTTP vhost for ssl_vhost."""
        # First candidate vhosts filter
        if ssl_vhost.ancestor:
            return ssl_vhost.ancestor
        candidate_http_vhs = [
            vhost for vhost in self.vhosts if not vhost.ssl
        ]

        # Second filter - check addresses
        for http_vh in candidate_http_vhs:
            if http_vh.same_server(ssl_vhost):
                return http_vh
        # Third filter - if none with same names, return generic
        for http_vh in candidate_http_vhs:
            if http_vh.same_server(ssl_vhost, generic=True):
                return http_vh

        return None

    def _get_proposed_addrs(self, vhost: obj.VirtualHost, port: str = "80") -> Iterable[obj.Addr]:
        """Return all addrs of vhost with the port replaced with the specified.

        :param obj.VirtualHost ssl_vhost: Original Vhost
        :param str port: Desired port for new addresses

        :returns: `set` of :class:`~obj.Addr`

        """
        redirects = set()
        for addr in vhost.addrs:
            redirects.add(addr.get_addr_obj(port))

        return redirects

    def enable_site(self, vhost: obj.VirtualHost) -> None:
        """Enables an available site, Apache reload required.

        .. note:: Does not make sure that the site correctly works or that all
                  modules are enabled appropriately.
        .. note:: The distribution specific override replaces functionality
                  of this method where available.

        :param vhost: vhost to enable
        :type vhost: :class:`~certbot_apache._internal.obj.VirtualHost`

        :raises .errors.NotSupportedError: If filesystem layout is not
            supported.

        """
        if vhost.enabled:
            return

        if not self.parser.parsed_in_original(vhost.filep):
            # Add direct include to root conf
            logger.info("Enabling site %s by adding Include to root configuration",
                        vhost.filep)
            self.save_notes += "Enabled site %s\n" % vhost.filep
            self.parser.add_include(self.parser.loc["default"], vhost.filep)
            vhost.enabled = True
        return

    # pylint: disable=unused-argument
    def enable_mod(self, mod_name: str, temp: bool = False) -> None:
        """Enables module in Apache.

        Both enables and reloads Apache so module is active.

        :param str mod_name: Name of the module to enable. (e.g. 'ssl')
        :param bool temp: Whether or not this is a temporary action.

        .. note:: The distribution specific override replaces functionality
                  of this method where available.

        :raises .errors.MisconfigurationError: We cannot enable modules in
            generic fashion.

        """
        mod_message = (
            f"Apache needs to have module  \"{mod_name}\" active for the "
            "requested installation options. Unfortunately Certbot is unable "
            "to install or enable it for you. Please install the module, and "
            "run Certbot again."
        )
        raise errors.MisconfigurationError(mod_message)

    def restart(self) -> None:
        """Runs a config test and reloads the Apache server.

        :raises .errors.MisconfigurationError: If either the config test
            or reload fails.

        """
        self.config_test()
        self._reload()

    def _reload(self) -> None:
        """Reloads the Apache server.

        :raises .errors.MisconfigurationError: If reload fails

        """
        try:
            util.run_script(self.options.restart_cmd)
        except errors.SubprocessError as err:
            logger.warning("Unable to restart apache using %s",
                        self.options.restart_cmd)
            if self.options.restart_cmd_alt:
                logger.debug("Trying alternative restart command: %s",
                             self.options.restart_cmd_alt)
                # There is an alternative restart command available
                # This usually is "restart" verb while original is "graceful"
                try:
                    util.run_script(self.options.restart_cmd_alt)
                    return
                except errors.SubprocessError as secerr:
                    error = str(secerr)
            else:
                error = str(err)
            raise errors.MisconfigurationError(error)

    def config_test(self) -> None:
        """Check the configuration of Apache for errors.

        :raises .errors.MisconfigurationError: If config_test fails

        """
        try:
            util.run_script(self.options.conftest_cmd)
        except errors.SubprocessError as err:
            raise errors.MisconfigurationError(str(err))

    def get_version(self) -> Tuple[int, ...]:
        """Return version of Apache Server.

        Version is returned as tuple. (ie. 2.4.7 = (2, 4, 7))

        :returns: version
        :rtype: tuple

        :raises .PluginError: if unable to find Apache version

        """
        try:
            stdout, _ = util.run_script(self.options.version_cmd)
        except errors.SubprocessError:
            raise errors.PluginError(
                "Unable to run %s -v" %
                self.options.version_cmd)

        regex = re.compile(r"Apache/([0-9\.]*)", re.IGNORECASE)
        matches = regex.findall(stdout)

        if len(matches) != 1:
            raise errors.PluginError("Unable to find Apache version")

        return tuple(int(i) for i in matches[0].split("."))

    def more_info(self) -> str:
        """Human-readable string to help understand the module"""
        return (
            "Configures Apache to authenticate and install HTTPS.{0}"
            "Server root: {root}{0}"
            "Version: {version}".format(
                os.linesep, root=self.parser.loc["root"],
                version=".".join(str(i) for i in self.version))
        )

    def auth_hint(
        self, failed_achalls: Iterable[achallenges.AnnotatedChallenge]
    ) -> str:  # pragma: no cover
        return ("The Certificate Authority failed to verify the temporary Apache configuration "
                "changes made by Certbot. Ensure that the listed domains point to this Apache "
                "server and that it is accessible from the internet.")

    ###########################################################################
    # Challenges Section
    ###########################################################################
    def get_chall_pref(self, unused_domain: str) -> Sequence[Type[challenges.HTTP01]]:
        """Return list of challenge preferences."""
        return [challenges.HTTP01]

    def perform(self, achalls: List[achallenges.AnnotatedChallenge]
                ) -> List[challenges.ChallengeResponse]:
        """Perform the configuration related challenge.

        This function currently assumes all challenges will be fulfilled.
        If this turns out not to be the case in the future. Cleanup and
        outstanding challenges will have to be designed better.

        """
        self._chall_out.update(achalls)
        responses: List[Optional[challenges.ChallengeResponse]] = [None] * len(achalls)
        http_doer = http_01.ApacheHttp01(self)

        for i, achall in enumerate(achalls):
            if not isinstance(achall, achallenges.KeyAuthorizationAnnotatedChallenge):
                raise errors.Error("Challenge should be an instance "  # pragma: no cover
                                   "of KeyAuthorizationAnnotatedChallenge")
            # Currently also have chall_doer hold associated index of the
            # challenge. This helps to put all of the responses back together
            # when they are all complete.
            http_doer.add_chall(achall, i)

        http_response = http_doer.perform()
        if http_response:
            # Must reload in order to activate the challenges.
            # Handled here because we may be able to load up other challenge
            # types
            self.restart()

            # TODO: Remove this dirty hack. We need to determine a reliable way
            #       of identifying when the new configuration is being used.
            time.sleep(3)

            self._update_responses(responses, http_response, http_doer)

        return [response for response in responses if response]

    def _update_responses(
        self,
        responses: List[Optional[challenges.ChallengeResponse]],
        chall_response: List[challenges.KeyAuthorizationChallengeResponse],
        chall_doer: http_01.ApacheHttp01
    ) -> None:
        # Go through all of the challenges and assign them to the proper
        # place in the responses return value. All responses must be in the
        # same order as the original challenges.
        for i, resp in enumerate(chall_response):
            responses[chall_doer.indices[i]] = resp

    def cleanup(self, achalls: List[achallenges.AnnotatedChallenge]) -> None:
        """Revert all challenges."""
        self._chall_out.difference_update(achalls)

        # If all of the challenges have been finished, clean up everything
        if not self._chall_out:
            self.revert_challenge_config()
            self.restart()
            self.parser.reset_modules()

    def install_ssl_options_conf(
        self, options_ssl: str, options_ssl_digest: str, warn_on_no_mod_ssl: bool = True
    ) -> None:
        """Copy Certbot's SSL options file into the system's config dir if required.

        :param bool warn_on_no_mod_ssl: True if we should warn if mod_ssl is not found.
        """

        # XXX if we ever try to enforce a local privilege boundary (eg, running
        # certbot for unprivileged users via setuid), this function will need
        # to be modified.
        apache_config_path = self.pick_apache_config(warn_on_no_mod_ssl)

        return common.install_version_controlled_file(
            options_ssl, options_ssl_digest, apache_config_path, constants.ALL_SSL_OPTIONS_HASHES)

    def enable_autohsts(self, _unused_lineage: RenewableCert, domains: List[str]) -> None:
        """
        Enable the AutoHSTS enhancement for defined domains

        :param _unused_lineage: Certificate lineage object, unused
        :type _unused_lineage: certbot._internal.storage.RenewableCert

        :param domains: List of domains in certificate to enhance
        :type domains: `list` of `str`
        """

        self._autohsts_fetch_state()
        _enhanced_vhosts: List[obj.VirtualHost] = []
        for d in domains:
            matched_vhosts = self.choose_vhosts(d, create_if_no_ssl=False)
            # We should be handling only SSL vhosts for AutoHSTS
            vhosts = [vhost for vhost in matched_vhosts if vhost.ssl]

            if not vhosts:
                msg_tmpl = ("Certbot was not able to find SSL VirtualHost for a "
                            "domain {0} for enabling AutoHSTS enhancement.")
                msg = msg_tmpl.format(d)
                logger.error(msg)
                raise errors.PluginError(msg)
            for vh in vhosts:
                try:
                    self._enable_autohsts_domain(vh)
                    _enhanced_vhosts.append(vh)
                except errors.PluginEnhancementAlreadyPresent:
                    if vh in _enhanced_vhosts:
                        continue
                    msg = ("VirtualHost for domain {0} in file {1} has a " +
                           "String-Transport-Security header present, exiting.")
                    raise errors.PluginEnhancementAlreadyPresent(
                        msg.format(d, vh.filep))
        if _enhanced_vhosts:
            note_msg = "Enabling AutoHSTS"
            self.save(note_msg)
            logger.info(note_msg)
            self.restart()

        # Save the current state to pluginstorage
        self._autohsts_save_state()

    def _enable_autohsts_domain(self, ssl_vhost: obj.VirtualHost) -> None:
        """Do the initial AutoHSTS deployment to a vhost

        :param ssl_vhost: The VirtualHost object to deploy the AutoHSTS
        :type ssl_vhost: :class:`~certbot_apache._internal.obj.VirtualHost` or None

        :raises errors.PluginEnhancementAlreadyPresent: When already enhanced

        """
        # This raises the exception
        self._verify_no_matching_http_header(ssl_vhost, "Strict-Transport-Security")

        if "headers_module" not in self.parser.modules:
            self.enable_mod("headers")
        # Prepare the HSTS header value
        hsts_header = constants.HEADER_ARGS["Strict-Transport-Security"][:-1]
        initial_maxage = constants.AUTOHSTS_STEPS[0]
        hsts_header.append("\"max-age={0}\"".format(initial_maxage))

        # Add ID to the VirtualHost for mapping back to it later
        uniq_id = self.add_vhost_id(ssl_vhost)
        if uniq_id is None:
            raise errors.Error("Could not generate a unique id")  # pragma: no cover
        self.save_notes += "Adding unique ID {0} to VirtualHost in {1}\n".format(
            uniq_id, ssl_vhost.filep)
        # Add the actual HSTS header
        self.parser.add_dir(ssl_vhost.path, "Header", hsts_header)
        note_msg = ("Adding gradually increasing HSTS header with initial value "
                    "of {0} to VirtualHost in {1}\n".format(
            initial_maxage, ssl_vhost.filep))
        self.save_notes += note_msg

        # Save the current state to pluginstorage
        self._autohsts[uniq_id] = {"laststep": 0, "timestamp": time.time()}

    def update_autohsts(self, _unused_domain: str) -> None:
        """
        Increase the AutoHSTS values of VirtualHosts that the user has enabled
        this enhancement for.

        :param _unused_domain: Not currently used
        :type _unused_domain: Not Available

        """
        self._autohsts_fetch_state()
        if not self._autohsts:
            # No AutoHSTS enabled for any domain
            return
        curtime = time.time()
        save_and_restart = False
        for id_str, config in list(self._autohsts.items()):
            if config["timestamp"] + constants.AUTOHSTS_FREQ > curtime:
                # Skip if last increase was < AUTOHSTS_FREQ ago
                continue
            nextstep = cast(int, config["laststep"]) + 1
            if nextstep < len(constants.AUTOHSTS_STEPS):
                # If installer hasn't been prepared yet, do it now
                if not self._prepared:
                    self.prepare()
                # Have not reached the max value yet
                try:
                    vhost = self.find_vhost_by_id(id_str)
                except errors.PluginError:
                    msg = ("Could not find VirtualHost with ID {0}, disabling "
                           "AutoHSTS for this VirtualHost").format(id_str)
                    logger.error(msg)
                    # Remove the orphaned AutoHSTS entry from pluginstorage
                    self._autohsts.pop(id_str)
                    continue
                self._autohsts_increase(vhost, id_str, nextstep)
                msg = ("Increasing HSTS max-age value for VirtualHost with id "
                       "{0}").format(id_str)
                self.save_notes += msg
                save_and_restart = True

        if save_and_restart:
            self.save("Increased HSTS max-age values")
            self.restart()

        self._autohsts_save_state()

    def deploy_autohsts(self, lineage: RenewableCert) -> None:
        """
        Checks if autohsts vhost has reached maximum auto-increased value
        and changes the HSTS max-age to a high value.

        :param lineage: Certificate lineage object
        :type lineage: certbot._internal.storage.RenewableCert
        """
        self._autohsts_fetch_state()
        if not self._autohsts:
            # No autohsts enabled for any vhost
            return

        vhosts: List[obj.VirtualHost] = []
        affected_ids = []
        # Copy, as we are removing from the dict inside the loop
        for id_str, config in list(self._autohsts.items()):
            if config["laststep"]+1 >= len(constants.AUTOHSTS_STEPS):
                # max value reached, try to make permanent
                try:
                    vhost: obj.VirtualHost = self.find_vhost_by_id(id_str)
                except errors.PluginError:
                    msg = ("VirtualHost with id {} was not found, unable to "
                           "make HSTS max-age permanent.").format(id_str)
                    logger.error(msg)
                    self._autohsts.pop(id_str)
                    continue
                if self._autohsts_vhost_in_lineage(vhost, lineage):
                    vhosts.append(vhost)
                    affected_ids.append(id_str)

        save_and_restart = False
        for vhost in vhosts:
            self._autohsts_write(vhost, constants.AUTOHSTS_PERMANENT)
            msg = ("Strict-Transport-Security max-age value for "
                   "VirtualHost in {0} was made permanent.").format(vhost.filep)
            logger.debug(msg)
            self.save_notes += msg+"\n"
            save_and_restart = True

        if save_and_restart:
            self.save("Made HSTS max-age permanent")
            self.restart()

        for id_str in affected_ids:
            self._autohsts.pop(id_str)

        # Update AutoHSTS storage (We potentially removed vhosts from managed)
        self._autohsts_save_state()


AutoHSTSEnhancement.register(ApacheConfigurator)
