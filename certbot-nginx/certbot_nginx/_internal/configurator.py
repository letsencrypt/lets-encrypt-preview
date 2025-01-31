# pylint: disable=too-many-lines
"""Nginx Configuration"""
import atexit
from contextlib import ExitStack
import logging
import importlib.resources
import re
import socket
import subprocess
import tempfile
import time
from typing import Any
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Optional
from typing import Sequence
from typing import Set
from typing import Tuple
from typing import Type
from typing import Union
from typing import cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from acme import challenges
from acme import crypto_util as acme_crypto_util
from certbot import achallenges
from certbot import crypto_util
from certbot import errors
from certbot import util
from certbot.compat import os
from certbot.display import util as display_util
from certbot.plugins import common
from certbot_nginx._internal import constants
from certbot_nginx._internal import display_ops
from certbot_nginx._internal import http_01
from certbot_nginx._internal import nginxparser
from certbot_nginx._internal import obj
from certbot_nginx._internal import parser

NAME_RANK = 0
START_WILDCARD_RANK = 1
END_WILDCARD_RANK = 2
REGEX_RANK = 3
NO_SSL_MODIFIER = 4


logger = logging.getLogger(__name__)


class NginxConfigurator(common.Configurator):
    """Nginx configurator.

    .. todo:: Add proper support for comments in the config. Currently,
        config files modified by the configurator will lose all their comments.

    :ivar config: Configuration.
    :type config: certbot.configuration.NamespaceConfig

    :ivar parser: Handles low level parsing
    :type parser: :class:`~certbot_nginx._internal.parser`

    :ivar str save_notes: Human-readable config change notes

    :ivar reverter: saves and reverts checkpoints
    :type reverter: :class:`certbot.reverter.Reverter`

    :ivar tup version: version of Nginx

    """

    description = "Nginx Web Server plugin"

    DEFAULT_LISTEN_PORT = '80'

    # SSL directives that Certbot can add when installing a new certificate.
    SSL_DIRECTIVES = ['ssl_certificate', 'ssl_certificate_key', 'ssl_dhparam']

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None]) -> None:
        default_server_root = _determine_default_server_root()
        add("server-root", default=constants.CLI_DEFAULTS["server_root"],
            help="Nginx server root directory. (default: %s)" % default_server_root)
        add("ctl", default=constants.CLI_DEFAULTS["ctl"], help="Path to the "
            "'nginx' binary, used for 'configtest' and retrieving nginx "
            "version number.")
        add("sleep-seconds", default=constants.CLI_DEFAULTS["sleep_seconds"], type=int,
            help="Number of seconds to wait for nginx configuration changes "
            "to apply when reloading.")

    @property
    def nginx_conf(self) -> str:
        """Nginx config file path."""
        return os.path.join(self.conf("server_root"), "nginx.conf")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize an Nginx Configurator.

        :param tup version: version of Nginx as a tuple (1, 4, 7)
            (used mostly for unittesting)

        :param tup openssl_version: version of OpenSSL linked to Nginx as a tuple (1, 4, 7)
            (used mostly for unittesting)

        """
        version = kwargs.pop("version", None)
        openssl_version = kwargs.pop("openssl_version", None)
        super().__init__(*args, **kwargs)

        # Files to save
        self.save_notes = ""

        # For creating new vhosts if no names match
        self.new_vhost: Optional[obj.VirtualHost] = None

        # List of vhosts configured per wildcard domain on this run.
        # used by deploy_cert() and enhance()
        self._wildcard_vhosts: Dict[str, List[obj.VirtualHost]] = {}
        self._wildcard_redirect_vhosts: Dict[str, List[obj.VirtualHost]] = {}

        # Add number of outstanding challenges
        self._chall_out = 0

        # These will be set in the prepare function
        self.version = version
        self.openssl_version = openssl_version
        self._enhance_func = {"redirect": self._enable_redirect,
                              "ensure-http-header": self._set_http_header,
                              "staple-ocsp": self._enable_ocsp_stapling}

        self.reverter.recovery_routine()
        self.parser: parser.NginxParser

    @property
    def mod_ssl_conf_src(self) -> str:
        """Full absolute path to SSL configuration file source."""

        # Why all this complexity? Well, we want to support Mozilla's intermediate
        # recommendations. But TLS1.3 is only supported by newer versions of Nginx.
        # And as for session tickets, our ideal is to turn them off across the board.
        # But! Turning them off at all is only supported with new enough versions of
        # Nginx. And older versions of OpenSSL have a bug that leads to browser errors
        # given certain configurations. While we'd prefer to have forward secrecy, we'd
        # rather fail open than error out. Unfortunately, Nginx can be compiled against
        # many versions of OpenSSL. So we have to check both for the two different features,
        # leading to four different combinations of options.
        # For a complete history, check out https://github.com/certbot/certbot/issues/7322

        use_tls13 = self.version >= (1, 13, 0)
        min_openssl_version = util.parse_loose_version('1.0.2l')
        session_tix_off = self.version >= (1, 5, 9) and self.openssl_version and\
            util.parse_loose_version(self.openssl_version) >= min_openssl_version

        if use_tls13:
            if session_tix_off:
                config_filename = "options-ssl-nginx.conf"
            else:
                config_filename = "options-ssl-nginx-tls13-session-tix-on.conf"
        else:
            if session_tix_off:
                config_filename = "options-ssl-nginx-tls12-only.conf"
            else:
                config_filename = "options-ssl-nginx-old.conf"

        file_manager = ExitStack()
        atexit.register(file_manager.close)
        ref = (importlib.resources.files("certbot_nginx").joinpath("_internal")
               .joinpath("tls_configs").joinpath(config_filename))

        return str(file_manager.enter_context(importlib.resources.as_file(ref)))

    @property
    def mod_ssl_conf(self) -> str:
        """Full absolute path to SSL configuration file."""
        return os.path.join(self.config.config_dir, constants.MOD_SSL_CONF_DEST)

    @property
    def updated_mod_ssl_conf_digest(self) -> str:
        """Full absolute path to digest of updated SSL configuration file."""
        return os.path.join(self.config.config_dir, constants.UPDATED_MOD_SSL_CONF_DIGEST)

    def install_ssl_options_conf(self, options_ssl: str, options_ssl_digest: str) -> None:
        """Copy Certbot's SSL options file into the system's config dir if required."""
        common.install_version_controlled_file(
            options_ssl, options_ssl_digest,
            self.mod_ssl_conf_src, constants.ALL_SSL_OPTIONS_HASHES)

    # This is called in determine_authenticator and determine_installer
    def prepare(self) -> None:
        """Prepare the authenticator/installer.

        :raises .errors.NoInstallationError: If Nginx ctl cannot be found
        :raises .errors.MisconfigurationError: If Nginx is misconfigured
        """
        # Verify Nginx is installed
        if not util.exe_exists(self.conf('ctl')):
            raise errors.NoInstallationError(
                "Could not find a usable 'nginx' binary. Ensure nginx exists, "
                "the binary is executable, and your PATH is set correctly.")

        # Make sure configuration is valid
        self.config_test()

        self.parser = parser.NginxParser(self.conf('server-root'))

        # Set Version
        if self.version is None:
            self.version = self.get_version()

        if self.openssl_version is None:
            self.openssl_version = self._get_openssl_version()

        self.install_ssl_options_conf(self.mod_ssl_conf, self.updated_mod_ssl_conf_digest)

        self.install_ssl_dhparams()

        # Prevent two Nginx plugins from modifying a config at once
        try:
            util.lock_dir_until_exit(self.conf('server-root'))
        except (OSError, errors.LockError):
            logger.debug('Encountered error:', exc_info=True)
            raise errors.PluginError('Unable to lock {0}'.format(self.conf('server-root')))

    # Entry point in main.py for installing cert
    def deploy_cert(self, domain: str, cert_path: str, key_path: str, chain_path: str,
                    fullchain_path: str) -> None:
        """Deploys certificate to specified virtual host.

        .. note:: Aborts if the vhost is missing ssl_certificate or
            ssl_certificate_key.

        .. note:: This doesn't save the config files!

        :raises errors.PluginError: When unable to deploy certificate due to
            a lack of directives or configuration

        """
        if not fullchain_path:
            raise errors.PluginError(
                "The nginx plugin currently requires --fullchain-path to "
                "install a certificate.")

        vhosts = self.choose_vhosts(domain, create_if_no_match=True)
        for vhost in vhosts:
            self._deploy_cert(vhost, cert_path, key_path, chain_path, fullchain_path)
            display_util.notify("Successfully deployed certificate for {} to {}"
                                .format(domain, vhost.filep))

    def _deploy_cert(self, vhost: obj.VirtualHost, _cert_path: str, key_path: str,
                     _chain_path: str, fullchain_path: str) -> None:
        """
        Helper function for deploy_cert() that handles the actual deployment
        this exists because we might want to do multiple deployments per
        domain originally passed for deploy_cert(). This is especially true
        with wildcard certificates
        """
        cert_directives = [['\n    ', 'ssl_certificate', ' ', fullchain_path],
                           ['\n    ', 'ssl_certificate_key', ' ', key_path]]

        self.parser.update_or_add_server_directives(vhost, cert_directives)
        logger.info("Deploying Certificate to VirtualHost %s", vhost.filep)

        self.save_notes += ("Changed vhost at %s with addresses of %s\n" %
                            (vhost.filep,
                             ", ".join(str(addr) for addr in vhost.addrs)))
        self.save_notes += "\tssl_certificate %s\n" % fullchain_path
        self.save_notes += "\tssl_certificate_key %s\n" % key_path

    def _choose_vhosts_wildcard(self, domain: str, prefer_ssl: bool,
                                no_ssl_filter_port: Optional[str] = None) -> List[obj.VirtualHost]:
        """Prompts user to choose vhosts to install a wildcard certificate for"""
        if prefer_ssl:
            vhosts_cache = self._wildcard_vhosts
            def preference_test(x: obj.VirtualHost) -> bool:
                return x.ssl
        else:
            vhosts_cache = self._wildcard_redirect_vhosts
            def preference_test(x: obj.VirtualHost) -> bool:
                return not x.ssl

        # Caching!
        if domain in vhosts_cache:
            # Vhosts for a wildcard domain were already selected
            return vhosts_cache[domain]

        # Get all vhosts whether or not they are covered by the wildcard domain
        vhosts = self.parser.get_vhosts()

        # Go through the vhosts, making sure that we cover all the names
        # present, but preferring the SSL or non-SSL vhosts
        filtered_vhosts = {}
        for vhost in vhosts:
            # Ensure we're listening non-sslishly on no_ssl_filter_port
            if no_ssl_filter_port is not None:
                if not self._vhost_listening_on_port_no_ssl(vhost, no_ssl_filter_port):
                    continue
            for name in vhost.names:
                if preference_test(vhost):
                    # Prefer either SSL or non-SSL vhosts
                    filtered_vhosts[name] = vhost
                elif name not in filtered_vhosts:
                    # Add if not in list previously
                    filtered_vhosts[name] = vhost

        # Only unique VHost objects
        dialog_input = set(filtered_vhosts.values())

        # Ask the user which of names to enable, expect list of names back
        return_vhosts = display_ops.select_vhost_multiple(list(dialog_input))

        for vhost in return_vhosts:
            if domain not in vhosts_cache:
                vhosts_cache[domain] = []
            vhosts_cache[domain].append(vhost)

        return return_vhosts

    #######################
    # Vhost parsing methods
    #######################
    def _choose_vhost_single(self, target_name: str) -> List[obj.VirtualHost]:
        matches = self._get_ranked_matches(target_name)
        vhosts = [x for x in [self._select_best_name_match(matches)] if x is not None]
        return vhosts

    def choose_vhosts(self, target_name: str,
                      create_if_no_match: bool = False) -> List[obj.VirtualHost]:
        """Chooses a virtual host based on the given domain name.

        .. note:: This makes the vhost SSL-enabled if it isn't already. Follows
            Nginx's server block selection rules preferring blocks that are
            already SSL.

        .. todo:: This should maybe return list if no obvious answer
            is presented.

        :param str target_name: domain name
        :param bool create_if_no_match: If we should create a new vhost from default
            when there is no match found. If we can't choose a default, raise a
            MisconfigurationError.

        :returns: ssl vhosts associated with name
        :rtype: list of :class:`~certbot_nginx._internal.obj.VirtualHost`

        """
        if util.is_wildcard_domain(target_name):
            # Ask user which VHosts to support.
            vhosts = self._choose_vhosts_wildcard(target_name, prefer_ssl=True)
        else:
            vhosts = self._choose_vhost_single(target_name)
        if not vhosts:
            if create_if_no_match:
                # result will not be [None] because it errors on failure
                vhosts = [self._vhost_from_duplicated_default(target_name, True,
                    str(self.config.https_port))]
            else:
                # No matches. Raise a misconfiguration error.
                raise errors.MisconfigurationError(
                            ("Cannot find a VirtualHost matching domain %s. "
                             "In order for Certbot to correctly perform the challenge "
                             "please add a corresponding server_name directive to your "
                             "nginx configuration for every domain on your certificate: "
                             "https://nginx.org/en/docs/http/server_names.html") % (target_name))
        # Note: if we are enhancing with ocsp, vhost should already be ssl.
        for vhost in vhosts:
            if not vhost.ssl:
                self._make_server_ssl(vhost)

        return vhosts

    def ipv6_info(self, host: str, port: str) -> Tuple[bool, bool]:
        """Returns tuple of booleans (ipv6_active, ipv6only_present)
        ipv6_active is true if any server block listens ipv6 address in any port

        ipv6only_present is true if ipv6only=on option exists in any server
        block ipv6 listen directive for the specified port.

        :param str host: Host to check ipv6only=on directive for
        :param str port: Port to check ipv6only=on directive for

        :returns: Tuple containing information if IPv6 is enabled in the global
            configuration, and existence of ipv6only directive for specified port
        :rtype: tuple of type (bool, bool)
        """
        vhosts = self.parser.get_vhosts()
        ipv6_active = False
        ipv6only_present = False
        for vh in vhosts:
            for addr in vh.addrs:
                if addr.ipv6:
                    ipv6_active = True
                if addr.ipv6only and addr.get_port() == port and addr.get_addr() == host:
                    ipv6only_present = True
        return ipv6_active, ipv6only_present

    def _vhost_from_duplicated_default(self, domain: str, allow_port_mismatch: bool,
                                       port: str) -> obj.VirtualHost:
        """if allow_port_mismatch is False, only server blocks with matching ports will be
           used as a default server block template.
        """
        assert self.parser is not None # prepare should already have been called here

        if self.new_vhost is None:
            default_vhost = self._get_default_vhost(domain, allow_port_mismatch, port)
            self.new_vhost = self.parser.duplicate_vhost(default_vhost,
                remove_singleton_listen_params=True)
            self.new_vhost.names = set()

        self._add_server_name_to_vhost(self.new_vhost, domain)
        return self.new_vhost

    def _add_server_name_to_vhost(self, vhost: obj.VirtualHost, domain: str) -> None:
        vhost.names.add(domain)
        name_block = [['\n    ', 'server_name']]
        for name in vhost.names:
            name_block[0].append(' ')
            name_block[0].append(name)
        self.parser.update_or_add_server_directives(vhost, name_block)

    def _get_default_vhost(self, domain: str, allow_port_mismatch: bool,
                           port: str) -> obj.VirtualHost:
        """Helper method for _vhost_from_duplicated_default; see argument documentation there"""
        vhost_list = self.parser.get_vhosts()
        # if one has default_server set, return that one
        all_default_vhosts = []
        port_matching_vhosts = []
        for vhost in vhost_list:
            for addr in vhost.addrs:
                if addr.default:
                    all_default_vhosts.append(vhost)
                    if self._port_matches(port, addr.get_port()):
                        port_matching_vhosts.append(vhost)
                    break

        if len(port_matching_vhosts) == 1:
            return port_matching_vhosts[0]
        elif len(all_default_vhosts) == 1 and allow_port_mismatch:
            return all_default_vhosts[0]

        # TODO: present a list of vhosts for user to choose from

        raise errors.MisconfigurationError("Could not automatically find a matching server "
                                           f"block for {domain}. Set the `server_name` directive "
                                           "to use the Nginx installer.")

    def _get_ranked_matches(self, target_name: str) -> List[Dict[str, Any]]:
        """Returns a ranked list of vhosts that match target_name.
        The ranking gives preference to SSL vhosts.

        :param str target_name: The name to match
        :returns: list of dicts containing the vhost, the matching name, and
            the numerical rank
        :rtype: list

        """
        vhost_list = self.parser.get_vhosts()
        return self._rank_matches_by_name_and_ssl(vhost_list, target_name)

    def _select_best_name_match(self,
                                matches: Sequence[Mapping[str, Any]]) -> Optional[obj.VirtualHost]:
        """Returns the best name match of a ranked list of vhosts.

        :param list matches: list of dicts containing the vhost, the matching name,
            and the numerical rank
        :returns: the most matching vhost
        :rtype: :class:`~certbot_nginx._internal.obj.VirtualHost`

        """
        if not matches:
            return None
        elif matches[0]['rank'] in [START_WILDCARD_RANK, END_WILDCARD_RANK,
            START_WILDCARD_RANK + NO_SSL_MODIFIER, END_WILDCARD_RANK + NO_SSL_MODIFIER]:
            # Wildcard match - need to find the longest one
            rank = matches[0]['rank']
            wildcards = [x for x in matches if x['rank'] == rank]
            return cast(obj.VirtualHost, max(wildcards, key=lambda x: len(x['name']))['vhost'])
        # Exact or regex match
        return cast(obj.VirtualHost, matches[0]['vhost'])

    def _rank_matches_by_name(self, vhost_list: Iterable[obj.VirtualHost],
                              target_name: str) -> List[Dict[str, Any]]:
        """Returns a ranked list of vhosts from vhost_list that match target_name.
        This method should always be followed by a call to _select_best_name_match.

        :param list vhost_list: list of vhosts to filter and rank
        :param str target_name: The name to match
        :returns: list of dicts containing the vhost, the matching name, and
            the numerical rank
        :rtype: list

        """
        # Nginx chooses a matching server name for a request with precedence:
        # 1. exact name match
        # 2. longest wildcard name starting with *
        # 3. longest wildcard name ending with *
        # 4. first matching regex in order of appearance in the file
        matches = []
        for vhost in vhost_list:
            name_type, name = parser.get_best_match(target_name, vhost.names)
            if name_type == 'exact':
                matches.append({'vhost': vhost,
                                'name': name,
                                'rank': NAME_RANK})
            elif name_type == 'wildcard_start':
                matches.append({'vhost': vhost,
                                'name': name,
                                'rank': START_WILDCARD_RANK})
            elif name_type == 'wildcard_end':
                matches.append({'vhost': vhost,
                                'name': name,
                                'rank': END_WILDCARD_RANK})
            elif name_type == 'regex':
                matches.append({'vhost': vhost,
                                'name': name,
                                'rank': REGEX_RANK})
        return sorted(matches, key=lambda x: x['rank'])

    def _rank_matches_by_name_and_ssl(self, vhost_list: Iterable[obj.VirtualHost],
                                      target_name: str) -> List[Dict[str, Any]]:
        """Returns a ranked list of vhosts from vhost_list that match target_name.
        The ranking gives preference to SSLishness before name match level.

        :param list vhost_list: list of vhosts to filter and rank
        :param str target_name: The name to match
        :returns: list of dicts containing the vhost, the matching name, and
            the numerical rank
        :rtype: list

        """
        matches = self._rank_matches_by_name(vhost_list, target_name)
        for match in matches:
            if not match['vhost'].ssl:
                match['rank'] += NO_SSL_MODIFIER
        return sorted(matches, key=lambda x: x['rank'])

    def choose_redirect_vhosts(self, target_name: str, port: str) -> List[obj.VirtualHost]:
        """Chooses a single virtual host for redirect enhancement.

        Chooses the vhost most closely matching target_name that is
        listening to port without using ssl.

        .. todo:: This should maybe return list if no obvious answer
            is presented.

        .. todo:: The special name "$hostname" corresponds to the machine's
            hostname. Currently we just ignore this.

        :param str target_name: domain name
        :param str port: port number

        :returns: vhosts associated with name
        :rtype: list of :class:`~certbot_nginx._internal.obj.VirtualHost`

        """
        if util.is_wildcard_domain(target_name):
            # Ask user which VHosts to enhance.
            vhosts = self._choose_vhosts_wildcard(target_name, prefer_ssl=False,
                no_ssl_filter_port=port)
        else:
            matches = self._get_redirect_ranked_matches(target_name, port)
            vhosts = [x for x in [self._select_best_name_match(matches)]if x is not None]
        return vhosts

    def choose_auth_vhosts(self, target_name: str) -> Tuple[List[obj.VirtualHost],
                                                            List[obj.VirtualHost]]:
        """Returns a list of HTTP and HTTPS vhosts with a server_name matching target_name.

        If no HTTP vhost exists, one will be cloned from the default vhost. If that fails, no HTTP
        vhost will be returned.

        :param str target_name: non-wildcard domain name

        :returns: tuple of HTTP and HTTPS virtualhosts
        :rtype: tuple of :class:`~certbot_nginx._internal.obj.VirtualHost`

        """
        vhosts = [m['vhost'] for m in self._get_ranked_matches(target_name) if m and 'vhost' in m]
        http_vhosts = [vh for vh in vhosts if
                       self._vhost_listening(vh, str(self.config.http01_port), False)]
        https_vhosts = [vh for vh in vhosts if
                        self._vhost_listening(vh, str(self.config.https_port), True)]

        # If no HTTP vhost matches, try create one from the default_server on http01_port.
        if not http_vhosts:
            try:
                http_vhosts = [self._vhost_from_duplicated_default(target_name, False,
                                                                   str(self.config.http01_port))]
            except errors.MisconfigurationError:
                http_vhosts = []

        return http_vhosts, https_vhosts

    def _port_matches(self, test_port: str, matching_port: str) -> bool:
        # test_port is a number, matching is a number or "" or None
        if matching_port == "" or matching_port is None:
            # if no port is specified, Nginx defaults to listening on port 80.
            return test_port == self.DEFAULT_LISTEN_PORT
        return test_port == matching_port

    def _vhost_listening(self, vhost: obj.VirtualHost, port: str, ssl: bool) -> bool:
        """Tests whether a vhost has an address listening on a port with SSL enabled or disabled.

        :param `obj.VirtualHost` vhost: The vhost whose addresses will be tested
        :param port str: The port number as a string that the address should be bound to
        :param bool ssl: Whether SSL should be enabled or disabled on the address

        :returns: Whether the vhost has an address listening on the port and protocol.
        :rtype: bool

        """
        assert self.parser is not None # prepare should already have been called here

        # if the 'ssl on' directive is present on the vhost, all its addresses have SSL enabled
        all_addrs_are_ssl = self.parser.has_ssl_on_directive(vhost)

        # if we want ssl vhosts: either 'ssl on' or 'addr.ssl' should be enabled
        # if we want plaintext vhosts: neither 'ssl on' nor 'addr.ssl' should be enabled
        def _ssl_matches(addr: obj.Addr) -> bool:
            return addr.ssl or all_addrs_are_ssl if ssl else \
                   not addr.ssl and not all_addrs_are_ssl

        # if there are no listen directives at all, Nginx defaults to
        # listening on port 80.
        if not vhost.addrs:
            return port == self.DEFAULT_LISTEN_PORT and ssl == all_addrs_are_ssl

        return any(self._port_matches(port, addr.get_port()) and _ssl_matches(addr)
                   for addr in vhost.addrs)

    def _vhost_listening_on_port_no_ssl(self, vhost: obj.VirtualHost, port: str) -> bool:
        return self._vhost_listening(vhost, port, False)

    def _get_redirect_ranked_matches(self, target_name: str, port: str) -> List[Dict[str, Any]]:
        """Gets a ranked list of plaintextish port-listening vhosts matching target_name

        Filter all hosts for those listening on port without using ssl.
        Rank by how well these match target_name.

        :param str target_name: The name to match
        :param str port: port number as a string
        :returns: list of dicts containing the vhost, the matching name, and
            the numerical rank
        :rtype: list

        """
        all_vhosts = self.parser.get_vhosts()

        def _vhost_matches(vhost: obj.VirtualHost, port: str) -> bool:
            return self._vhost_listening_on_port_no_ssl(vhost, port)

        matching_vhosts = [vhost for vhost in all_vhosts if _vhost_matches(vhost, port)]

        return self._rank_matches_by_name(matching_vhosts, target_name)

    def get_all_names(self) -> Set[str]:
        """Returns all names found in the Nginx Configuration.

        :returns: All ServerNames, ServerAliases, and reverse DNS entries for
                  virtual host addresses
        :rtype: set

        """
        all_names: Set[str] = set()

        for vhost in self.parser.get_vhosts():
            try:
                vhost.names.remove("$hostname")
                vhost.names.add(socket.gethostname())
            except KeyError:
                pass

            all_names.update(vhost.names)

            for addr in vhost.addrs:
                host = addr.get_addr()
                if common.hostname_regex.match(host):
                    # If it's a hostname, add it to the names.
                    all_names.add(host)
                elif not common.private_ips_regex.match(host):
                    # If it isn't a private IP, do a reverse DNS lookup
                    try:
                        if addr.ipv6:
                            host = addr.get_ipv6_exploded()
                            socket.inet_pton(socket.AF_INET6, host)
                        else:
                            socket.inet_pton(socket.AF_INET, host)
                        all_names.add(socket.gethostbyaddr(host)[0])
                    except (OSError, socket.herror, socket.timeout):
                        continue

        return util.get_filtered_names(all_names)

    def _get_snakeoil_paths(self) -> Tuple[str, str]:
        """Generate invalid certs that let us create ssl directives for Nginx"""
        # TODO: generate only once
        tmp_dir = os.path.join(self.config.work_dir, "snakeoil")
        le_key = crypto_util.generate_key(
            key_type='rsa', key_size=2048, key_dir=tmp_dir, keyname="key.pem",
            strict_permissions=self.config.strict_permissions)
        assert le_key.file is not None
        cryptography_key = serialization.load_pem_private_key(le_key.pem, password=None)
        assert isinstance(cryptography_key, rsa.RSAPrivateKey)
        cert = acme_crypto_util.make_self_signed_cert(
            cryptography_key,
            domains=[socket.gethostname()]
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        cert_file, cert_path = util.unique_file(
            os.path.join(tmp_dir, "cert.pem"), mode="wb")
        with cert_file:
            cert_file.write(cert_pem)
        return cert_path, le_key.file

    def _make_server_ssl(self, vhost: obj.VirtualHost) -> None:
        """Make a server SSL.

        Make a server SSL by adding new listen and SSL directives.

        :param vhost: The vhost to add SSL to.
        :type vhost: :class:`~certbot_nginx._internal.obj.VirtualHost`

        """
        https_port = self.config.https_port
        http_port = self.config.http01_port

        # no addresses should have ssl turned on here
        assert not vhost.ssl

        addrs_to_insert: List[obj.Addr] = [
            obj.Addr.fromstring(f'{addr.get_addr()}:{https_port} ssl')
            for addr in vhost.addrs
            if addr.get_port() == str(http_port)
        ]

        # If the vhost was implicitly listening on the default Nginx port,
        # have it continue to do so.
        if not vhost.addrs:
            listen_block = [['\n    ', 'listen', ' ', self.DEFAULT_LISTEN_PORT]]
            self.parser.add_server_directives(vhost, listen_block)

        if not addrs_to_insert:
            # there are no existing addresses listening on 80
            if vhost.ipv6_enabled():
                addrs_to_insert += [obj.Addr.fromstring(f'[::]:{https_port} ssl')]
            if vhost.ipv4_enabled():
                addrs_to_insert += [obj.Addr.fromstring(f'{https_port} ssl')]

        addr_blocks: List[List[str]] = []
        ipv6only_set_here: Set[Tuple[str, str]] = set()
        for addr in addrs_to_insert:
            host = addr.get_addr()
            port = addr.get_port()
            if addr.ipv6:
                addr_block = ['\n    ',
                              'listen',
                              ' ',
                              f'{host}:{port}',
                              ' ',
                              'ssl']
                ipv6only_exists = self.ipv6_info(host, port)[1]
                if not ipv6only_exists and (host, port) not in ipv6only_set_here:
                    addr.ipv6only = True # bookkeeping in case we switch output implementation
                    ipv6only_set_here.add((host, port))
                    addr_block.append(' ')
                    addr_block.append('ipv6only=on')
                addr_blocks.append(addr_block)
            else:
                tuple_string = f'{host}:{port}' if host else f'{port}'
                addr_block = ['\n    ',
                              'listen',
                              ' ',
                              tuple_string,
                              ' ',
                              'ssl']
                addr_blocks.append(addr_block)

        snakeoil_cert, snakeoil_key = self._get_snakeoil_paths()

        ssl_block = ([
            *addr_blocks,
            ['\n    ', 'ssl_certificate', ' ', snakeoil_cert],
            ['\n    ', 'ssl_certificate_key', ' ', snakeoil_key],
            ['\n    ', 'include', ' ', self.mod_ssl_conf],
            ['\n    ', 'ssl_dhparam', ' ', self.ssl_dhparams],
        ])

        self.parser.add_server_directives(
            vhost, ssl_block)

    ##################################
    # enhancement methods (Installer)
    ##################################
    def supported_enhancements(self) -> List[str]:
        """Returns currently supported enhancements."""
        return ['redirect', 'ensure-http-header', 'staple-ocsp']

    def enhance(self, domain: str, enhancement: str,
                options: Optional[Union[str, List[str]]] = None) -> None:
        """Enhance configuration.

        :param str domain: domain to enhance
        :param str enhancement: enhancement type defined in
            :const:`~certbot.plugins.enhancements.ENHANCEMENTS`
        :param options: options for the enhancement
            See :const:`~certbot.plugins.enhancements.ENHANCEMENTS`
            documentation for appropriate parameter.

        """
        try:
            self._enhance_func[enhancement](domain, options)
        except (KeyError, ValueError):
            raise errors.PluginError(
                "Unsupported enhancement: {0}".format(enhancement))

    def _has_certbot_redirect(self, vhost: obj.VirtualHost, domain: str) -> bool:
        test_redirect_block = _test_block_from_block(_redirect_block_for_domain(domain))
        return vhost.contains_list(test_redirect_block)

    def _set_http_header(self, domain: str, header_substring: Union[str, List[str], None]) -> None:
        """Enables header identified by header_substring on domain.

        If the vhost is listening plaintextishly, separates out the relevant
        directives into a new server block, and only add header directive to
        HTTPS block.

        :param str domain: the domain to enable header for.
        :param str header_substring: String to uniquely identify a header.
                        e.g. Strict-Transport-Security, Upgrade-Insecure-Requests
        :returns: Success
        :raises .errors.PluginError: If no viable HTTPS host can be created or
            set with header header_substring.
        """
        if not isinstance(header_substring, str):
            raise errors.NotSupportedError("Invalid header_substring type "
                                           f"{type(header_substring)}, expected a str.")
        if header_substring not in constants.HEADER_ARGS:
            raise errors.NotSupportedError(
                f"{header_substring} is not supported by the nginx plugin.")

        vhosts = self.choose_vhosts(domain)
        if not vhosts:
            raise errors.PluginError(
                "Unable to find corresponding HTTPS host for enhancement.")
        for vhost in vhosts:
            if vhost.has_header(header_substring):
                raise errors.PluginEnhancementAlreadyPresent(
                    "Existing %s header" % (header_substring))

            # if there is no separate SSL block, break the block into two and
            # choose the SSL block.
            if vhost.ssl and any(not addr.ssl for addr in vhost.addrs):
                _, vhost = self._split_block(vhost)

            header_directives = [
                ['\n    ', 'add_header', ' ', header_substring, ' '] +
                    constants.HEADER_ARGS[header_substring],
                ['\n']]
            self.parser.add_server_directives(vhost, header_directives)

    def _add_redirect_block(self, vhost: obj.VirtualHost, domain: str) -> None:
        """Add redirect directive to vhost
        """
        redirect_block = _redirect_block_for_domain(domain)

        self.parser.add_server_directives(
            vhost, redirect_block, insert_at_top=True)

    def _split_block(self, vhost: obj.VirtualHost, only_directives: Optional[List[str]] = None
                     ) -> Tuple[obj.VirtualHost, obj.VirtualHost]:
        """Splits this "virtual host" (i.e. this nginx server block) into
        separate HTTP and HTTPS blocks.

        :param vhost: The server block to break up into two.
        :param list only_directives: If this exists, only duplicate these directives
            when splitting the block.
        :type vhost: :class:`~certbot_nginx._internal.obj.VirtualHost`
        :returns: tuple (http_vhost, https_vhost)
        :rtype: tuple of type :class:`~certbot_nginx._internal.obj.VirtualHost`
        """
        http_vhost = self.parser.duplicate_vhost(vhost, only_directives=only_directives)

        def _ssl_match_func(directive: str) -> bool:
            return 'ssl' in directive

        def _ssl_config_match_func(directive: str) -> bool:
            return self.mod_ssl_conf in directive

        def _no_ssl_match_func(directive: str) -> bool:
            return 'ssl' not in directive

        # remove all ssl addresses and related directives from the new block
        for directive in self.SSL_DIRECTIVES:
            self.parser.remove_server_directives(http_vhost, directive)
        self.parser.remove_server_directives(http_vhost, 'listen', match_func=_ssl_match_func)
        self.parser.remove_server_directives(http_vhost, 'include',
                                             match_func=_ssl_config_match_func)

        # remove all non-ssl addresses from the existing block
        self.parser.remove_server_directives(vhost, 'listen', match_func=_no_ssl_match_func)
        return http_vhost, vhost

    def _enable_redirect(self, domain: str,
                         unused_options: Optional[Union[str, List[str]]]) -> None:
        """Redirect all equivalent HTTP traffic to ssl_vhost.

        If the vhost is listening plaintextishly, separate out the
        relevant directives into a new server block and add a rewrite directive.

        .. note:: This function saves the configuration

        :param str domain: domain to enable redirect for
        :param unused_options: Not currently used
        :type unused_options: Not Available
        """

        port = self.DEFAULT_LISTEN_PORT
        # If there are blocks listening plaintextishly on self.DEFAULT_LISTEN_PORT,
        # choose the most name-matching one.

        vhosts = self.choose_redirect_vhosts(domain, port)

        if not vhosts:
            logger.info("No matching insecure server blocks listening on port %s found.",
                self.DEFAULT_LISTEN_PORT)
            return

        for vhost in vhosts:
            self._enable_redirect_single(domain, vhost)

    def _enable_redirect_single(self, domain: str, vhost: obj.VirtualHost) -> None:
        """Redirect all equivalent HTTP traffic to ssl_vhost.

        If the vhost is listening plaintextishly, separate out the
        relevant directives into a new server block and add a rewrite directive.

        .. note:: This function saves the configuration

        :param str domain: domain to enable redirect for
        :param `~obj.Vhost` vhost: vhost to enable redirect for
        """
        if vhost.ssl:
            http_vhost, _ = self._split_block(vhost, ['listen', 'server_name'])

            # Add this at the bottom to get the right order of directives
            return_404_directive = [['\n    ', 'return', ' ', '404']]
            self.parser.add_server_directives(http_vhost, return_404_directive)

            vhost = http_vhost

        if self._has_certbot_redirect(vhost, domain):
            logger.info("Traffic on port %s already redirecting to ssl in %s",
                self.DEFAULT_LISTEN_PORT, vhost.filep)
        else:
            # Redirect plaintextish host to https
            self._add_redirect_block(vhost, domain)
            logger.info("Redirecting all traffic on port %s to ssl in %s",
                self.DEFAULT_LISTEN_PORT, vhost.filep)

    def _enable_ocsp_stapling(self, domain: str,
                              chain_path: Optional[Union[str, List[str]]]) -> None:
        """Include OCSP response in TLS handshake

        :param str domain: domain to enable OCSP response for
        :param chain_path: chain file path
        :type chain_path: `str` or `None`

        """
        if not isinstance(chain_path, str) and chain_path is not None:
            raise errors.NotSupportedError(f"Invalid chain_path type {type(chain_path)}, "
                                           "expected a str or None.")
        vhosts = self.choose_vhosts(domain)
        for vhost in vhosts:
            self._enable_ocsp_stapling_single(vhost, chain_path)

    def _enable_ocsp_stapling_single(self, vhost: obj.VirtualHost,
                                     chain_path: Optional[str]) -> None:
        """Include OCSP response in TLS handshake

        :param str vhost: vhost to enable OCSP response for
        :param chain_path: chain file path
        :type chain_path: `str` or `None`

        """
        if self.version < (1, 3, 7):
            raise errors.PluginError("Version 1.3.7 or greater of nginx "
                                     "is needed to enable OCSP stapling")

        if chain_path is None:
            raise errors.PluginError(
                "--chain-path is required to enable "
                "Online Certificate Status Protocol (OCSP) stapling "
                "on nginx >= 1.3.7.")

        stapling_directives = [
            ['\n    ', 'ssl_trusted_certificate', ' ', chain_path],
            ['\n    ', 'ssl_stapling', ' ', 'on'],
            ['\n    ', 'ssl_stapling_verify', ' ', 'on'], ['\n']]

        try:
            self.parser.add_server_directives(vhost,
                                              stapling_directives)
        except errors.MisconfigurationError as error:
            logger.debug(str(error))
            raise errors.PluginError("An error occurred while enabling OCSP "
                                     "stapling for {0}.".format(vhost.names))

        self.save_notes += ("OCSP Stapling was enabled "
                            "on SSL Vhost: {0}.\n".format(vhost.filep))
        self.save_notes += "\tssl_trusted_certificate {0}\n".format(chain_path)
        self.save_notes += "\tssl_stapling on\n"
        self.save_notes += "\tssl_stapling_verify on\n"

    ######################################
    # Nginx server management (Installer)
    ######################################
    def restart(self) -> None:
        """Restarts nginx server.

        :raises .errors.MisconfigurationError: If either the reload fails.

        """
        nginx_restart(self.conf('ctl'), self.nginx_conf, self.conf('sleep-seconds'))

    def config_test(self) -> None:
        """Check the configuration of Nginx for errors.

        :raises .errors.MisconfigurationError: If config_test fails

        """
        try:
            util.run_script([self.conf('ctl'), "-c", self.nginx_conf, "-t"])
        except errors.SubprocessError as err:
            raise errors.MisconfigurationError(str(err))

    def _nginx_version(self) -> str:
        """Return results of nginx -V

        :returns: version text
        :rtype: str

        :raises .PluginError:
            Unable to run Nginx version command
        """
        try:
            proc = subprocess.run(
                [self.conf('ctl'), "-c", self.nginx_conf, "-V"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                check=False,
                env=util.env_no_snap_for_external_calls())
            text = proc.stderr  # nginx prints output to stderr
        except (OSError, ValueError) as error:
            logger.debug(str(error), exc_info=True)
            raise errors.PluginError(
                "Unable to run %s -V" % self.conf('ctl'))
        return text

    def get_version(self) -> Tuple[int, ...]:
        """Return version of Nginx Server.

        Version is returned as tuple. (ie. 2.4.7 = (2, 4, 7))

        :returns: version
        :rtype: tuple

        :raises .PluginError:
            Unable to find Nginx version or version is unsupported

        """
        text = self._nginx_version()

        version_regex = re.compile(r"nginx version: ([^/]+)/([0-9\.]*)", re.IGNORECASE)
        version_matches = version_regex.findall(text)

        sni_regex = re.compile(r"TLS SNI support enabled", re.IGNORECASE)
        sni_matches = sni_regex.findall(text)

        ssl_regex = re.compile(r" --with-http_ssl_module")
        ssl_matches = ssl_regex.findall(text)

        if not version_matches:
            raise errors.PluginError("Unable to find Nginx version")
        if not ssl_matches:
            raise errors.PluginError(
                "Nginx build is missing SSL module (--with-http_ssl_module).")
        if not sni_matches:
            raise errors.PluginError("Nginx build doesn't support SNI")

        product_name, product_version = version_matches[0]
        if product_name != 'nginx':
            logger.warning("NGINX derivative %s is not officially supported by"
                           " certbot", product_name)

        nginx_version = tuple(int(i) for i in product_version.split("."))

        # nginx < 0.8.48 uses machine hostname as default server_name instead of
        # the empty string
        if nginx_version < (0, 8, 48):
            raise errors.NotSupportedError("Nginx version must be 0.8.48+")

        return nginx_version

    def _get_openssl_version(self) -> str:
        """Return version of OpenSSL linked to Nginx.

        Version is returned as string. If no version can be found, empty string is returned.

        :returns: openssl_version
        :rtype: str

        :raises .PluginError:
            Unable to run Nginx version command
        """
        text = self._nginx_version()

        matches: List[str] = re.findall(r"running with OpenSSL ([^ ]+) ", text)
        if not matches:
            matches = re.findall(r"built with OpenSSL ([^ ]+) ", text)
            if not matches:
                logger.warning("NGINX configured with OpenSSL alternatives is not officially"
                    " supported by Certbot.")
                return ""
        return matches[0]

    def more_info(self) -> str:
        """Human-readable string to help understand the module"""
        return (
            "Configures Nginx to authenticate and install HTTPS.{0}"
            "Server root: {root}{0}"
            "Version: {version}".format(
                os.linesep, root=self.parser.config_root,
                version=".".join(str(i) for i in self.version))
        )

    def auth_hint(self,  # pragma: no cover
                  failed_achalls: Iterable[achallenges.AnnotatedChallenge]) -> str:
        return (
            "The Certificate Authority failed to verify the temporary nginx configuration changes "
            "made by Certbot. Ensure the listed domains point to this nginx server and that it is "
            "accessible from the internet."
        )

    ###################################################
    # Wrapper functions for Reverter class (Installer)
    ###################################################
    def save(self, title: Optional[str] = None, temporary: bool = False) -> None:
        """Saves all changes to the configuration files.

        :param str title: The title of the save. If a title is given, the
            configuration will be saved as a new checkpoint and put in a
            timestamped directory.

        :param bool temporary: Indicates whether the changes made will
            be quickly reversed in the future (ie. challenges)

        :raises .errors.PluginError: If there was an error in
            an attempt to save the configuration, or an error creating a
            checkpoint

        """
        save_files = set(self.parser.parsed.keys())
        self.add_to_checkpoint(save_files, self.save_notes, temporary)
        self.save_notes = ""

        # Change 'ext' to something else to not override existing conf files
        self.parser.filedump(ext='')
        if title and not temporary:
            self.finalize_checkpoint(title)

    def recovery_routine(self) -> None:
        """Revert all previously modified files.

        Reverts all modified files that have not been saved as a checkpoint

        :raises .errors.PluginError: If unable to recover the configuration

        """
        super().recovery_routine()
        self.new_vhost = None
        self.parser.load()

    def revert_challenge_config(self) -> None:
        """Used to cleanup challenge configurations.

        :raises .errors.PluginError: If unable to revert the challenge config.

        """
        self.revert_temporary_config()
        self.new_vhost = None
        self.parser.load()

    def rollback_checkpoints(self, rollback: int = 1) -> None:
        """Rollback saved checkpoints.

        :param int rollback: Number of checkpoints to revert

        :raises .errors.PluginError: If there is a problem with the input or
            the function is unable to correctly revert the configuration

        """
        super().rollback_checkpoints(rollback)
        self.new_vhost = None
        self.parser.load()

    ###########################################################################
    # Challenges Section for Authenticator
    ###########################################################################
    def get_chall_pref(self, unused_domain: str) -> List[Type[challenges.Challenge]]:
        """Return list of challenge preferences."""
        return [challenges.HTTP01]

    # Entry point in main.py for performing challenges
    def perform(self, achalls: List[achallenges.AnnotatedChallenge]
                ) -> List[challenges.ChallengeResponse]:
        """Perform the configuration related challenge.

        This function currently assumes all challenges will be fulfilled.
        If this turns out not to be the case in the future. Cleanup and
        outstanding challenges will have to be designed better.

        """
        self._chall_out += len(achalls)
        responses: List[Optional[challenges.ChallengeResponse]] = [None] * len(achalls)
        http_doer = http_01.NginxHttp01(self)

        for i, achall in enumerate(achalls):
            # Currently also have chall_doer hold associated index of the
            # challenge. This helps to put all of the responses back together
            # when they are all complete.
            if not isinstance(achall, achallenges.KeyAuthorizationAnnotatedChallenge):
                raise errors.Error("Challenge should be an instance "
                                   "of KeyAuthorizationAnnotatedChallenge")
            http_doer.add_chall(achall, i)

        http_response = http_doer.perform()
        # Must restart in order to activate the challenges.
        # Handled here because we may be able to load up other challenge types
        self.restart()

        # Go through all of the challenges and assign them to the proper place
        # in the responses return value. All responses must be in the same order
        # as the original challenges.
        for i, resp in enumerate(http_response):
            responses[http_doer.indices[i]] = resp

        return [response for response in responses if response]

    # called after challenges are performed
    def cleanup(self, achalls: List[achallenges.AnnotatedChallenge]) -> None:
        """Revert all challenges."""
        self._chall_out -= len(achalls)

        # If all of the challenges have been finished, clean up everything
        if self._chall_out <= 0:
            self.revert_challenge_config()
            self.restart()


def _test_block_from_block(block: List[Any]) -> List[Any]:
    test_block = nginxparser.UnspacedList(block)
    parser.comment_directive(test_block, 0)
    return test_block[:-1]


def _redirect_block_for_domain(domain: str) -> List[Any]:
    updated_domain = domain
    match_symbol = '='
    if util.is_wildcard_domain(domain):
        match_symbol = '~'
        updated_domain = updated_domain.replace('.', r'\.')
        updated_domain = updated_domain.replace('*', '[^.]+')
        updated_domain = '^' + updated_domain + '$'
    redirect_block = [[
        ['\n    ', 'if', ' ', '($host', ' ', match_symbol, ' ', '%s)' % updated_domain, ' '],
        [['\n        ', 'return', ' ', '301', ' ', 'https://$host$request_uri'],
        '\n    ']],
        ['\n']]
    return redirect_block


def nginx_restart(nginx_ctl: str, nginx_conf: str, sleep_duration: int) -> None:
    """Restarts the Nginx Server.

    .. todo:: Nginx restart is fatal if the configuration references
        non-existent SSL cert/key files. Remove references to /etc/letsencrypt
        before restart.

    :param str nginx_ctl: Path to the Nginx binary.
    :param str nginx_conf: Path to the Nginx configuration file.
    :param int sleep_duration: How long to sleep after sending the reload signal.

    """
    try:
        reload_output: str = ""
        with tempfile.TemporaryFile() as out:
            proc = subprocess.run([nginx_ctl, "-c", nginx_conf, "-s", "reload"],
                                  env=util.env_no_snap_for_external_calls(),
                                  stdout=out, stderr=out, check=False)
            out.seek(0)
            reload_output = out.read().decode("utf-8")

        if proc.returncode != 0:
            logger.debug("nginx reload failed:\n%s", reload_output)
            # Maybe Nginx isn't running - try start it
            # Write to temporary files instead of piping because of communication issues on Arch
            # https://github.com/certbot/certbot/issues/4324
            with tempfile.TemporaryFile() as out:
                nginx_proc = subprocess.run([nginx_ctl, "-c", nginx_conf],
                    stdout=out, stderr=out, env=util.env_no_snap_for_external_calls(), check=False)
                if nginx_proc.returncode != 0:
                    out.seek(0)
                    # Enter recovery routine...
                    raise errors.MisconfigurationError(
                        "nginx restart failed:\n%s" % out.read().decode("utf-8"))

    except (OSError, ValueError):
        raise errors.MisconfigurationError("nginx restart failed")
    # Nginx can take a significant duration of time to fully apply a new config, depending
    # on size and contents (https://github.com/certbot/certbot/issues/7422). Lacking a way
    # to reliably identify when this process is complete, we provide the user with control
    # over how long Certbot will sleep after reloading the configuration.
    if sleep_duration > 0:
        time.sleep(sleep_duration)


def _determine_default_server_root() -> str:
    if os.environ.get("CERTBOT_DOCS") == "1":
        default_server_root = (f"{constants.LINUX_SERVER_ROOT} "
                               f"or {constants.FREEBSD_DARWIN_SERVER_ROOT}")
    else:
        default_server_root = constants.CLI_DEFAULTS["server_root"]
    return default_server_root
