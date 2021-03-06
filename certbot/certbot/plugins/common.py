"""Plugin common functions."""
import logging
import re
import shutil
import tempfile
from typing import List

from josepy import util as jose_util
import pkg_resources
import zope.interface

from certbot import achallenges  # pylint: disable=unused-import
from certbot import crypto_util
from certbot import errors
from certbot import interfaces
from certbot import reverter
from certbot._internal import constants
from certbot.compat import filesystem
from certbot.compat import os
from certbot.plugins.storage import PluginStorage

logger = logging.getLogger(__name__)


def option_namespace(name):
    """ArgumentParser options namespace (prefix of all options)."""
    return name + "-"


def dest_namespace(name):
    """ArgumentParser dest namespace (prefix of all destinations)."""
    return name.replace("-", "_") + "_"


private_ips_regex = re.compile(
    r"(^127\.0\.0\.1)|(^10\.)|(^172\.1[6-9]\.)|"
    r"(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)")
hostname_regex = re.compile(
    r"^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*[a-z]+$", re.IGNORECASE)


@zope.interface.implementer(interfaces.IPlugin)
class Plugin:
    """Generic plugin."""
    # provider is not inherited, subclasses must define it on their own
    # @zope.interface.provider(interfaces.IPluginFactory)

    def __init__(self, config, name):
        self.config = config
        self.name = name

    @jose_util.abstractclassmethod
    def add_parser_arguments(cls, add):
        """Add plugin arguments to the CLI argument parser.

        :param callable add: Function that proxies calls to
            `argparse.ArgumentParser.add_argument` prepending options
            with unique plugin name prefix.

        """

    @classmethod
    def inject_parser_options(cls, parser, name):
        """Inject parser options.

        See `~.IPlugin.inject_parser_options` for docs.

        """
        # dummy function, doesn't check if dest.startswith(self.dest_namespace)
        def add(arg_name_no_prefix, *args, **kwargs):
            return parser.add_argument(
                "--{0}{1}".format(option_namespace(name), arg_name_no_prefix),
                *args, **kwargs)
        return cls.add_parser_arguments(add)

    @property
    def option_namespace(self):
        """ArgumentParser options namespace (prefix of all options)."""
        return option_namespace(self.name)

    def option_name(self, name):
        """Option name (include plugin namespace)."""
        return self.option_namespace + name

    @property
    def dest_namespace(self):
        """ArgumentParser dest namespace (prefix of all destinations)."""
        return dest_namespace(self.name)

    def dest(self, var):
        """Find a destination for given variable ``var``."""
        # this should do exactly the same what ArgumentParser(arg),
        # does to "arg" to compute "dest"
        return self.dest_namespace + var.replace("-", "_")

    def conf(self, var):
        """Find a configuration value for variable ``var``."""
        return getattr(self.config, self.dest(var))


class Installer(Plugin):
    """An installer base class with reverter and ssl_dhparam methods defined.

    Installer plugins do not have to inherit from this class.

    """
    def __init__(self, *args, **kwargs):
        super(Installer, self).__init__(*args, **kwargs)
        self.storage = PluginStorage(self.config, self.name)
        self.reverter = reverter.Reverter(self.config)

    def add_to_checkpoint(self, save_files, save_notes, temporary=False):
        """Add files to a checkpoint.

        :param set save_files: set of filepaths to save
        :param str save_notes: notes about changes during the save
        :param bool temporary: True if the files should be added to a
            temporary checkpoint rather than a permanent one. This is
            usually used for changes that will soon be reverted.

        :raises .errors.PluginError: when unable to add to checkpoint

        """
        if temporary:
            checkpoint_func = self.reverter.add_to_temp_checkpoint
        else:
            checkpoint_func = self.reverter.add_to_checkpoint

        try:
            checkpoint_func(save_files, save_notes)
        except errors.ReverterError as err:
            raise errors.PluginError(str(err))

    def finalize_checkpoint(self, title):
        """Timestamp and save changes made through the reverter.

        :param str title: Title describing checkpoint

        :raises .errors.PluginError: when an error occurs

        """
        try:
            self.reverter.finalize_checkpoint(title)
        except errors.ReverterError as err:
            raise errors.PluginError(str(err))

    def recovery_routine(self):
        """Revert all previously modified files.

        Reverts all modified files that have not been saved as a checkpoint

        :raises .errors.PluginError: If unable to recover the configuration

        """
        try:
            self.reverter.recovery_routine()
        except errors.ReverterError as err:
            raise errors.PluginError(str(err))

    def revert_temporary_config(self):
        """Rollback temporary checkpoint.

        :raises .errors.PluginError: when unable to revert config

        """
        try:
            self.reverter.revert_temporary_config()
        except errors.ReverterError as err:
            raise errors.PluginError(str(err))

    def rollback_checkpoints(self, rollback=1):
        """Rollback saved checkpoints.

        :param int rollback: Number of checkpoints to revert

        :raises .errors.PluginError: If there is a problem with the input or
            the function is unable to correctly revert the configuration

        """
        try:
            self.reverter.rollback_checkpoints(rollback)
        except errors.ReverterError as err:
            raise errors.PluginError(str(err))

    @property
    def ssl_dhparams(self):
        """Full absolute path to ssl_dhparams file."""
        return os.path.join(self.config.config_dir, constants.SSL_DHPARAMS_DEST)

    @property
    def updated_ssl_dhparams_digest(self):
        """Full absolute path to digest of updated ssl_dhparams file."""
        return os.path.join(self.config.config_dir, constants.UPDATED_SSL_DHPARAMS_DIGEST)

    def install_ssl_dhparams(self):
        """Copy Certbot's ssl_dhparams file into the system's config dir if required."""
        return install_version_controlled_file(
            self.ssl_dhparams,
            self.updated_ssl_dhparams_digest,
            constants.SSL_DHPARAMS_SRC,
            constants.ALL_SSL_DHPARAMS_HASHES)


class Addr:
    r"""Represents an virtual host address.

    :param str addr: addr part of vhost address
    :param str port: port number or \*, or ""

    """
    def __init__(self, tup, ipv6=False):
        self.tup = tup
        self.ipv6 = ipv6

    @classmethod
    def fromstring(cls, str_addr):
        """Initialize Addr from string."""
        if str_addr.startswith('['):
            # ipv6 addresses starts with [
            endIndex = str_addr.rfind(']')
            host = str_addr[:endIndex + 1]
            port = ''
            if len(str_addr) > endIndex + 2 and str_addr[endIndex + 1] == ':':
                port = str_addr[endIndex + 2:]
            return cls((host, port), ipv6=True)
        else:
            tup = str_addr.partition(':')
            return cls((tup[0], tup[2]))

    def __str__(self):
        if self.tup[1]:
            return "%s:%s" % self.tup
        return self.tup[0]

    def normalized_tuple(self):
        """Normalized representation of addr/port tuple
        """
        if self.ipv6:
            return (self.get_ipv6_exploded(), self.tup[1])
        return self.tup

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            # compare normalized to take different
            # styles of representation into account
            return self.normalized_tuple() == other.normalized_tuple()

        return False

    def __hash__(self):
        return hash(self.tup)

    def get_addr(self):
        """Return addr part of Addr object."""
        return self.tup[0]

    def get_port(self):
        """Return port."""
        return self.tup[1]

    def get_addr_obj(self, port):
        """Return new address object with same addr and new port."""
        return self.__class__((self.tup[0], port), self.ipv6)

    def _normalize_ipv6(self, addr):
        """Return IPv6 address in normalized form, helper function"""
        addr = addr.lstrip("[")
        addr = addr.rstrip("]")
        return self._explode_ipv6(addr)

    def get_ipv6_exploded(self):
        """Return IPv6 in normalized form"""
        if self.ipv6:
            return ":".join(self._normalize_ipv6(self.tup[0]))
        return ""

    def _explode_ipv6(self, addr):
        """Explode IPv6 address for comparison"""
        result = ['0', '0', '0', '0', '0', '0', '0', '0']
        addr_list = addr.split(":")
        if len(addr_list) > len(result):
            # too long, truncate
            addr_list = addr_list[0:len(result)]
        append_to_end = False
        for i, block in enumerate(addr_list):
            if not block:
                # encountered ::, so rest of the blocks should be
                # appended to the end
                append_to_end = True
                continue
            if len(block) > 1:
                # remove leading zeros
                block = block.lstrip("0")
            if not append_to_end:
                result[i] = str(block)
            else:
                # count the location from the end using negative indices
                result[i-len(addr_list)] = str(block)
        return result


class ChallengePerformer:
    """Abstract base for challenge performers.

    :ivar configurator: Authenticator and installer plugin
    :ivar achalls: Annotated challenges
    :vartype achalls: `list` of `.KeyAuthorizationAnnotatedChallenge`
    :ivar indices: Holds the indices of challenges from a larger array
        so the user of the class doesn't have to.
    :vartype indices: `list` of `int`

    """

    def __init__(self, configurator):
        self.configurator = configurator
        self.achalls = []  # type: List[achallenges.KeyAuthorizationAnnotatedChallenge]
        self.indices = []  # type: List[int]

    def add_chall(self, achall, idx=None):
        """Store challenge to be performed when perform() is called.

        :param .KeyAuthorizationAnnotatedChallenge achall: Annotated
            challenge.
        :param int idx: index to challenge in a larger array

        """
        self.achalls.append(achall)
        if idx is not None:
            self.indices.append(idx)

    def perform(self):
        """Perform all added challenges.

        :returns: challenge responses
        :rtype: `list` of `acme.challenges.KeyAuthorizationChallengeResponse`


        """
        raise NotImplementedError()


def install_version_controlled_file(dest_path, digest_path, src_path, all_hashes):
    """Copy a file into an active location (likely the system's config dir) if required.

       :param str dest_path: destination path for version controlled file
       :param str digest_path: path to save a digest of the file in
       :param str src_path: path to version controlled file found in distribution
       :param list all_hashes: hashes of every released version of the file
    """
    current_hash = crypto_util.sha256sum(src_path)

    def _write_current_hash():
        with open(digest_path, "w") as f:
            f.write(current_hash)

    def _install_current_file():
        shutil.copyfile(src_path, dest_path)
        _write_current_hash()

    # Check to make sure options-ssl.conf is installed
    if not os.path.isfile(dest_path):
        _install_current_file()
        return
    # there's already a file there. if it's up to date, do nothing. if it's not but
    # it matches a known file hash, we can update it.
    # otherwise, print a warning once per new version.
    active_file_digest = crypto_util.sha256sum(dest_path)
    if active_file_digest == current_hash: # already up to date
        return
    if active_file_digest in all_hashes: # safe to update
        _install_current_file()
    else:  # has been manually modified, not safe to update
        # did they modify the current version or an old version?
        if os.path.isfile(digest_path):
            with open(digest_path, "r") as f:
                saved_digest = f.read()
            # they modified it after we either installed or told them about this version, so return
            if saved_digest == current_hash:
                return
        # there's a new version but we couldn't update the file, or they deleted the digest.
        # save the current digest so we only print this once, and print a warning
        _write_current_hash()
        logger.warning("%s has been manually modified; updated file "
            "saved to %s. We recommend updating %s for security purposes.",
            dest_path, src_path, dest_path)


# test utils used by certbot_apache/certbot_nginx (hence
# "pragma: no cover") TODO: this might quickly lead to dead code (also
# c.f. #383)

def dir_setup(test_dir, pkg):  # pragma: no cover
    """Setup the directories necessary for the configurator."""
    def expanded_tempdir(prefix):
        """Return the real path of a temp directory with the specified prefix

        Some plugins rely on real paths of symlinks for working correctly. For
        example, certbot-apache uses real paths of configuration files to tell
        a virtual host from another. On systems where TMP itself is a symbolic
        link, (ex: OS X) such plugins will be confused. This function prevents
        such a case.
        """
        return filesystem.realpath(tempfile.mkdtemp(prefix))

    temp_dir = expanded_tempdir("temp")
    config_dir = expanded_tempdir("config")
    work_dir = expanded_tempdir("work")

    filesystem.chmod(temp_dir, constants.CONFIG_DIRS_MODE)
    filesystem.chmod(config_dir, constants.CONFIG_DIRS_MODE)
    filesystem.chmod(work_dir, constants.CONFIG_DIRS_MODE)

    test_configs = pkg_resources.resource_filename(
        pkg, os.path.join("testdata", test_dir))

    shutil.copytree(
        test_configs, os.path.join(temp_dir, test_dir), symlinks=True)

    return temp_dir, config_dir, work_dir
