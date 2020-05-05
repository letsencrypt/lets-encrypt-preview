"""Renewable certificates storage."""
import datetime
import glob
import logging
import re
import shutil
import stat

import configobj
import parsedatetime
import pytz
import six

import certbot
from certbot import crypto_util
from certbot import errors
from certbot import interfaces
from certbot import ocsp
from certbot import util
from certbot._internal import cli
from certbot._internal import constants
from certbot._internal import error_handler
from certbot._internal.plugins import disco as plugins_disco
from certbot.compat import filesystem
from certbot.compat import os
from certbot.plugins import common as plugins_common

logger = logging.getLogger(__name__)

ALL_ITEMS = ("cert", "privkey", "chain", "fullchain", "privkey_fullchain")
README = "README"
CURRENT_VERSION = util.get_strict_version(certbot.__version__)
BASE_PRIVKEY_MODE = 0o600


def renewal_conf_files(config):
    """Build a list of all renewal configuration files.

    :param certbot.interfaces.IConfig config: Configuration object

    :returns: list of renewal configuration files
    :rtype: `list` of `str`

    """
    result = glob.glob(os.path.join(config.renewal_configs_dir, "*.conf"))
    result.sort()
    return result

def renewal_file_for_certname(config, certname):
    """Return /path/to/certname.conf in the renewal conf directory"""
    path = os.path.join(config.renewal_configs_dir, "{0}.conf".format(certname))
    if not os.path.exists(path):
        raise errors.CertStorageError("No certificate found with name {0} (expected "
            "{1}).".format(certname, path))
    return path


def cert_path_for_cert_name(config, cert_name):
    """ If `--cert-name` was specified, but you need a value for `--cert-path`.

    :param `configuration.NamespaceConfig` config: parsed command line arguments
    :param str cert_name: cert name.

    """
    cert_name_implied_conf = renewal_file_for_certname(config, cert_name)
    fullchain_path = configobj.ConfigObj(cert_name_implied_conf)["fullchain"]
    with open(fullchain_path) as f:
        cert_path = (fullchain_path, f.read())
    return cert_path


def config_with_defaults(config=None):
    """Merge supplied config, if provided, on top of builtin defaults."""
    defaults_copy = configobj.ConfigObj(constants.RENEWER_DEFAULTS)
    defaults_copy.merge(config if config is not None else configobj.ConfigObj())
    return defaults_copy


def add_time_interval(base_time, interval, textparser=parsedatetime.Calendar()):
    """Parse the time specified time interval, and add it to the base_time

    The interval can be in the English-language format understood by
    parsedatetime, e.g., '10 days', '3 weeks', '6 months', '9 hours', or
    a sequence of such intervals like '6 months 1 week' or '3 days 12
    hours'. If an integer is found with no associated unit, it is
    interpreted by default as a number of days.

    :param datetime.datetime base_time: The time to be added with the interval.
    :param str interval: The time interval to parse.

    :returns: The base_time plus the interpretation of the time interval.
    :rtype: :class:`datetime.datetime`"""

    if interval.strip().isdigit():
        interval += " days"

    # try to use the same timezone, but fallback to UTC
    tzinfo = base_time.tzinfo or pytz.UTC

    return textparser.parseDT(interval, base_time, tzinfo=tzinfo)[0]


def write_renewal_config(o_filename, n_filename, archive_dir, target, relevant_data):
    """Writes a renewal config file with the specified name and values.

    :param str o_filename: Absolute path to the previous version of config file
    :param str n_filename: Absolute path to the new destination of config file
    :param str archive_dir: Absolute path to the archive directory
    :param dict target: Maps ALL_ITEMS to their symlink paths
    :param dict relevant_data: Renewal configuration options to save

    :returns: Configuration object for the new config file
    :rtype: configobj.ConfigObj

    """
    config = configobj.ConfigObj(o_filename)
    config["version"] = certbot.__version__
    config["archive_dir"] = archive_dir
    for kind in ALL_ITEMS:
        config[kind] = target[kind]

    if "renewalparams" not in config:
        config["renewalparams"] = {}
        config.comments["renewalparams"] = ["",
                                            "Options used in "
                                            "the renewal process"]

    config["renewalparams"].update(relevant_data)

    for k in config["renewalparams"].keys():
        if k not in relevant_data:
            del config["renewalparams"][k]

    if "renew_before_expiry" not in config:
        default_interval = constants.RENEWER_DEFAULTS["renew_before_expiry"]
        config.initial_comment = ["renew_before_expiry = " + default_interval]

    # TODO: add human-readable comments explaining other available
    #       parameters
    logger.debug("Writing new config %s.", n_filename)

    # Ensure that the file exists
    open(n_filename, 'a').close()

    # Copy permissions from the old version of the file, if it exists.
    if os.path.exists(o_filename):
        current_permissions = stat.S_IMODE(os.lstat(o_filename).st_mode)
        filesystem.chmod(n_filename, current_permissions)

    with open(n_filename, "wb") as f:
        config.write(outfile=f)
    return config


def rename_renewal_config(prev_name, new_name, cli_config):
    """Renames cli_config.certname's config to cli_config.new_certname.

    :param .NamespaceConfig cli_config: parsed command line
        arguments
    """
    prev_filename = renewal_filename_for_lineagename(cli_config, prev_name)
    new_filename = renewal_filename_for_lineagename(cli_config, new_name)
    if os.path.exists(new_filename):
        raise errors.ConfigurationError("The new certificate name "
            "is already in use.")
    try:
        filesystem.replace(prev_filename, new_filename)
    except OSError:
        raise errors.ConfigurationError("Please specify a valid filename "
            "for the new certificate name.")


def update_configuration(lineagename, archive_dir, target, cli_config):
    """Modifies lineagename's config to contain the specified values.

    :param str lineagename: Name of the lineage being modified
    :param str archive_dir: Absolute path to the archive directory
    :param dict target: Maps ALL_ITEMS to their symlink paths
    :param .NamespaceConfig cli_config: parsed command line
        arguments

    :returns: Configuration object for the updated config file
    :rtype: configobj.ConfigObj

    """
    config_filename = renewal_filename_for_lineagename(cli_config, lineagename)
    temp_filename = config_filename + ".new"

    # If an existing tempfile exists, delete it
    if os.path.exists(temp_filename):
        os.unlink(temp_filename)

    # Save only the config items that are relevant to renewal
    values = relevant_values(vars(cli_config.namespace))
    write_renewal_config(config_filename, temp_filename, archive_dir, target, values)
    filesystem.replace(temp_filename, config_filename)

    return configobj.ConfigObj(config_filename)


def get_link_target(link):
    """Get an absolute path to the target of link.

    :param str link: Path to a symbolic link

    :returns: Absolute path to the target of link
    :rtype: str

    :raises .CertStorageError: If link does not exists.

    """
    try:
        target = os.readlink(link)
    except OSError:
        raise errors.CertStorageError(
            "Expected {0} to be a symlink".format(link))

    if not os.path.isabs(target):
        target = os.path.join(os.path.dirname(link), target)
    return os.path.abspath(target)

def _write_live_readme_to(readme_path, is_base_dir=False):
    prefix = ""
    if is_base_dir:
        prefix = "[cert name]/"
    with open(readme_path, "w") as f:
        logger.debug("Writing README to %s.", readme_path)
        f.write("This directory contains your keys and certificates.\n\n"
                "`{prefix}privkey.pem`  : the private key for your certificate.\n"
                "`{prefix}fullchain.pem`: the certificate file used in most server software.\n"
                "`{prefix}chain.pem`    : used for OCSP stapling in Nginx >=1.3.7.\n"
                "`{prefix}cert.pem`     : will break many server configurations, and "
                                    "should not be used\n"
                "                 without reading further documentation (see link below).\n\n"
                "WARNING: DO NOT MOVE OR RENAME THESE FILES!\n"
                "         Certbot expects these files to remain in this location in order\n"
                "         to function properly!\n\n"
                "We recommend not moving these files. For more information, see the Certbot\n"
                "User Guide at https://certbot.eff.org/docs/using.html#where-are-my-"
                                    "certificates.\n".format(prefix=prefix))


def _relevant(namespaces, option):
    """
    Is this option one that could be restored for future renewal purposes?

    :param namespaces: plugin namespaces for configuration options
    :type namespaces: `list` of `str`
    :param str option: the name of the option

    :rtype: bool
    """
    from certbot._internal import renewal

    return (option in renewal.CONFIG_ITEMS or
            any(option.startswith(namespace) for namespace in namespaces))


def relevant_values(all_values):
    """Return a new dict containing only items relevant for renewal.

    :param dict all_values: The original values.

    :returns: A new dictionary containing items that can be used in renewal.
    :rtype dict:

    """
    plugins = plugins_disco.PluginsRegistry.find_all()
    namespaces = [plugins_common.dest_namespace(plugin) for plugin in plugins]

    rv = dict(
        (option, value)
        for option, value in six.iteritems(all_values)
        if _relevant(namespaces, option) and cli.option_was_set(option, value))
    # We always save the server value to help with forward compatibility
    # and behavioral consistency when versions of Certbot with different
    # server defaults are used.
    rv["server"] = all_values["server"]
    return rv

def lineagename_for_filename(config_filename):
    """Returns the lineagename for a configuration filename.
    """
    if not config_filename.endswith(".conf"):
        raise errors.CertStorageError(
            "renewal config file name must end in .conf")
    return os.path.basename(config_filename[:-len(".conf")])

def renewal_filename_for_lineagename(config, lineagename):
    """Returns the lineagename for a configuration filename.
    """
    return os.path.join(config.renewal_configs_dir, lineagename) + ".conf"

def _relpath_from_file(archive_dir, from_file):
    """Path to a directory from a file"""
    return os.path.relpath(archive_dir, os.path.dirname(from_file))

def full_archive_path(config_obj, cli_config, lineagename):
    """Returns the full archive path for a lineagename

    Uses cli_config to determine archive path if not available from config_obj.

    :param configobj.ConfigObj config_obj: Renewal conf file contents (can be None)
    :param configuration.NamespaceConfig cli_config: Main config file
    :param str lineagename: Certificate name
    """
    if config_obj and "archive_dir" in config_obj:
        return config_obj["archive_dir"]
    return os.path.join(cli_config.default_archive_dir, lineagename)

def _full_live_path(cli_config, lineagename):
    """Returns the full default live path for a lineagename"""
    return os.path.join(cli_config.live_dir, lineagename)

def delete_files(config, certname):
    """Delete all files related to the certificate.

    If some files are not found, ignore them and continue.
    """
    renewal_filename = renewal_file_for_certname(config, certname)
    # file exists
    full_default_archive_dir = full_archive_path(None, config, certname)
    full_default_live_dir = _full_live_path(config, certname)
    try:
        renewal_config = configobj.ConfigObj(renewal_filename)
    except configobj.ConfigObjError:
        # config is corrupted
        logger.warning("Could not parse %s. You may wish to manually "
            "delete the contents of %s and %s.", renewal_filename,
            full_default_live_dir, full_default_archive_dir)
        raise errors.CertStorageError(
            "error parsing {0}".format(renewal_filename))
    finally:
        # we couldn't read it, but let's at least delete it
        # if this was going to fail, it already would have.
        os.remove(renewal_filename)
        logger.debug("Removed %s", renewal_filename)

    # cert files and (hopefully) live directory
    # it's not guaranteed that the files are in our default storage
    # structure. so, first delete the cert files.
    directory_names = set()
    for kind in ALL_ITEMS:
        link = renewal_config.get(kind)
        try:
            os.remove(link)
            logger.debug("Removed %s", link)
        except OSError:
            logger.debug("Unable to delete %s", link)
        directory = os.path.dirname(link)
        directory_names.add(directory)

    # if all four were in the same directory, and the only thing left
    # is the README file (or nothing), delete that directory.
    # this will be wrong in very few but some cases.
    if len(directory_names) == 1:
        # delete the README file
        directory = directory_names.pop()
        readme_path = os.path.join(directory, README)
        try:
            os.remove(readme_path)
            logger.debug("Removed %s", readme_path)
        except OSError:
            logger.debug("Unable to delete %s", readme_path)
        # if it's now empty, delete the directory
        try:
            os.rmdir(directory) # only removes empty directories
            logger.debug("Removed %s", directory)
        except OSError:
            logger.debug("Unable to remove %s; may not be empty.", directory)

    # archive directory
    try:
        archive_path = full_archive_path(renewal_config, config, certname)
        shutil.rmtree(archive_path)
        logger.debug("Removed %s", archive_path)
    except OSError:
        logger.debug("Unable to remove %s", archive_path)


class RenewableCert(interfaces.RenewableCert):
    """Renewable certificate.

    Represents a lineage of certificates that is under the management of
    Certbot, indicated by the existence of an associated renewal
    configuration file.

    Note that the notion of "current version" for a lineage is
    maintained on disk in the structure of symbolic links, and is not
    explicitly stored in any instance variable in this object. The
    RenewableCert object is able to determine information about the
    current (or other) version by accessing data on disk, but does not
    inherently know any of this information except by examining the
    symbolic links as needed. The instance variables mentioned below
    point to symlinks that reflect the notion of "current version" of
    each managed object, and it is these paths that should be used when
    configuring servers to use the certificate managed in a lineage.
    These paths are normally within the "live" directory, and their
    symlink targets -- the actual cert files -- are normally found
    within the "archive" directory.

    :ivar str cert: The path to the symlink representing the current
        version of the certificate managed by this lineage.
    :ivar str privkey: The path to the symlink representing the current
        version of the private key managed by this lineage.
    :ivar str chain: The path to the symlink representing the current version
        of the chain managed by this lineage.
    :ivar str fullchain: The path to the symlink representing the
        current version of the fullchain (combined chain and cert)
        managed by this lineage.
    :ivar str privkey_fullchain: The path to the symlink representing the
        current version of the privkey_fullchain file (combined private key,
        chain, and cert) managed by this lineage.
    :ivar configobj.ConfigObj configuration: The renewal configuration
        options associated with this lineage, obtained from parsing the
        renewal configuration file and/or systemwide defaults.

    """
    def __init__(self, config_filename, cli_config, update_symlinks=False):
        """Instantiate a RenewableCert object from an existing lineage.

        :param str config_filename: the path to the renewal config file
            that defines this lineage.
        :param .NamespaceConfig: parsed command line arguments

        :raises .CertStorageError: if the configuration file's name didn't end
            in ".conf", or the file is missing or broken.

        """
        self.cli_config = cli_config
        self._lineagename = lineagename_for_filename(config_filename)

        # self.configuration should be used to read parameters that
        # may have been chosen based on default values from the
        # systemwide renewal configuration; self.configfile should be
        # used to make and save changes.
        try:
            self.configfile = configobj.ConfigObj(config_filename)
        except configobj.ConfigObjError:
            raise errors.CertStorageError(
                "error parsing {0}".format(config_filename))
        # TODO: Do we actually use anything from defaults and do we want to
        #       read further defaults from the systemwide renewal configuration
        #       file at this stage?
        self.configuration = config_with_defaults(self.configfile)

        if "version" in self.configuration:
            self.conf_version = util.get_strict_version(self.configuration["version"])
            logger.debug("Configuration file has version %s.", self.conf_version)
        else:
            logger.warning("Configuration file is missing a version number.")
            self.conf_version = util.get_strict_version("0.0.dev0")

        if self.conf_version < CURRENT_VERSION:
            self._upgrade_configuration()

        if self.conf_version > CURRENT_VERSION:
            logger.info(
                "Attempting to parse the version %s renewal configuration "
                "file found at %s with version %s of Certbot. This might not "
                "work.", self.configuration["version"], config_filename,
                certbot.__version__)

        for kind in ALL_ITEMS:
            if not kind in self.configuration:
                raise errors.CertStorageError(
                    "renewal config file {0} is missing required "
                    "file reference {1}".format(self.configfile, kind))

        self.cert = self.configuration["cert"]
        self.privkey = self.configuration["privkey"]
        self.chain = self.configuration["chain"]
        self.fullchain = self.configuration["fullchain"]
        self.privkey_fullchain = self.configuration["privkey_fullchain"]
        self.live_dir = os.path.dirname(self.cert)

        self._fix_symlinks()
        if update_symlinks:
            self._update_symlinks()
        self._check_symlinks()

    @property
    def key_path(self):
        """Duck type for self.privkey"""
        return self.privkey

    @property
    def cert_path(self):
        """Duck type for self.cert"""
        return self.cert

    @property
    def chain_path(self):
        """Duck type for self.chain"""
        return self.chain

    @property
    def fullchain_path(self):
        """Duck type for self.fullchain"""
        return self.fullchain

    @property
    def privkey_fullchain_path(self):
        """Duck type for self.privkey_fullchain"""
        return self.privkey_fullchain

    @property
    def lineagename(self):
        """Name given to the certificate lineage.

        :rtype: str

        """
        return self._lineagename

    @property
    def target_expiry(self):
        """The current target certificate's expiration datetime

        :returns: Expiration datetime of the current target certificate
        :rtype: :class:`datetime.datetime`
        """
        return crypto_util.notAfter(self.current_target("cert"))

    @property
    def archive_dir(self):
        """Returns the default or specified archive directory"""
        return full_archive_path(self.configuration,
            self.cli_config, self.lineagename)

    def relative_archive_dir(self, from_file):
        """Returns the default or specified archive directory as a relative path

        Used for creating symbolic links.
        """
        return _relpath_from_file(self.archive_dir, from_file)

    @property
    def is_test_cert(self):
        """Returns true if this is a test cert from a staging server."""
        server = self.configuration["renewalparams"].get("server", None)
        if server:
            return util.is_staging(server)
        return False

    def _upgrade_configuration(self):
        logger.info("Upgrading config from %s to %s",
            self.conf_version, CURRENT_VERSION)

        # Add the privkey_fullchain lineage item on upgrade
        if "privkey_fullchain" not in self.configuration and (
            self.conf_version < constants.PKFC_VERSION
        ):
            # create privkey_fullchain in the archive_dir
            pkfc_real = os.path.join(self.archive_dir, "privkey_" +
                os.path.basename(filesystem.realpath(self.configuration["fullchain"])))
            logger.debug("Writing private key and full chain to %s.", pkfc_real)
            with util.safe_open(pkfc_real, "wb", chmod=BASE_PRIVKEY_MODE) as pkfc:
                with open(self.configuration["privkey"], "rb") as pk:
                    pkfc.write(pk.read())
                with open(self.configuration["fullchain"], "rb") as fc:
                    pkfc.write(fc.read())
            # create the symlink in the same place as the fullchain one
            linkname = os.path.join(
                os.path.dirname(self.configuration["fullchain"]),
                "privkey_fullchain.pem")
            os.symlink(_relpath_from_file(pkfc_real, linkname), linkname)
            self.configuration["privkey_fullchain"] = linkname

        # Update renewal config file
        self.conf_version = CURRENT_VERSION
        symlinks = dict((kind, self.configuration[kind]) for kind in ALL_ITEMS)
        self.configfile = update_configuration(
            self.lineagename, self.archive_dir, symlinks, self.cli_config)

    def _check_symlinks(self):
        """Raises an exception if a symlink doesn't exist"""
        for kind in ALL_ITEMS:
            link = getattr(self, kind)
            if not os.path.islink(link):
                raise errors.CertStorageError(
                    "expected {0} to be a symlink".format(link))
            target = get_link_target(link)
            if not os.path.exists(target):
                raise errors.CertStorageError("target {0} of symlink {1} does "
                                              "not exist".format(target, link))

    def _update_symlinks(self):
        """Updates symlinks to use archive_dir"""
        for kind in ALL_ITEMS:
            link = getattr(self, kind)
            previous_link = get_link_target(link)
            new_link = os.path.join(self.relative_archive_dir(link),
                os.path.basename(previous_link))

            os.unlink(link)
            os.symlink(new_link, link)

    def _consistent(self):
        """Are the files associated with this lineage self-consistent?

        :returns: Whether the files stored in connection with this
            lineage appear to be correct and consistent with one
            another.
        :rtype: bool

        """
        # Each element must be referenced with an absolute path
        for x in (self.cert, self.privkey, self.chain, self.fullchain, self.privkey_fullchain):
            if not os.path.isabs(x):
                logger.debug("Element %s is not referenced with an "
                             "absolute path.", x)
                return False

        # Each element must exist and be a symbolic link
        for x in (self.cert, self.privkey, self.chain, self.fullchain, self.privkey_fullchain):
            if not os.path.islink(x):
                logger.debug("Element %s is not a symbolic link.", x)
                return False
        for kind in ALL_ITEMS:
            link = getattr(self, kind)
            target = get_link_target(link)

            # Each element's link must point within the cert lineage's
            # directory within the official archive directory
            if not os.path.samefile(os.path.dirname(target), self.archive_dir):
                logger.debug("Element's link does not point within the "
                             "cert lineage's directory within the "
                             "official archive directory. Link: %s, "
                             "target directory: %s, "
                             "archive directory: %s. If you've specified "
                             "the archive directory in the renewal configuration "
                             "file, you may need to update links by running "
                             "certbot update_symlinks.",
                             link, os.path.dirname(target), self.archive_dir)
                return False

            # The link must point to a file that exists
            if not os.path.exists(target):
                logger.debug("Link %s points to file %s that does not exist.",
                             link, target)
                return False

            # The link must point to a file that follows the archive
            # naming convention
            pattern = re.compile(r"^{0}([0-9]+)\.pem$".format(kind))
            if not pattern.match(os.path.basename(target)):
                logger.debug("%s does not follow the archive naming "
                             "convention.", target)
                return False

            # It is NOT required that the link's target be a regular
            # file (it may itself be a symlink). But we should probably
            # do a recursive check that ultimately the target does
            # exist?
        # XXX: Additional possible consistency checks (e.g.
        #      cryptographic validation of the chain being a chain,
        #      the chain matching the cert, and the cert matching
        #      the subject key)
        # XXX: All five of the targets are in the same directory
        #      (This check is redundant with the check that they
        #      are all in the desired directory!)
        #      len(set(os.path.basename(self.current_target(x)
        #      for x in ALL_ITEMS))) == 1
        return True

    def _fix(self):
        """Attempt to fix defects or inconsistencies in this lineage.

        .. todo:: Currently unimplemented.

        """
        # TODO: Figure out what kinds of fixes are possible.  For
        #       example, checking if there is a valid version that
        #       we can update the symlinks to.  (Maybe involve
        #       parsing keys and certs to see if they exist and
        #       if a key corresponds to the subject key of a cert?)

    # TODO: In general, the symlink-reading functions below are not
    #       cautious enough about the possibility that links or their
    #       targets may not exist.  (This shouldn't happen, but might
    #       happen as a result of random tampering by a sysadmin, or
    #       filesystem errors, or crashes.)

    def _previous_symlinks(self):
        """Returns the kind and path of all symlinks used in recovery.

        :returns: list of (kind, symlink) tuples
        :rtype: list

        """
        previous_symlinks = []
        for kind in ALL_ITEMS:
            link_dir = os.path.dirname(getattr(self, kind))
            link_base = "previous_{0}.pem".format(kind)
            previous_symlinks.append((kind, os.path.join(link_dir, link_base)))

        return previous_symlinks

    def _fix_symlinks(self):
        """Fixes symlinks in the event of an incomplete version update.

        If there is no problem with the current symlinks, this function
        has no effect.

        """
        previous_symlinks = self._previous_symlinks()
        if all(os.path.exists(link[1]) for link in previous_symlinks):
            for kind, previous_link in previous_symlinks:
                current_link = getattr(self, kind)
                if os.path.lexists(current_link):
                    os.unlink(current_link)
                os.symlink(os.readlink(previous_link), current_link)

        for _, link in previous_symlinks:
            if os.path.exists(link):
                os.unlink(link)

    def current_target(self, kind):
        """Returns full path to which the specified item currently points.

        :param str kind: the lineage member item ("cert", "privkey",
            "chain", "fullchain", or "privkey_fullchain")

        :returns: The path to the current version of the specified
            member.
        :rtype: str or None

        """
        if kind not in ALL_ITEMS:
            raise errors.CertStorageError("unknown kind of item")
        link = getattr(self, kind)
        if not os.path.exists(link):
            logger.debug("Expected symlink %s for %s does not exist.",
                         link, kind)
            return None
        return get_link_target(link)

    def current_version(self, kind):
        """Returns numerical version of the specified item.

        For example, if kind is "chain" and the current chain link
        points to a file named "chain7.pem", returns the integer 7.

        :param str kind: the lineage member item ("cert", "privkey",
            "chain", "fullchain", or "privkey_fullchain")

        :returns: the current version of the specified member.
        :rtype: int

        """
        if kind not in ALL_ITEMS:
            raise errors.CertStorageError("unknown kind of item")
        pattern = re.compile(r"^{0}([0-9]+)\.pem$".format(kind))
        target = self.current_target(kind)
        if target is None or not os.path.exists(target):
            logger.debug("Current-version target for %s "
                         "does not exist at %s.", kind, target)
            target = ""
        matches = pattern.match(os.path.basename(target))
        if matches:
            return int(matches.groups()[0])
        logger.debug("No matches for target %s.", kind)
        return None

    def version(self, kind, version):
        """The filename that corresponds to the specified version and kind.

        .. warning:: The specified version may not exist in this
           lineage. There is no guarantee that the file path returned
           by this method actually exists.

        :param str kind: the lineage member item ("cert", "privkey",
            "chain", "fullchain", or "privkey_fullchain")
        :param int version: the desired version

        :returns: The path to the specified version of the specified member.
        :rtype: str

        """
        if kind not in ALL_ITEMS:
            raise errors.CertStorageError("unknown kind of item")
        where = os.path.dirname(self.current_target(kind))
        return os.path.join(where, "{0}{1}.pem".format(kind, version))

    def available_versions(self, kind):
        """Which alternative versions of the specified kind of item exist?

        The archive directory where the current version is stored is
        consulted to obtain the list of alternatives.

        :param str kind: the lineage member item ( ``cert``, ``privkey``,
            ``chain``, ``fullchain``, or ``privkey_fullchain``)

        :returns: all of the version numbers that currently exist
        :rtype: `list` of `int`

        """
        if kind not in ALL_ITEMS:
            raise errors.CertStorageError("unknown kind of item")
        where = os.path.dirname(self.current_target(kind))
        files = os.listdir(where)
        pattern = re.compile(r"^{0}([0-9]+)\.pem$".format(kind))
        matches = [pattern.match(f) for f in files]
        return sorted([int(m.groups()[0]) for m in matches if m])

    def newest_available_version(self, kind):
        """Newest available version of the specified kind of item?

        :param str kind: the lineage member item ( ``cert``, ``privkey``,
            ``chain``, ``fullchain``, or ``privkey_fullchain``)

        :returns: the newest available version of this member
        :rtype: int

        """
        return max(self.available_versions(kind))

    def latest_common_version(self):
        """Newest version for which all items are available?

        :returns: the newest available version for which all members
            ( ``cert``, ``privkey``, ``chain``, ``fullchain``,
            or ``privkey_fullchain``) exist
        :rtype: int

        """
        # TODO: this can raise CertStorageError if there is no version overlap
        #       (it should probably return None instead)
        # TODO: this can raise a spurious AttributeError if the current
        #       link for any kind is missing (it should probably return None)
        versions = [self.available_versions(x) for x in ALL_ITEMS]
        return max(n for n in versions[0] if all(n in v for v in versions[1:]))

    def next_free_version(self):
        """Smallest version newer than all full or partial versions?

        :returns: the smallest version number that is larger than any
            version of any item currently stored in this lineage
        :rtype: int

        """
        # TODO: consider locking/mutual exclusion between updating processes
        # This isn't self.latest_common_version() + 1 because we don't want
        # collide with a version that might exist for one file type but not
        # for the others.
        return max(self.newest_available_version(x) for x in ALL_ITEMS) + 1

    def ensure_deployed(self):
        """Make sure we've deployed the latest version.

        :returns: False if a change was needed, True otherwise
        :rtype: bool

        May need to recover from rare interrupted / crashed states."""

        if self.has_pending_deployment():
            logger.warning("Found a new cert /archive/ that was not linked to in /live/; "
                        "fixing...")
            self.update_all_links_to(self.latest_common_version())
            return False
        return True


    def has_pending_deployment(self):
        """Is there a later version of all of the managed items?

        :returns: ``True`` if there is a complete version of this
            lineage with a larger version number than the current
            version, and ``False`` otherwise
        :rtype: bool

        """
        # TODO: consider whether to assume consistency or treat
        #       inconsistent/consistent versions differently
        smallest_current = min(self.current_version(x) for x in ALL_ITEMS)
        return smallest_current < self.latest_common_version()

    def _update_link_to(self, kind, version):
        """Make the specified item point at the specified version.

        (Note that this method doesn't verify that the specified version
        exists.)

        :param str kind: the lineage member item ("cert", "privkey",
            "chain", "fullchain" or "privkey_fullchain")
        :param int version: the desired version

        """
        if kind not in ALL_ITEMS:
            raise errors.CertStorageError("unknown kind of item")
        link = getattr(self, kind)
        filename = "{0}{1}.pem".format(kind, version)
        # Relative rather than absolute target directory
        target_directory = os.path.dirname(os.readlink(link))
        # TODO: it could be safer to make the link first under a temporary
        #       filename, then unlink the old link, then rename the new link
        #       to the old link; this ensures that this process is able to
        #       create symlinks.
        # TODO: we might also want to check consistency of related links
        #       for the other corresponding items
        os.unlink(link)
        os.symlink(os.path.join(target_directory, filename), link)

    def update_all_links_to(self, version):
        """Change all member objects to point to the specified version.

        :param int version: the desired version

        """
        with error_handler.ErrorHandler(self._fix_symlinks):
            previous_links = self._previous_symlinks()
            for kind, link in previous_links:
                os.symlink(self.current_target(kind), link)

            for kind in ALL_ITEMS:
                self._update_link_to(kind, version)

            for _, link in previous_links:
                os.unlink(link)

    def names(self):
        """What are the subject names of this certificate?

        :returns: the subject names
        :rtype: `list` of `str`
        :raises .CertStorageError: if could not find cert file.

        """
        target = self.current_target("cert")
        if target is None:
            raise errors.CertStorageError("could not find cert file")
        with open(target) as f:
            return crypto_util.get_names_from_cert(f.read())

    def ocsp_revoked(self, version):
        """Is the specified cert version revoked according to OCSP?

        Also returns True if the cert version is declared as revoked
        according to OCSP. If OCSP status could not be determined, False
        is returned.

        :param int version: the desired version number

        :returns: True if the certificate is revoked, otherwise, False
        :rtype: bool

        """
        cert_path = self.version("cert", version)
        chain_path = self.version("chain", version)
        # While the RevocationChecker should return False if it failed to
        # determine the OCSP status, let's ensure we don't crash Certbot by
        # catching all exceptions here.
        try:
            return ocsp.RevocationChecker().ocsp_revoked_by_paths(cert_path,
                                                                  chain_path)
        except Exception as e:  # pylint: disable=broad-except
            logger.warning(
                "An error occurred determining the OCSP status of %s.",
                cert_path)
            logger.debug(str(e))
            return False

    def autorenewal_is_enabled(self):
        """Is automatic renewal enabled for this cert?

        If autorenew is not specified, defaults to True.

        :returns: True if automatic renewal is enabled
        :rtype: bool

        """
        return ("autorenew" not in self.configuration["renewalparams"] or
                self.configuration["renewalparams"].as_bool("autorenew"))

    def should_autorenew(self):
        """Should we now try to autorenew the most recent cert version?

        This is a policy question and does not only depend on whether
        the cert is expired. (This considers whether autorenewal is
        enabled, whether the cert is revoked, and whether the time
        interval for autorenewal has been reached.)

        Note that this examines the numerically most recent cert version,
        not the currently deployed version.

        :returns: whether an attempt should now be made to autorenew the
            most current cert version in this lineage
        :rtype: bool

        """
        if self.autorenewal_is_enabled():
            # Consider whether to attempt to autorenew this cert now

            # Renewals on the basis of revocation
            if self.ocsp_revoked(self.latest_common_version()):
                logger.debug("Should renew, certificate is revoked.")
                return True

            # Renews some period before expiry time
            default_interval = constants.RENEWER_DEFAULTS["renew_before_expiry"]
            interval = self.configuration.get("renew_before_expiry", default_interval)
            expiry = crypto_util.notAfter(self.version(
                "cert", self.latest_common_version()))
            now = pytz.UTC.fromutc(datetime.datetime.utcnow())
            if expiry < add_time_interval(now, interval):
                logger.debug("Should renew, less than %s before certificate "
                             "expiry %s.", interval,
                             expiry.strftime("%Y-%m-%d %H:%M:%S %Z"))
                return True
        return False

    @classmethod
    def new_lineage(cls, lineagename, cert, privkey, chain, cli_config):
        """Create a new certificate lineage.

        Attempts to create a certificate lineage -- enrolled for
        potential future renewal -- with the (suggested) lineage name
        lineagename, and the associated cert, privkey, and chain (the
        associated fullchain will be created automatically). Optional
        configurator and renewalparams record the configuration that was
        originally used to obtain this cert, so that it can be reused
        later during automated renewal.

        Returns a new RenewableCert object referring to the created
        lineage. (The actual lineage name, as well as all the relevant
        file paths, will be available within this object.)

        :param str lineagename: the suggested name for this lineage
            (normally the current cert's first subject DNS name)
        :param str cert: the initial certificate version in PEM format
        :param str privkey: the private key in PEM format
        :param str chain: the certificate chain in PEM format
        :param .NamespaceConfig cli_config: parsed command line
            arguments

        :returns: the newly-created RenewalCert object
        :rtype: :class:`storage.renewableCert`

        """

        # Examine the configuration and find the new lineage's name
        for i in (cli_config.renewal_configs_dir, cli_config.default_archive_dir,
                  cli_config.live_dir):
            if not os.path.exists(i):
                filesystem.makedirs(i, 0o700)
                logger.debug("Creating directory %s.", i)
        config_file, config_filename = util.unique_lineage_name(
            cli_config.renewal_configs_dir, lineagename)
        base_readme_path = os.path.join(cli_config.live_dir, README)
        if not os.path.exists(base_readme_path):
            _write_live_readme_to(base_readme_path, is_base_dir=True)

        # Determine where on disk everything will go
        # lineagename will now potentially be modified based on which
        # renewal configuration file could actually be created
        lineagename = lineagename_for_filename(config_filename)
        archive = full_archive_path(None, cli_config, lineagename)
        live_dir = _full_live_path(cli_config, lineagename)
        if os.path.exists(archive):
            config_file.close()
            raise errors.CertStorageError(
                "archive directory exists for " + lineagename)
        if os.path.exists(live_dir):
            config_file.close()
            raise errors.CertStorageError(
                "live directory exists for " + lineagename)
        filesystem.mkdir(archive)
        filesystem.mkdir(live_dir)
        logger.debug("Archive directory %s and live "
                     "directory %s created.", archive, live_dir)

        # Put the data into the appropriate files on disk
        target = {kind: os.path.join(live_dir, kind + ".pem") for kind in ALL_ITEMS}
        archive_target = {kind: os.path.join(archive, kind + "1.pem") for kind in ALL_ITEMS}
        for kind in ALL_ITEMS:
            os.symlink(_relpath_from_file(archive_target[kind], target[kind]), target[kind])
        with open(target["cert"], "wb") as f:
            logger.debug("Writing certificate to %s.", target["cert"])
            f.write(cert)
        with util.safe_open(archive_target["privkey"], "wb", chmod=BASE_PRIVKEY_MODE) as f:
            logger.debug("Writing private key to %s.", target["privkey"])
            f.write(privkey)
            # XXX: Let's make sure to get the file permissions right here
        with open(target["chain"], "wb") as f:
            logger.debug("Writing chain to %s.", target["chain"])
            f.write(chain)
        with open(target["fullchain"], "wb") as f:
            # assumes that OpenSSL.crypto.dump_certificate includes
            # ending newline character
            logger.debug("Writing full chain to %s.", target["fullchain"])
            f.write(cert + chain)
        with util.safe_open(archive_target["privkey_fullchain"], "wb",
                            chmod=BASE_PRIVKEY_MODE) as f:
            logger.debug("Writing private key and full chain to %s.",
                         target["privkey_fullchain"])
            f.write(privkey + cert + chain)

        # Write a README file to the live directory
        readme_path = os.path.join(live_dir, README)
        _write_live_readme_to(readme_path)

        # Document what we've done in a new renewal config file
        config_file.close()

        # Save only the config items that are relevant to renewal
        values = relevant_values(vars(cli_config.namespace))

        new_config = write_renewal_config(config_filename, config_filename, archive,
            target, values)
        return cls(new_config.filename, cli_config)

    def save_successor(self, prior_version, new_cert,
                       new_privkey, new_chain, cli_config):
        """Save new cert and chain as a successor of a prior version.

        Returns the new version number that was created.

        .. note:: this function does NOT update links to deploy this
                  version

        :param int prior_version: the old version to which this version
            is regarded as a successor (used to choose a privkey, if the
            key has not changed, but otherwise this information is not
            permanently recorded anywhere)
        :param bytes new_cert: the new certificate, in PEM format
        :param bytes new_privkey: the new private key, in PEM format,
            or ``None``, if the private key has not changed
        :param bytes new_chain: the new chain, in PEM format
        :param .NamespaceConfig cli_config: parsed command line
            arguments

        :returns: the new version number that was created
        :rtype: int

        """
        # XXX: assumes official archive location rather than examining links
        # XXX: consider using os.open for availability of os.O_EXCL
        # XXX: ensure file permissions are correct; also create directories
        #      if needed (ensuring their permissions are correct)
        # Figure out what the new version is and hence where to save things

        self.cli_config = cli_config
        target_version = self.next_free_version()
        target = {kind: os.path.join(self.archive_dir, "{0}{1}.pem".format(kind, target_version))
                  for kind in ALL_ITEMS}

        old_privkey = os.path.join(
            self.archive_dir, "privkey{0}.pem".format(prior_version))

        # Distinguish the cases where the privkey has changed and where it
        # has not changed (in the latter case, making an appropriate symlink
        # to an earlier privkey version)
        if new_privkey is None:
            # The behavior below keeps the prior key by creating a new
            # symlink to the old key or the target of the old key symlink.
            if os.path.islink(old_privkey):
                old_privkey = os.readlink(old_privkey)
            else:
                old_privkey = "privkey{0}.pem".format(prior_version)
            logger.debug("Writing symlink to old private key, %s.", old_privkey)
            os.symlink(old_privkey, target["privkey"])
        else:
            with util.safe_open(target["privkey"], "wb", chmod=BASE_PRIVKEY_MODE) as f:
                logger.debug("Writing new private key to %s.", target["privkey"])
                f.write(new_privkey)
            # Preserve gid and (mode & MASK_FOR_PRIVATE_KEY_PERMISSIONS)
            # from previous privkey in this lineage.
            mode = filesystem.compute_private_key_mode(old_privkey, BASE_PRIVKEY_MODE)
            filesystem.copy_ownership_and_apply_mode(
                old_privkey, target["privkey"], mode, copy_user=False, copy_group=True)

        # Save everything else
        with open(target["cert"], "wb") as f:
            logger.debug("Writing certificate to %s.", target["cert"])
            f.write(new_cert)
        with open(target["chain"], "wb") as f:
            logger.debug("Writing chain to %s.", target["chain"])
            f.write(new_chain)
        with open(target["fullchain"], "wb") as f:
            logger.debug("Writing full chain to %s.", target["fullchain"])
            f.write(new_cert + new_chain)
        with util.safe_open(target["privkey_fullchain"], "wb", chmod=BASE_PRIVKEY_MODE) as f:
            logger.debug("Writing private key and full chain to %s.", target["privkey_fullchain"])
            with open(target["privkey"], "rb") as pk:
                f.write(pk.read())
            f.write(new_cert + new_chain)
        # Preserve gid and (mode & MASK_FOR_PRIVATE_KEY_PERMISSIONS)
        # from previous privkey_fullchain in this lineage.
        old_pkfc = os.path.join(self.archive_dir,
                "privkey_fullchain{0}.pem".format(prior_version))
        mode = filesystem.compute_private_key_mode(old_pkfc, BASE_PRIVKEY_MODE)
        filesystem.copy_ownership_and_apply_mode(
            old_pkfc, target["privkey_fullchain"], mode, copy_user=False, copy_group=True)

        symlinks = dict((kind, self.configuration[kind]) for kind in ALL_ITEMS)
        # Update renewal config file
        self.configfile = update_configuration(
            self.lineagename, self.archive_dir, symlinks, cli_config)
        self.configuration = config_with_defaults(self.configfile)

        return target_version
