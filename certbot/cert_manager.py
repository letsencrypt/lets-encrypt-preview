"""Tools for managing certificates."""
import datetime
import logging
import os
import pytz
import re
import traceback
import zope.component

from certbot import crypto_util
from certbot import errors
from certbot import interfaces
from certbot import ocsp
from certbot import storage
from certbot import util

from certbot.display import util as display_util

logger = logging.getLogger(__name__)

###################
# Commands
###################

def update_live_symlinks(config):
    """Update the certificate file family symlinks to use archive_dir.

    Use the information in the config file to make symlinks point to
    the correct archive directory.

    .. note:: This assumes that the installation is using a Reverter object.

    :param config: Configuration.
    :type config: :class:`certbot.configuration.NamespaceConfig`

    """
    for renewal_file in storage.renewal_conf_files(config):
        storage.RenewableCert(renewal_file, config, update_symlinks=True)

def rename_lineage(config):
    """Rename the specified lineage to the new name.

    :param config: Configuration.
    :type config: :class:`certbot.configuration.NamespaceConfig`

    """
    disp = zope.component.getUtility(interfaces.IDisplay)

    certname = _get_certname(config, "rename")

    new_certname = config.new_certname
    if not new_certname:
        code, new_certname = disp.input(
            "Enter the new name for certificate {0}".format(certname),
            flag="--updated-cert-name", force_interactive=True)
        if code != display_util.OK or not new_certname:
            raise errors.Error("User ended interaction.")

    lineage = lineage_for_certname(config, certname)
    if not lineage:
        raise errors.ConfigurationError("No existing certificate with name "
            "{0} found.".format(certname))
    storage.rename_renewal_config(certname, new_certname, config)
    disp.notification("Successfully renamed {0} to {1}."
        .format(certname, new_certname), pause=False)

def certificates(config):
    """Display information about certs configured with Certbot

    :param config: Configuration.
    :type config: :class:`certbot.configuration.NamespaceConfig`
    """
    parsed_certs = []
    parse_failures = []
    for renewal_file in storage.renewal_conf_files(config):
        try:
            renewal_candidate = storage.RenewableCert(renewal_file, config)
            crypto_util.verify_renewable_cert(renewal_candidate)
            parsed_certs.append(renewal_candidate)
        except Exception as e:  # pylint: disable=broad-except
            logger.warning("Renewal configuration file %s produced an "
                           "unexpected error: %s. Skipping.", renewal_file, e)
            logger.debug("Traceback was:\n%s", traceback.format_exc())
            parse_failures.append(renewal_file)

    # Describe all the certs
    _describe_certs(config, parsed_certs, parse_failures)

def delete(config):
    """Delete Certbot files associated with a certificate lineage."""
    certname = _get_certname(config, "delete")
    storage.delete_files(config, certname)
    disp = zope.component.getUtility(interfaces.IDisplay)
    disp.notification("Deleted all files relating to certificate {0}."
        .format(certname), pause=False)

###################
# Public Helpers
###################

def lineage_for_certname(cli_config, certname):
    """Find a lineage object with name certname."""
    configs_dir = cli_config.renewal_configs_dir
    # Verify the directory is there
    util.make_or_verify_dir(configs_dir, mode=0o755, uid=os.geteuid())
    try:
        renewal_file = storage.renewal_file_for_certname(cli_config, certname)
    except errors.CertStorageError:
        return None
    try:
        return storage.RenewableCert(renewal_file, cli_config)
    except (errors.CertStorageError, IOError):
        logger.debug("Renewal conf file %s is broken.", renewal_file)
        logger.debug("Traceback was:\n%s", traceback.format_exc())
        return None

def domains_for_certname(config, certname):
    """Find the domains in the cert with name certname."""
    lineage = lineage_for_certname(config, certname)
    return lineage.names() if lineage else None

def find_duplicative_certs(config, domains):
    """Find existing certs that duplicate the request."""
    def update_certs_for_domain_matches(candidate_lineage, rv):
        """Return cert as identical_names_cert if it matches,
           or subset_names_cert if it matches as subset
        """
        # TODO: Handle these differently depending on whether they are
        #       expired or still valid?
        identical_names_cert, subset_names_cert = rv
        candidate_names = set(candidate_lineage.names())
        if candidate_names == set(domains):
            identical_names_cert = candidate_lineage
        elif candidate_names.issubset(set(domains)):
            # This logic finds and returns the largest subset-names cert
            # in the case where there are several available.
            if subset_names_cert is None:
                subset_names_cert = candidate_lineage
            elif len(candidate_names) > len(subset_names_cert.names()):
                subset_names_cert = candidate_lineage
        return (identical_names_cert, subset_names_cert)

    return _search_lineages(config, update_certs_for_domain_matches, (None, None))

def _archive_files(candidate_lineage, filetype):
    """ In order to match things like:
        /etc/letsencrypt/archive/example.com/chain1.pem.

        Anonymous functions which call this function are eventually passed (in a list) to
        `match_and_check_overlaps` to help specify the acceptable_matches.
    """
    archive_dir = candidate_lineage.archive_dir
    pattern = [os.path.join(archive_dir, f) for f in os.listdir(archive_dir)
                    if re.match("{0}[0-9]*.pem".format(filetype), f)]
    if len(pattern) > 0:
        return pattern
    else:
        return None

def _acceptable_matches():
    return [lambda x: [x.fullchain_path], lambda x: [x.cert_path],
            lambda x: _archive_files(x, "cert"), lambda x: _archive_files(x, "fullchain")]

def cert_path_to_lineage(cli_config):
    """ If config.cert_path is defined, try to find an appropriate value for config.certname.

    :param .NamespaceConfig cli_config
    """
    acceptable_matches = _acceptable_matches()
    match = match_and_check_overlaps(cli_config, acceptable_matches,
            lambda x: cli_config.cert_path[0], lambda x: x.lineagename)
    return match[0]

def match_and_check_overlaps(cli_config, acceptable_matches, match_func, rv_func):
    """ Searches through all lineages for a match, and checks for duplicates.
    If a duplicate is found, an error is raised, as performing operations on lineages
    that have their properties incorrectly duplicated elsewhere is probably a bad idea.

    :param .NamespaceConfig cli_config
    :param list acceptable_matches: a list of functions that specify acceptable matches
    :param function match_func: specifies what to match
    :param function rv_func: specifies what to return

    """
    def find_matches(candidate_lineage, return_value, acceptable_matches):
        """Returns a list of matches using _search_lineages."""
        acceptable_matches_rv = []
        for func in acceptable_matches:
            acceptable_matches_rv += func(candidate_lineage)
        match = match_func(candidate_lineage)
        if match in acceptable_matches_rv:
            return_value.append(rv_func(candidate_lineage))
        return return_value

    matched = _search_lineages(cli_config, find_matches, [], acceptable_matches)
    if not matched:
        raise errors.Error("No match found for cert-path {0}!".format(cli_config.cert_path))
    elif len(matched) > 1:
        raise errors.OverlappingMatchFound()
    else:
        return matched

def human_readable_cert_info(config, cert, skip_filter_checks=False):
    """ Returns a human readable description of info about a RenewablCert object"""
    certinfo = []
    checker = ocsp.RevocationChecker()

    if config.certname and cert.lineagename != config.certname and not skip_filter_checks:
        return ""
    if config.domains and not set(config.domains).issubset(cert.names()):
        return ""
    now = pytz.UTC.fromutc(datetime.datetime.utcnow())

    reasons = []
    if cert.is_test_cert:
        reasons.append('TEST_CERT')
    if cert.target_expiry <= now:
        reasons.append('EXPIRED')
    if checker.ocsp_revoked(cert.cert, cert.chain):
        reasons.append('REVOKED')

    if reasons:
        status = "INVALID: " + ", ".join(reasons)
    else:
        diff = cert.target_expiry - now
        if diff.days == 1:
            status = "VALID: 1 day"
        elif diff.days < 1:
            status = "VALID: {0} hour(s)".format(diff.seconds // 3600)
        else:
            status = "VALID: {0} days".format(diff.days)

    valid_string = "{0} ({1})".format(cert.target_expiry, status)
    certinfo.append("  Certificate Name: {0}\n"
                    "    Domains: {1}\n"
                    "    Expiry Date: {2}\n"
                    "    Certificate Path: {3}\n"
                    "    Private Key Path: {4}".format(
                         cert.lineagename,
                         " ".join(cert.names()),
                         valid_string,
                         cert.fullchain,
                         cert.privkey))
    return "".join(certinfo)

###################
# Private Helpers
###################

def _get_certname(config, verb):
    """Get certname from flag, interactively, or error out.
    """
    certname = config.certname
    if not certname:
        disp = zope.component.getUtility(interfaces.IDisplay)
        filenames = storage.renewal_conf_files(config)
        choices = [storage.lineagename_for_filename(name) for name in filenames]
        if not choices:
            raise errors.Error("No existing certificates found.")
        code, index = disp.menu("Which certificate would you like to {0}?".format(verb),
                                choices, flag="--cert-name",
                                force_interactive=True)
        if code != display_util.OK or not index in range(0, len(choices)):
            raise errors.Error("User ended interaction.")
        certname = choices[index]
    return certname

def _report_lines(msgs):
    """Format a results report for a category of single-line renewal outcomes"""
    return "  " + "\n  ".join(str(msg) for msg in msgs)

def _report_human_readable(config, parsed_certs):
    """Format a results report for a parsed cert"""
    certinfo = []
    for cert in parsed_certs:
        certinfo.append(human_readable_cert_info(config, cert))
    return "\n".join(certinfo)

def _describe_certs(config, parsed_certs, parse_failures):
    """Print information about the certs we know about"""
    out = []

    notify = out.append

    if not parsed_certs and not parse_failures:
        notify("No certs found.")
    else:
        if parsed_certs:
            match = "matching " if config.certname or config.domains else ""
            notify("Found the following {0}certs:".format(match))
            notify(_report_human_readable(config, parsed_certs))
        if parse_failures:
            notify("\nThe following renewal configuration files "
               "were invalid:")
            notify(_report_lines(parse_failures))

    disp = zope.component.getUtility(interfaces.IDisplay)
    disp.notification("\n".join(out), pause=False, wrap=False)

def _search_lineages(cli_config, func, initial_rv, *args):
    """Iterate func over unbroken lineages, allowing custom return conditions.

    Allows flexible customization of return values, including multiple
    return values and complex checks.
    """
    configs_dir = cli_config.renewal_configs_dir
    # Verify the directory is there
    util.make_or_verify_dir(configs_dir, mode=0o755, uid=os.geteuid())

    rv = initial_rv
    for renewal_file in storage.renewal_conf_files(cli_config):
        try:
            candidate_lineage = storage.RenewableCert(renewal_file, cli_config)
        except (errors.CertStorageError, IOError):
            logger.debug("Renewal conf file %s is broken. Skipping.", renewal_file)
            logger.debug("Traceback was:\n%s", traceback.format_exc())
            continue
        rv = func(candidate_lineage, rv, *args)
    return rv
