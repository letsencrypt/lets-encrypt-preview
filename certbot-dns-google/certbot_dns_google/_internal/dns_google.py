"""DNS Authenticator for Google Cloud DNS."""
import logging
from typing import Any
from typing import Callable
from typing import Dict
from typing import Optional

import google.auth

from google.auth import exceptions as googleauth_exceptions
from googleapiclient import discovery
from googleapiclient import errors as googleapiclient_errors

from certbot import errors
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

ADC_URL = 'https://cloud.google.com/docs/authentication/application-default-credentials'
ACCT_URL = 'https://developers.google.com/identity/protocols/OAuth2ServiceAccount#creatinganaccount'
PERMISSIONS_URL = 'https://cloud.google.com/dns/access-control#permissions_and_roles'
METADATA_URL = 'http://metadata.google.internal/computeMetadata/v1/'
METADATA_HEADERS = {'Metadata-Flavor': 'Google'}


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Google Cloud DNS

    This Authenticator uses the Google Cloud DNS API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are using Google Cloud DNS '
                   'for DNS).')
    ttl = 60
    google_client = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 60) -> None:
        super().add_parser_arguments(add, default_propagation_seconds=60)
        add('credentials',
            help=('Path to Google Cloud DNS service account JSON file to use instead of relying on'
                  ' Application Default Credentials (ADC). (See {0} for information about ADC, {1}'
                  ' for information about creating a service account, and {2} for information about'
                  ' the permissions required to modify Cloud DNS records.)')
                  .format(ADC_URL, ACCT_URL, PERMISSIONS_URL),
            default=None)

        add('project',
            help=('The ID of the Google Cloud project that the Google Cloud DNS managed zone(s)' +
                  ' reside in. This will be determined automatically if not specified.'),
            default=None)

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Google Cloud DNS API.'

    def _setup_credentials(self) -> None:
        if self.conf('credentials') is not None:
            self._configure_file('credentials',
                                 'path to Google Cloud DNS service account JSON file')

            dns_common.validate_file_permissions(self.conf('credentials'))

        try:
            self._get_google_client()
        except googleauth_exceptions.DefaultCredentialsError as e:
            raise errors.PluginError('Authentication using Google Application Default Credentials '
                                     'failed ({}). Please configure credentials using'
                                     ' --dns-google-credentials <file>'.format(e))

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_google_client().add_txt_record(validation_name, validation, self.ttl)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_google_client().del_txt_record(validation_name, validation, self.ttl)

    def _get_google_client(self) -> '_GoogleClient':
        if self.google_client is None:
            self.google_client = _GoogleClient(self.conf('credentials'), self.conf('project'))
        return self.google_client



class _GoogleClient:
    """
    Encapsulates all communication with the Google Cloud DNS API.
    """

    def __init__(self, account_json: Optional[str] = None,
                 dns_project_id: Optional[str] = None,
                 dns_api: Optional[discovery.Resource] = None) -> None:

        scopes = ['https://www.googleapis.com/auth/ndev.clouddns.readwrite']
        credentials = None
        project_id = None

        if account_json is not None:
            try:
                credentials, project_id = google.auth.load_credentials_from_file(
                    account_json, scopes=scopes)
            except googleauth_exceptions.GoogleAuthError as e:
                raise errors.PluginError(
                    "Error loading credentials file '{}': {}".format(account_json, e))
        else:
            credentials, project_id = google.auth.default(scopes=scopes)

        if dns_project_id is not None:
            project_id = dns_project_id

        if not project_id:
            raise errors.PluginError('The Google Cloud project could not be automatically '
                                     'determined. Please configure it using --dns-google-project'
                                     ' <project>.')
        self.project_id = project_id

        if not dns_api:
            self.dns = discovery.build('dns', 'v1',
                                       credentials=credentials,
                                       cache_discovery=False)
        else:
            self.dns = dns_api

    def add_txt_record(self, record_name: str, record_content: str, record_ttl: int) -> None:
        """
        Add a TXT record using the supplied information.

        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Google API
        """

        zone_id = self._find_managed_zone_id(record_name)

        record_contents = self.get_existing_txt_rrset(zone_id, record_name)
        if record_contents is None:
            # If it wasn't possible to fetch the records at this label (missing .list permission),
            # assume there aren't any (#5678). If there are actually records here, this will fail
            # with HTTP 409/412 API errors.
            record_contents = {"rrdatas": []}
        add_records = record_contents["rrdatas"][:]

        if "\""+record_content+"\"" in record_contents["rrdatas"]:
            # The process was interrupted previously and validation token exists
            return

        add_records.append(record_content)

        data = {
            "kind": "dns#change",
            "additions": [
                {
                    "kind": "dns#resourceRecordSet",
                    "type": "TXT",
                    "name": record_name + ".",
                    "rrdatas": add_records,
                    "ttl": record_ttl,
                },
            ],
        }

        if record_contents["rrdatas"]:
            # We need to remove old records in the same request
            data["deletions"] = [
                {
                    "kind": "dns#resourceRecordSet",
                    "type": "TXT",
                    "name": record_name + ".",
                    "rrdatas": record_contents["rrdatas"],
                    "ttl": record_contents["ttl"],
                },
            ]

        changes = self.dns.changes()

        try:
            request = changes.create(project=self.project_id, managedZone=zone_id, body=data)
            response = request.execute()

            status = response['status']
            change = response['id']
            while status == 'pending':
                request = changes.get(project=self.project_id, managedZone=zone_id, changeId=change)
                response = request.execute()
                status = response['status']
        except googleapiclient_errors.Error as e:
            logger.error('Encountered error adding TXT record: %s', e)
            raise errors.PluginError('Error communicating with the Google Cloud DNS API: {0}'
                                     .format(e))

    def del_txt_record(self, record_name: str, record_content: str, record_ttl: int) -> None:
        """
        Delete a TXT record using the supplied information.

        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Google API
        """

        try:
            zone_id = self._find_managed_zone_id(record_name)
        except errors.PluginError:
            logger.warning('Error finding zone. Skipping cleanup.')
            return

        record_contents = self.get_existing_txt_rrset(zone_id, record_name)
        if record_contents is None:
            # If it wasn't possible to fetch the records at this label (missing .list permission),
            # assume there aren't any (#5678). If there are actually records here, this will fail
            # with HTTP 409/412 API errors.
            record_contents = {"rrdatas": ["\"" + record_content + "\""], "ttl": record_ttl}

        data = {
            "kind": "dns#change",
            "deletions": [
                {
                    "kind": "dns#resourceRecordSet",
                    "type": "TXT",
                    "name": record_name + ".",
                    "rrdatas": record_contents["rrdatas"],
                    "ttl": record_contents["ttl"],
                },
            ],
        }

        # Remove the record being deleted from the list
        readd_contents = [r for r in record_contents["rrdatas"]
                            if r != "\"" + record_content + "\""]
        if readd_contents:
            # We need to remove old records in the same request
            data["additions"] = [
                {
                    "kind": "dns#resourceRecordSet",
                    "type": "TXT",
                    "name": record_name + ".",
                    "rrdatas": readd_contents,
                    "ttl": record_contents["ttl"],
                },
            ]

        changes = self.dns.changes()

        try:
            request = changes.create(project=self.project_id, managedZone=zone_id, body=data)
            request.execute()
        except googleapiclient_errors.Error as e:
            logger.warning('Encountered error deleting TXT record: %s', e)

    def get_existing_txt_rrset(self, zone_id: str, record_name: str) -> Optional[Dict[str, Any]]:
        """
        Get existing TXT records from the RRset for the record name.

        If an error occurs while requesting the record set, it is suppressed
        and None is returned.

        :param str zone_id: The ID of the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').

        :returns: The resourceRecordSet corresponding to `record_name` or None
        :rtype: `resourceRecordSet <https://cloud.google.com/dns/docs/reference/v1/resourceRecordSets#resource>` or `None` # pylint: disable=line-too-long

        """
        rrs_request = self.dns.resourceRecordSets()
        # Add dot as the API returns absolute domains
        record_name += "."
        request = rrs_request.list(project=self.project_id, managedZone=zone_id, name=record_name,
                                   type="TXT")
        try:
            response = request.execute()
        except googleapiclient_errors.Error:
            logger.info("Unable to list existing records. If you're "
                        "requesting a wildcard certificate, this might not work.")
            logger.debug("Error was:", exc_info=True)
        else:
            if response and response["rrsets"]:
                return response["rrsets"][0]
        return None

    def _find_managed_zone_id(self, domain: str) -> str:
        """
        Find the managed zone for a given domain.

        :param str domain: The domain for which to find the managed zone.
        :returns: The ID of the managed zone, if found.
        :rtype: str
        :raises certbot.errors.PluginError: if the managed zone cannot be found.
        """

        zone_dns_name_guesses = dns_common.base_domain_name_guesses(domain)

        mz = self.dns.managedZones()
        for zone_name in zone_dns_name_guesses:
            try:
                request = mz.list(project=self.project_id, dnsName=zone_name + '.')
                response = request.execute()
                zones = response['managedZones']
            except googleapiclient_errors.Error as e:
                raise errors.PluginError('Encountered error finding managed zone: {0}'
                                         .format(e))

            for zone in zones:
                zone_id = zone['id']
                if zone['visibility'] == "public":
                    logger.debug('Found id of %s for %s using name %s', zone_id, domain, zone_name)
                    return zone_id

        raise errors.PluginError('Unable to determine managed zone for {0} using zone names: {1}.'
                                 .format(domain, zone_dns_name_guesses))
