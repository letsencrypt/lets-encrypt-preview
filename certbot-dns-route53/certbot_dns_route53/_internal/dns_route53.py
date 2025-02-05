"""Certbot Route53 authenticator plugin."""
import collections
import logging
import time
from typing import Any
from typing import Callable
from typing import DefaultDict
from typing import Dict
from typing import Iterable
from typing import List
from typing import Type
from typing import cast

import boto3
from botocore.exceptions import ClientError
from botocore.exceptions import NoCredentialsError
from botocore.credentials import SharedCredentialProvider

from acme import challenges
from certbot import achallenges
from certbot import errors
from certbot import interfaces
from certbot.achallenges import AnnotatedChallenge
from certbot.plugins import common
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

INSTRUCTIONS = (
    "To use certbot-dns-route53, configure credentials as described at "
    "https://boto3.readthedocs.io/en/latest/guide/configuration.html#best-practices-for-configuring-credentials "  # pylint: disable=line-too-long
    "and add the necessary permissions for Route53 access.")


class Authenticator(common.Plugin, interfaces.Authenticator):
    """Route53 Authenticator

    This authenticator solves a DNS01 challenge by uploading the answer to AWS
    Route53.
    """

    description = ("Obtain certificates using a DNS TXT record (if you are using AWS Route53 for "
                   "DNS).")
    ttl = 10

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        if self.conf('credentials_file') and isinstance(self.conf('credentials_file'), str):
            dns_common.validate_file_permissions(self.conf('credentials'))

            creds = SharedCredentialProvider(self.conf("credentials")).load()

            if creds is None:
                raise errors.PluginError("Couldn't load AWS credentials")
            self.r53 = boto3.client("route53",
                aws_access_key_id=creds.access_key, aws_secret_access_key=creds.secret_key)
        else:
            self.r53 = boto3.client("route53")
        self._attempt_cleanup = False
        self._resource_records: DefaultDict[str, List[Dict[str, str]]] = \
            collections.defaultdict(list)

    def more_info(self) -> str:
        return "Solve a DNS01 challenge using AWS Route53"

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None]) -> None:
        add('credentials_file', help='Load AWS credentials from specified file.', default=None)

    def auth_hint(self, failed_achalls: List[achallenges.AnnotatedChallenge]) -> str:
        return (
            'The Certificate Authority failed to verify the DNS TXT records created by '
            '--dns-route53. Ensure the above domains have their DNS hosted by AWS Route53.'
        )

    def prepare(self) -> None:
        pass

    def get_chall_pref(self, unused_domain: str) -> Iterable[Type[challenges.Challenge]]:
        return [challenges.DNS01]

    def perform(self, achalls: List[AnnotatedChallenge]) -> List[challenges.ChallengeResponse]:
        self._attempt_cleanup = True

        try:
            change_ids = [
                self._change_txt_record("UPSERT",
                  achall.validation_domain_name(achall.domain),
                  achall.validation(achall.account_key))
                for achall in achalls
            ]

            for change_id in change_ids:
                self._wait_for_change(change_id)
        except (NoCredentialsError, ClientError) as e:
            logger.debug('Encountered error during perform: %s', e, exc_info=True)
            raise errors.PluginError("\n".join([str(e), INSTRUCTIONS]))
        return [achall.response(achall.account_key) for achall in achalls]

    def cleanup(self, achalls: List[achallenges.AnnotatedChallenge]) -> None:
        if self._attempt_cleanup:
            for achall in achalls:
                domain = achall.domain
                validation_domain_name = achall.validation_domain_name(domain)
                validation = achall.validation(achall.account_key)

                self._cleanup(validation_domain_name, validation)

    def _cleanup(self, validation_name: str, validation: str) -> None:
        try:
            self._change_txt_record("DELETE", validation_name, validation)
        except (NoCredentialsError, ClientError) as e:
            logger.debug('Encountered error during cleanup: %s', e, exc_info=True)

    def _find_zone_id_for_domain(self, domain: str) -> str:
        """Find the zone id responsible a given FQDN.

           That is, the id for the zone whose name is the longest parent of the
           domain.
        """
        paginator = self.r53.get_paginator("list_hosted_zones")
        zones: list[tuple[str, str]] = []
        target_labels = domain.rstrip(".").split(".")
        for page in paginator.paginate():
            for zone in page["HostedZones"]:
                if zone["Config"]["PrivateZone"]:
                    continue

                candidate_labels = zone["Name"].rstrip(".").split(".")
                if candidate_labels == target_labels[-len(candidate_labels):]:
                    zones.append((zone["Name"], zone["Id"]))

        if not zones:
            raise errors.PluginError(
                "Unable to find a Route53 hosted zone for {0}".format(domain)
            )

        # Order the zones that are suffixes for our desired to domain by
        # length, this puts them in an order like:
        # ["foo.bar.baz.com", "bar.baz.com", "baz.com", "com"]
        # And then we choose the first one, which will be the most specific.
        zones.sort(key=lambda z: len(z[0]), reverse=True)
        return zones[0][1]

    def _change_txt_record(self, action: str, validation_domain_name: str, validation: str) -> str:
        zone_id = self._find_zone_id_for_domain(validation_domain_name)

        rrecords = self._resource_records[validation_domain_name]
        challenge = {"Value": '"{0}"'.format(validation)}
        if action == "DELETE":
            # Remove the record being deleted from the list of tracked records
            rrecords.remove(challenge)
            if rrecords:
                # Need to update instead, as we're not deleting the rrset
                action = "UPSERT"
            else:
                # Create a new list containing the record to use with DELETE
                rrecords = [challenge]
        else:
            rrecords.append(challenge)

        response = self.r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Comment": "certbot-dns-route53 certificate validation " + action,
                "Changes": [
                    {
                        "Action": action,
                        "ResourceRecordSet": {
                            "Name": validation_domain_name,
                            "Type": "TXT",
                            "TTL": self.ttl,
                            "ResourceRecords": rrecords,
                        }
                    }
                ]
            }
        )
        return cast(str, response["ChangeInfo"]["Id"])

    def _wait_for_change(self, change_id: str) -> None:
        """Wait for a change to be propagated to all Route53 DNS servers.
           https://docs.aws.amazon.com/Route53/latest/APIReference/API_GetChange.html
        """
        for unused_n in range(0, 120):
            response = self.r53.get_change(Id=change_id)
            if response["ChangeInfo"]["Status"] == "INSYNC":
                return
            time.sleep(5)
        raise errors.PluginError(
            "Timed out waiting for Route53 change. Current status: %s" %
            response["ChangeInfo"]["Status"])


# Our route53 plugin was initially a 3rd party plugin named `certbot-route53:auth` as described at
# https://github.com/certbot/certbot/issues/4688. This shim exists to allow installations using the
# old plugin name of `certbot-route53:auth` to continue to work without cluttering things like
# Certbot's help output with two route53 plugins.
class HiddenAuthenticator(Authenticator):
    """A hidden shim around certbot-dns-route53 for backwards compatibility."""

    hidden = True
