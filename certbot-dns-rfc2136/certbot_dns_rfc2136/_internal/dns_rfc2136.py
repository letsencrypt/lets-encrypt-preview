"""DNS Authenticator using RFC 2136 Dynamic Updates."""
import logging
from time import sleep
from typing import Any
from typing import Callable
from typing import List
from typing import Iterable
from typing import cast
from typing import Optional
from typing import Dict
from collections import namedtuple

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.tsig
import dns.tsigkeyring
import dns.update

from acme import challenges
from certbot import errors
from certbot import achallenges
from certbot.display import util as display_util
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration
from certbot.util import is_ipaddress

logger = logging.getLogger(__name__)

DEFAULT_NETWORK_TIMEOUT = 45


TXTRecord = namedtuple('TXTRecord', ['name', 'content', 'ttl'], defaults=[-1])


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator using RFC 2136 Dynamic Updates

    This Authenticator uses RFC 2136 Dynamic Updates to fulfill a dns-01 challenge.
    """

    ALGORITHMS = {
      'HMAC-MD5': dns.tsig.HMAC_MD5,
      'HMAC-SHA1': dns.tsig.HMAC_SHA1,
      'HMAC-SHA224': dns.tsig.HMAC_SHA224,
      'HMAC-SHA256': dns.tsig.HMAC_SHA256,
      'HMAC-SHA384': dns.tsig.HMAC_SHA384,
      'HMAC-SHA512': dns.tsig.HMAC_SHA512
    }

    PORT = 53

    description = 'Obtain certificates using a DNS TXT record with RFC2136 UPDATE.'
    ttl = 120

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 60) -> None:
        super().add_parser_arguments(add, default_propagation_seconds=60)
        add('credentials', help='RFC 2136 credentials INI file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'RFC 2136 Dynamic Updates.'

    def _validate_credentials(self, credentials: CredentialsConfiguration) -> None:
        server = cast(str, credentials.conf('server'))
        if not is_ipaddress(server):
            raise errors.PluginError("The configured target DNS server ({0}) is not a valid IPv4 "
                                     "or IPv6 address. A hostname is not allowed.".format(server))
        algorithm = credentials.conf('algorithm')
        if algorithm:
            if not self.ALGORITHMS.get(algorithm.upper()):
                raise errors.PluginError("Unknown algorithm: {0}.".format(algorithm))

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            'RFC 2136 credentials INI file',
            {
                'name': 'TSIG key name',
                'secret': 'TSIG key secret',
                'server': 'The target DNS server'
            },
            self._validate_credentials
        )

    def _perform(self, _domain: str, validation_name: str, validation: str) -> None:
        assert False
    def perform(self, achalls: List[achallenges.AnnotatedChallenge]
                ) -> List[challenges.ChallengeResponse]: # pylint: disable=missing-function-docstring
        self._setup_credentials()

        self._attempt_cleanup = True

        self._get_rfc2136_client().add_txt_records(TXTRecord(
                name=achall.validation_domain_name(achall.domain),
                content=achall.validation(achall.account_key),
                ttl=self.ttl
            ) for achall in achalls)

        # DNS updates take time to propagate and checking to see if the update has occurred is not
        # reliable (the machine this code is running on might be able to see an update before
        # the ACME server). So: we sleep for a short amount of time we believe to be long enough.
        display_util.notify("Waiting %d seconds for DNS changes to propagate" %
                    self.conf('propagation-seconds'))
        sleep(self.conf('propagation-seconds'))

        return [achall.response(achall.account_key) for achall in achalls]

    def _cleanup(self, _domain: str, validation_name: str, validation: str) -> None:
        assert False
    def cleanup(self, achalls: List[achallenges.AnnotatedChallenge]) -> None:  # pylint: disable=missing-function-docstring
        if self._attempt_cleanup:
            self._get_rfc2136_client().del_txt_records(TXTRecord(
                    name=achall.validation_domain_name(achall.domain),
                    content=achall.validation(achall.account_key)
                ) for achall in achalls)

    def _get_rfc2136_client(self) -> "_RFC2136Client":
        if not self.credentials:  # pragma: no cover
            raise errors.Error("Plugin has not been prepared.")

        return _RFC2136Client(cast(str, self.credentials.conf('server')),
                              int(cast(str, self.credentials.conf('port')) or self.PORT),
                              cast(str, self.credentials.conf('name')),
                              cast(str, self.credentials.conf('secret')),
                              self.ALGORITHMS.get(self.credentials.conf('algorithm') or '',
                                                  dns.tsig.HMAC_MD5),
                              (self.credentials.conf('sign_query') or '').upper() == "TRUE")


SOA_CACHE: Dict[str, bool] = {}
class _RFC2136Client:
    """
    Encapsulates all communication with the target DNS server.
    """
    def __init__(self, server: str, port: int, key_name: str, key_secret: str,
                 key_algorithm: dns.name.Name, sign_query: bool,
                 timeout: int = DEFAULT_NETWORK_TIMEOUT) -> None:
        self.server = server
        self.port = port
        self.keyring = dns.tsigkeyring.from_text({
            key_name: key_secret
        })
        self.algorithm = key_algorithm
        self.sign_query = sign_query
        self._default_timeout = timeout

    def _group_by_domain(self, records: Iterable[TXTRecord]) -> Dict[str, List[TXTRecord]]:
        """
        Group records to add/delete by the zone to which they belong for batching.
        """

        by_domain: Dict[str, List[TXTRecord]] = {}
        for record in records:
            domain = self._find_domain(record.name)
            try:
                by_domain[domain].append(record)
            except KeyError:
                by_domain[domain] = [record]
        return by_domain

    def add_txt_records(self, records: Iterable[TXTRecord]) -> None:
        """
        Add TXT records using the supplied information.

        :param str records[].name: The record name (typically beginning with '_acme-challenge.').
        :param str records[].content: The record content (typically the challenge validation).
        :param int records[].ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the DNS server
        """

        for domain, drecords in self._group_by_domain(records).items():
            self._add_txt_records(domain, drecords)

    def _add_txt_records(self, domain: str, records: Iterable[TXTRecord]) -> None:
        o = dns.name.from_text(domain)
        update = dns.update.Update(
            domain,
            keyring=self.keyring,
            keyalgorithm=self.algorithm)

        for record in records:
            n = dns.name.from_text(record.name)
            rel = n.relativize(o)
            update.add(rel, record.ttl, dns.rdatatype.TXT, record.content)

        try:
            response = dns.query.tcp(update, self.server, self._default_timeout, self.port)
        except Exception as e:
            raise errors.PluginError('Encountered error adding TXT record: {0}'
                                     .format(e))
        rcode = response.rcode()

        if rcode == dns.rcode.NOERROR:
            logger.debug('Successfully added TXT records %s', ', '.join(r.name for r in records))
        else:
            raise errors.PluginError('Received response from server: {0}'
                                     .format(dns.rcode.to_text(rcode)))


    def del_txt_records(self, records: Iterable[TXTRecord]) -> None:
        """
        Delete a TXT record using the supplied information.

        :param str records[].name: The record name (typically beginning with '_acme-challenge.').
        :param str records[].content: The record content (typically the challenge validation).
        :raises certbot.errors.PluginError: if an error occurs communicating with the DNS server
        """

        for domain, drecords in self._group_by_domain(records).items():
            self._del_txt_records(domain, drecords)

    def _del_txt_records(self, domain: str, records: Iterable[TXTRecord]) -> None:
        o = dns.name.from_text(domain)
        update = dns.update.Update(
            domain,
            keyring=self.keyring,
            keyalgorithm=self.algorithm)

        for record in records:
            n = dns.name.from_text(record.name)
            rel = n.relativize(o)
            update.delete(rel, dns.rdatatype.TXT, record.content)

        try:
            response = dns.query.tcp(update, self.server, self._default_timeout, self.port)
        except Exception as e:
            raise errors.PluginError('Encountered error deleting TXT record: {0}'
                                     .format(e))
        rcode = response.rcode()

        if rcode == dns.rcode.NOERROR:
            logger.debug('Successfully deleted TXT record %s', ', '.join(r.name for r in records))
        else:
            raise errors.PluginError('Received response from server: {0}'
                                     .format(dns.rcode.to_text(rcode)))

    def _find_domain(self, record_name: str) -> str:
        """
        Find the closest domain with an SOA record for a given domain name.

        :param str record_name: The record name for which to find the closest SOA record.
        :returns: The domain, if found.
        :rtype: str
        :raises certbot.errors.PluginError: if no SOA record can be found.
        """

        domain_name_guesses = dns_common.base_domain_name_guesses(record_name)

        # Loop through until we find an authoritative SOA record
        for guess in domain_name_guesses:
            try:
                if SOA_CACHE[guess]:
                    return guess
            except KeyError:
                if self._query_soa(guess):
                    SOA_CACHE[guess] = True
                    return guess
                SOA_CACHE[guess] = False

        raise errors.PluginError('Unable to determine base domain for {0} using names: {1}.'
                                 .format(record_name, domain_name_guesses))

    def _query_soa(self, domain_name: str) -> bool:
        """
        Query a domain name for an authoritative SOA record.

        :param str domain_name: The domain name to query for an SOA record.
        :returns: True if found, False otherwise.
        :rtype: bool
        :raises certbot.errors.PluginError: if no response is received.
        """

        domain = dns.name.from_text(domain_name)

        request = dns.message.make_query(domain, dns.rdatatype.SOA, dns.rdataclass.IN)
        # Turn off Recursion Desired bit in query
        request.flags ^= dns.flags.RD
        # Use our TSIG keyring if configured
        if self.sign_query:
            request.use_tsig(self.keyring, algorithm=self.algorithm)

        try:
            try:
                response = dns.query.tcp(request, self.server, self._default_timeout, self.port)
            except (OSError, dns.exception.Timeout) as e:
                logger.debug('TCP query failed, fallback to UDP: %s', e)
                response = dns.query.udp(request, self.server, self._default_timeout, self.port)
            rcode = response.rcode()

            # Authoritative Answer bit should be set
            if (rcode == dns.rcode.NOERROR
                    and response.get_rrset(response.answer,
                                           domain, dns.rdataclass.IN, dns.rdatatype.SOA)
                    and response.flags & dns.flags.AA):
                logger.debug('Received authoritative SOA response for %s', domain_name)
                return True

            logger.debug('No authoritative SOA record found for %s', domain_name)
            return False
        except Exception as e:
            raise errors.PluginError('Encountered error when making query: {0}'
                                     .format(e))
