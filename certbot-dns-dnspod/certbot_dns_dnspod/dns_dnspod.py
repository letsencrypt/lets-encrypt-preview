"""DNS Authenticator for Dnspod."""
import logging

from certbot_dns_dnspod.dns_dnspod_client import DnspodClient
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Dnspod
    This Authenticator uses the Dnspod API to fulfill a dns-01 challenge.
    """

    description = "Obtain certs using a DNS TXT record (if you are using Dnspod for DNS)."

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add)
        add("credentials", help="Dnspod credentials INI file.")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return "This plugin configures a DNS TXT record to respond to a dns-01 challenge using " + \
               "the Dnspod API."

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "Dnspod credentials INI file",
            {
                "id": "id for Dnspod account",
                "token": "API token for Dnspod account"
            }
        )

    def _perform(self, domain, validation_name, validation):
        domain = self._find_domain(domain)
        self._get_dnspod_client().ensure_record(domain, validation_name, "TXT", validation)

    def _cleanup(self, domain, validation_name, validation):
        domain = self._find_domain(domain)
        self._get_dnspod_client().remove_record_by_sub_domain(domain, validation_name, "TXT")

    def _get_dnspod_client(self): # pragma: no cover
        return DnspodClient(self.credentials.conf("id"), self.credentials.conf("token"))

    def _find_domain(self, domain_name):
        domain_name_guesses = dns_common.base_domain_name_guesses(domain_name)
        domains = self._get_dnspod_client().domain_list()
        for guess in domain_name_guesses:
            if guess in domains:
                return guess

        raise errors.PluginError("Unable to determine base domain for {0} using names: {1}."
                                                     .format(domain_name, domain_name_guesses))
