"""DNS Authenticator for ConoHa DNS."""
import logging

import zope.interface
from lexicon.providers import conoha

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

API_INFO_URL = "https://manage.conoha.jp/API/"


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for ConoHa DNS

    This Authenticator uses the ConoHa API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using ConoHa for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=10)
        add('credentials', help='ConoHa credentials file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the ConoHa API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'ConoHa credentials file',
            {
                'region': \
                    'Region for ConoHa API',
                'tenant-id': \
                    'Tenant ID for ConoHa API obtained from {0}'.format(API_INFO_URL),
                'api-username': \
                    'API username for ConoHa API obtained from {0}'.format(API_INFO_URL),
                'api-password': \
                    'API password for ConoHa API obtained from {0}'.format(API_INFO_URL),
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_conoha_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_conoha_client().del_txt_record(domain, validation_name, validation)

    def _get_conoha_client(self):
        return _ConohaLexiconClient(
            self.credentials.conf('region'),
            self.credentials.conf('tenant-id'),
            self.credentials.conf('api-username'),
            self.credentials.conf('api-password'),
            self.ttl
        )


class _ConohaLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the ConoHa via Lexicon.
    """

    def __init__(self, region, auth_tenant_id, auth_username, auth_password, ttl):
        super(_ConohaLexiconClient, self).__init__()

        self.provider = conoha.Provider({
            'provider_name': 'conoha',
            'region': region,
            'auth_tenant_id': auth_tenant_id,
            'auth_username': auth_username,
            'auth_password': auth_password,
            'ttl': ttl,
        })

    def _handle_http_error(self, e, domain_name):
        hint = None
        if str(e).startswith('401 Client Error:'):
            hint = 'Are your API crendentials correct?'

        return errors.PluginError('Error determining zone identifier for {0}: {1}.{2}'
                                  .format(domain_name, e, ' ({0})'.format(hint) if hint else ''))
