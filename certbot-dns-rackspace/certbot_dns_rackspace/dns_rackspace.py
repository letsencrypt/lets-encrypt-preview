"""DNS Authenticator for Rackspace Cloud DNS."""
import logging

import zope.interface
from lexicon.providers import rackspace

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://account.rackspace.com/'
USER_URL = 'https://account.rackspace.com/users'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Rackspace Cloud DNS

    This Authenticator uses the Rackspace Cloud DNS v1 API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record \
                   (if you are using Rackspace Cloud DNS).'
    """Minimum TTL for Rackspace Cloud DNS is 300 seconds"""
    ttl = 300

    """Manually set a sleep time to work around possible bug in Rackspace Lexicon script"""
    sleep_time = 1

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=30)
        add('credentials', help='Rackspace Cloud credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Rackspace Cloud DNS API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Rackspace Cloud credentials INI file',
            {
                'username': 'Username for Rackspace Cloud Account.',
                'apiKey': 'User\'s API Key for the Rackspace Cloud APIs. \
                           (See {0})'.format(USER_URL),
                'account_id': 'Rackspace Account number (See {0})'.format(ACCOUNT_URL)
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_rackspace_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_rackspace_client().del_txt_record(domain, validation_name, validation)

    def _get_rackspace_client(self):
        return _RackspaceLexiconClient(self.credentials.conf('username'),
                                       self.credentials.conf('apiKey'),
                                       self.credentials.conf('account_id'),
                                       self.sleep_time,
                                       self.ttl)


class _RackspaceLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the Rackspace Cloud DNS API via Lexicon.
    """

    def __init__(self, username, apiKey, account_id, sleep_time, ttl):
        super(_RackspaceLexiconClient, self).__init__()

        self.provider = rackspace.Provider({
            'auth_username': username,
            'auth_api_key': apiKey,
            'auth_account': account_id,
            'sleep_time': sleep_time,
            'ttl': ttl,
        })

    def _handle_http_error(self, e, domain_name):
        hint = None
        if str(e).startswith('401 Client Error: Unauthorized for url:'):
            hint = 'Are your API credentials correct?'

        return errors.PluginError('Error determining zone identifier for {0}: {1}.{2}'
                                  .format(domain_name, e, ' ({0})'.format(hint) if hint else ''))
