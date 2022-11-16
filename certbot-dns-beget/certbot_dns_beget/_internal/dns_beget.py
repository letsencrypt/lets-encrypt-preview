"""DNS Authenticator for Beget DNS."""
import logging

import requests
import json
import zope.interface

from requests.exceptions import ConnectionError
from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

API_URL = 'https://api.beget.com/api'

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Beget

    This Authenticator uses the Beget API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using Beget for DNS).'
    priority = 10

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=30)
        add('credentials', help='Beget credentials file.')

    def more_info(self):  # pylint: disable=missing-function-docstring
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Beget API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Beget credentials file',
            {
                'login': 'Login for Beget API, obtained from {0}'.format(API_URL),
                'password': 'Password for Beget API, obtained from {0}'.format(API_URL)
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_beget_client().add_txt_record(domain, validation_name, validation, self.priority)

    def _cleanup(self, domain, validation_name, validation):
        self._get_beget_client().del_txt_record(domain, validation_name, validation)

    def _get_beget_client(self):
        return _BegetClient(self.credentials.conf('login'), self.credentials.conf('password'))


class _BegetClient(object):
    """
    Encapsulates all communication with the Beget via Lexicon.
    """

    def __init__(self, login, password):
        self.login = login
        self.password = password

    def add_txt_record(self, domain_name, record_name, record_content, record_priority = 10):
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the Beget zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_priority: The record priority (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Beget API
        """

        domain = {}
        input_data = {}
        domainList = self._beget_api('/domain/getList', input_data)
        if domainList['status'] == 'success':
            for _domain in domainList['result']:
                if _domain['fqdn'] == domain_name:
                    domain = _domain

            subdomainList = self._beget_api('/domain/getSubdomainList', input_data)

            isExist = False
            
            if subdomainList['status'] == 'success':
                for _subdomain in subdomainList['result']:
                    if _subdomain['fqdn'] == record_name:
                        print(_subdomain, record_name)
                        isExist = True
                        break
            
            subdomain = record_name.replace('.' + domain_name, '')
            if isExist == False:
                input_data = {
                    'subdomain' : subdomain,
                    'domain_id' : domain['id']
                }
                print(input_data)
                self._beget_api('/domain/addSubdomainVirtual', input_data)

            records = self._find_records(record_name)
            recordTxt = {
                "priority" : record_priority,
                "value" : record_content,
            }

            if "TXT" in records:
                records["TXT"].append(recordTxt)
            else:
                records["TXT"] = [recordTxt]

            input_data = {
                "fqdn" : record_name,
                "records": records
            }

            self._beget_api('/dns/changeRecords', input_data)            

    def del_txt_record(self, domain_name, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Failures are logged, but not raised.

        :param str domain: The domain to use to look up the Beget zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """

        input_data = {}
        subdomainList = self._beget_api('/domain/getSubdomainList', input_data)

        if subdomainList['status'] == 'success':
            for _subdomain in subdomainList['result']:
                if _subdomain['fqdn'] == record_name:
                    input_data = {
                        'id' : _subdomain['id'],
                    }
                    self._beget_api('/domain/deleteSubdomain', input_data)
                    break
        
    def _find_records(self, domain):
        """
        Find the find_records for a given domain.
        :param str domain: The domain for which to find the records.
        :returns: The records, if found.
        :rtype: json
        :raises certbot.errors.PluginError: if no records is found.
        """

        input_data = {
            "fqdn" : domain
        }

        data = self._beget_api('/dns/getData', input_data)
        if data['status'] == 'success':
            return data['result']['records']
        else:
            logger.error(data['errors'])
            raise errors.PluginError(data['errors'])
    
    def _beget_api(self, method, data):
        try:
            
            response = requests.get(
                API_URL + method,
                params = {
                    'login' : self.login,
                    'passwd' : self.password,
                    'input_format' : 'json',
                    'output_format' : 'json',
                    'input_data' : json.dumps(data) 
                }
            )
           
            json_response = response.json()

            if json_response['status'] == "error":
                logger.error(json_response['error_text'])
                raise errors.PluginError(json_response['error_text'])
            else:
                return json_response['answer']

        except ConnectionError as e:
            code = int(e)
            hint = None
            logger.error('Error communicating with the Beget API: %d %s', e, e)
            raise errors.PluginError('Error communicating with the Beget API: {0}{1}'
                                     .format(e, ' ({0})'.format(hint) if hint else ''))

    def _handle_http_error(self, e, domain_name):
        if domain_name in str(e) and (str(e).startswith('404 Client Error: Not Found for url:') or \
                                      str(e).startswith("400 Client Error: Bad Request for url:")):
            return None  # Expected errors when zone name guess is wrong
        hint = None
        if str(e).startswith('401 Client Error: Unauthorized for url:'):
            hint = 'Are your login and password values correct?'

        return errors.PluginError('Error determining zone identifier: {0}.{1}'
                                  .format(e, ' ({0})'.format(hint) if hint else ''))
