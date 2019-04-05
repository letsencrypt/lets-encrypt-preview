"""Certbot DNS Authenticator for BookMyName."""
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

import requests
from bs4 import BeautifulSoup
import re

from acme.magic_typing import List # pylint: disable=unused-import, no-name-in-module

class Error(Exception):
    """Generic BookMyName error"""

class LoginError(Error):
    """BookMyname login failure"""

class DomainError(Error):
    """BookMyName domain access failure"""

class ZoneError(Error):
    """BookMyName zone access failure"""

class Manager(object):
    """BookMyName account manager

    This class handles the managing of a BookMyName account.
    It allows logging in, listing the domains registered to this account
    and reading and writing the zone of a registered domain.

    NOTE:

    There is an API provided by BookMyName to big (500+ domains) accounts.
    This file is NOT a client implementation of this BookMyName API.
    This file is just a wrapper around simple HTTP website access.

    The manager is not unit-testable as it requires a BookMyName account
    and there is no such test account available.

    OTOH, for unit-testing the _BookMyNameClient class, a mockup of this
    manager is used, which simulates an account and a domain.
    """

    description = 'Manages a BookMyName DNS account.'

    def __init__(self, login, password, http_session):
        self.login = login
        self.password = password
        self.session = http_session
        self.logged_in = False

    def log_in(self):
        """
        Log in on the website

        Open the website login page and pass the handle (login/id) and
        password. The session identifier will remain in self.session
        and allow further POST and GET requests to succeed.

        This method can be called several times; it will only log in
        once.
        """
        if not self.logged_in:
            try:
                self.session.post(
                    "https://www.bookmyname.com/login.cgi",
                    {
                        'handle': self.login,
                        'passwd': self.password
                    }
                )
                self.logged_in = True
            except:
                raise LoginError

    def get_domains(self):
        """
        Get the list of registered domains with their corresponding IDs

        This uses a URL which is not normally reached from the website
        but has been provided by the BookMyName support desk. This URL
        encodes the user id and password, which would be BAD if it were
        HTTP, but since that is HTTPS, the URL is passed inside the SSL
        connection.
        """
        self.log_in()
        try:
            domainsPage = self.session.get(
                "https://www.bookmyname.com/manager.cgi?cmd=dld"
            )
            domainsHtml = BeautifulSoup(domainsPage.text, 'html.parser')
            domainTableRows = domainsHtml.select("form table tr")
            domainsLastRow = domainTableRows[-1]
            IdentifierURL = domainsLastRow.td.a['href']
            IdentifierFrag = re.sub(r"^.*dlist-", "", IdentifierURL)
            Identifier = re.sub(r"\.csv\?cmd=csv$", "", IdentifierFrag)
            domainsCsv = self.session.get(
                "https://www.bookmyname.com/apis-cgi.cgi?id={0}&pwd={1}&fct=domain_list_ctc".format(
                    Identifier,
                    self.password)
            )
            domains = [x.split(',')[0].strip('"') for x in domainsCsv.text.split()]
            return domains
        except:
            raise DomainError

    def get_domain_zone(self, domain):
        """
        Get the zone for a given domain name

        NOTE: this returns the raw zone content, with lots of spaces
        inserted in order to align fields if using a fixed width font.

        This method will log in if necessary
        """
        self.log_in()
        try:
            zone_page = self.session.get(
                "https://www.bookmyname.com/manager.cgi?cmd=gdp&domain={0}&mode=1"
                .format(domain)
            )
            zone_html = BeautifulSoup(zone_page.text, 'html.parser')
            zone_textarea = zone_html.select('textarea[name="gdp_zonefile"]')[0]
            return zone_textarea.text.strip()
        except:
            raise ZoneError

    def set_domain_zone(self, domain, zone):
        """
        Set the zone for a given domain name

        NOTES: Extra whitespace within lines has no effect, but OTOH,
        the zone cannot be entirely empty, so if it is, we replace it
        with a single \n.
        Also, TXT records (and possibly others) require double quotes.

        This method will log in if necessary
        """
        if zone == '':
            zone = '\n'
        self.log_in()
        try:
            self.session.post(
                "https://www.bookmyname.com/manager.cgi?cmd=gdp&mode=1",
                {
                    'domain': domain,
                    'gdp_zonefile': zone,
                    'mode': 1,
                    'Submit': 'Valider'
                }
            )
        except:
            raise ZoneError

class _BookMyNameClient(object):
    """
    Encapsulates all communication with BookMyName.
    """

    def __init__(self, login, password, session):
        self.manager = Manager(login, password, session)
        self.domains = [] # type: List[str]

    def login(self):
        """
        Log in and pre-fetch registered domains and ids

        This method can be called several times; only the first one will
        cause an actual login and domain+id list fetch.
        """
        if len(self.domains) == 0:
            try:
                self.manager.log_in()
                try:
                    self.domains = self.manager.get_domains()
                except Error as e:
                    raise errors.PluginError(
                        'Error getting BookMyName domains: {0}'.format(e)
                    )
            except Error as e:
                raise errors.PluginError(
                    'Error logging into BookMyName: {0}'.format(e)
                )

    def get_registered_domain(self, domain):
        """
        Return the registered domain matching the provided domain if any

        A registered domain matches the provided domain if the provided
        domain ends with the registered domain.

        This method will log in if needed.
        """
        self.login()
        for registered_domain in self.domains:
            if domain.endswith(registered_domain):
                return registered_domain
        raise errors.PluginError(
            'No registered BookMyName domain match for domain {0}'
            .format(domain)
        )

    def update_zone(self, domain, validation_name, validation, add):
        """
        Add a TXT record for the validation name and value

        The record sets as low a TTL as BookMyName allows, which is 300.

        The validation name has the full domain, but the record expects
        only the prefix, without the registered domain at the end, so we
        remove the suffix.

        This method will log in if needed.
        """
        self.login()
        try:
            registered_domain = self.get_registered_domain(domain)
            short_valid_name = re.sub(r"\."+registered_domain+"$", "", validation_name)
            record = short_valid_name + ' 300 TXT "' + validation +'"'
            zone_in = self.manager.get_domain_zone(registered_domain)
            zonelines_raw = zone_in.split('\n')
            zonelines = [' '.join(X.split()) for X in zonelines_raw]
            if add:
                zonelines.append(record)
            else:
                zonelines.remove(record)
            zone_out = '\n'.join(zonelines)
            self.manager.set_domain_zone(registered_domain, zone_out)
        except Error as e:
            raise errors.PluginError(
                'Error {0} BookMyName domain {1} TXT record {2} = {3}: {4}'
                .format(
                    "adding" if add else "removing",
                    registered_domain,
                    short_valid_name,
                    validation,
                    e)
            )

    def add_txt_record(self, domain, validation_name, validation):
        """
        Add a TXT record for the validation name and value

        The record sets as low a TTL as BookMyName allows, which is 300.

        The validation name has the full domain, but the record expects
        only the prefix, without the registered domain at the end, so we
        remove the suffix.

        This method will log in if needed.
        """
        self.update_zone(domain, validation_name, validation, True)

    def del_txt_record(self, domain, validation_name, validation):
        """
        Delete a TXT record for the validation name and value

        The validation name has the full domain, but the record contains
        only the prefix, without the registered domain at the end, so we
        remove the suffix.

        This method will log in if needed.
        """
        self.update_zone(domain, validation_name, validation, False)

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for BookMyName

    This Authenticator fulfills a dns-01 challenge for BookMyName domains.
    """

    description = 'Obtain certs using DNS TXT records at BookMyName.'

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None
        self.manager = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=900)
        add('credentials', help='BookMyName credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the BookMyName API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'BookMyName credentials INI file',
            {
                'login': 'Login (ID) for BookMyName account',
                'password': 'Password for BookMyName account login/ID'
            }
        )

    def _get_bookmyname_client(self):
        return _BookMyNameClient(
                self.credentials.conf('login'),
                self.credentials.conf('password'),
                requests.session()
            )

    def _perform(self, domain, validation_name, validation):
        self._get_bookmyname_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_bookmyname_client().del_txt_record(domain, validation_name, validation)
