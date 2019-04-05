"""Tests for certbot_dns_bookmyname.dns_bookmyname."""

import os
import unittest

import mock

from certbot import errors
from certbot.plugins.dns_common import CredentialsConfiguration
from certbot.plugins import dns_test_common
from certbot.tests import util as test_util

import requests
import certbot_dns_bookmyname.dns_bookmyname as bookmyname


class BookMyNameTest(unittest.TestCase):

    def setUp(self):

        self.session = mock.MagicMock(spec=requests.session())

        self.manager = bookmyname.Manager('a_login', 'a_password', self.session)


    def test_log_in_success(self):

        self.manager.session.post.return_value = b"""
<html>
    <body>
    </body>
</html>
        """

        self.manager.log_in()

        self.manager.session.post.assert_called_once_with(
            "https://www.bookmyname.com/login.cgi",
            {
                'handle': 'a_login',
                'passwd': 'a_password'
            }
        )

    def test_log_in_failure(self):

        self.manager.session.post.side_effect = Exception

        self.assertRaises(
            bookmyname.LoginError,
            self.manager.log_in
        )

        self.manager.session.post.assert_called_once_with(
            "https://www.bookmyname.com/login.cgi",
            {
                'handle': 'a_login',
                'passwd': 'a_password'
            }
        )

    def test_get_domains_success(self):

        p = mock.MagicMock(requests.Response())
        p.text = b"""
<html>
  <body>
  </body>
</html>
        """
        self.manager.session.post.return_value = p
        gd = mock.MagicMock(requests.Response())
        gd.text = b"""
<html>
  <body>
    <form>
      <table>
        <tr>
          <td>
            <a href="dlist-12345.csv?cmd=csv">whatever</a>
          </td>
        </tr>
      </table>
    </form>
  </body>
</html>
        """
        gl = mock.MagicMock(requests.Response())
        gl.text = """
"bookmyname.invalid","1544007590","64","12345","12345","12345","12345","Active","unsigned"
        """
        self.manager.session.get.side_effect = [gd, gl]

        self.assertEqual(
            self.manager.get_domains(),
            [
                u'bookmyname.invalid'
            ]
        )

        self.manager.session.post.assert_called_with(
            "https://www.bookmyname.com/login.cgi",
            {
                'handle': 'a_login',
                'passwd': 'a_password'
            }
        )

        self.manager.session.get.assert_has_calls(
            [
                mock.call(
                    'https://www.bookmyname.com/manager.cgi?cmd=dld'
                ),
                mock.call(
                    'https://www.bookmyname.com/apis-cgi.cgi?'
                        'id=12345&pwd=a_password&fct=domain_list_ctc'
                )
            ]
        )

    def test_get_domains_login_failure(self):

        self.manager.session.post.side_effect = Exception

        self.assertRaises(
            bookmyname.LoginError,
            self.manager.log_in
        )

        self.manager.session.post.assert_called_once_with(
            "https://www.bookmyname.com/login.cgi",
            {
                'handle': 'a_login',
                'passwd': 'a_password'
            }
        )

        self.manager.session.get.assert_not_called()

    def test_get_domains_domain_failure(self):

        p = mock.MagicMock(requests.Response())
        p.text = b"""
<html>
  <body>
  </body>
</html>
        """
        self.manager.session.post.return_value = p
        self.manager.session.get.side_effect = Exception

        self.assertRaises(
            bookmyname.DomainError,
            self.manager.get_domains
        )

        self.manager.session.post.assert_called_once_with(
            "https://www.bookmyname.com/login.cgi",
            {
                'handle': 'a_login',
                'passwd': 'a_password'
            }
        )

        self.manager.session.get.assert_called_once_with(
            'https://www.bookmyname.com/manager.cgi?cmd=dld'
        )

    def test_get_domain_zone_success(self):

        p = mock.MagicMock(requests.Response())
        p.text = b"""
<html>
  <body>
  </body>
</html>
        """
        self.manager.session.post.return_value = p
        gd = mock.MagicMock(requests.Response())
        gd.text = b"""
<html>
  <body>
    <form>
      <table>
        <tr>
          <td>
            <a href="dlist-12345.csv?cmd=csv">whatever</a>
          </td>
        </tr>
      </table>
    </form>
  </body>
</html>
        """
        gl = mock.MagicMock(requests.Response())
        gl.text = """
"bookmyname.invalid","1544007590","64","12345","12345","12345","12345","Active","unsigned"
        """
        gz = mock.MagicMock(requests.Response())
        gz.text = b"""
<html>
  <body>
    <form>
      <textarea name="gdp_zonefile">
        @ CNAME xyz
      </textarea>
    </form>
  </body>
</html>
        """
        self.manager.session.get.side_effect = [gd, gl, gz]

        self.manager.get_domains()
        self.assertEqual(
            self.manager.get_domain_zone('bookmyname.invalid'),
            '@ CNAME xyz'
        )

        self.manager.session.post.assert_called_once_with(
            "https://www.bookmyname.com/login.cgi",
            {
                'handle': 'a_login',
                'passwd': 'a_password'
            }
        )

        self.manager.session.get.assert_has_calls(
            [
                mock.call(
                    'https://www.bookmyname.com/manager.cgi?cmd=dld'
                ),
                mock.call(
                    'https://www.bookmyname.com/apis-cgi.cgi?'
                        'id=12345&pwd=a_password&fct=domain_list_ctc'
                )
            ]
        )

    def test_get_domain_zone_failure(self):

        p = mock.MagicMock(requests.Response())
        p.text = b"""
<html>
  <body>
  </body>
</html>
        """
        self.manager.session.post.return_value = p
        gd = mock.MagicMock(requests.Response())
        gd.text = b"""
<html>
  <body>
    <form>
      <table>
        <tr>
          <td>
            <a href="dlist-12345.csv?cmd=csv">whatever</a>
          </td>
        </tr>
      </table>
    </form>
  </body>
</html>
        """
        gl = mock.MagicMock(requests.Response())
        gl.text = """
"bookmyname.invalid","1544007590","64","12345","12345","12345","12345","Active","unsigned"
        """
        self.manager.session.get.side_effect = [gd, gl, Exception]

        self.manager.get_domains()
        self.assertRaises(
            bookmyname.ZoneError,
            self.manager.get_domain_zone,
            'bookmyname.invalid'
        )

        self.manager.session.post.assert_called_once_with(
            "https://www.bookmyname.com/login.cgi",
            {
                'handle': 'a_login',
                'passwd': 'a_password'
            }
        )

        self.manager.session.get.assert_has_calls(
            [
                mock.call(
                    'https://www.bookmyname.com/manager.cgi?cmd=dld'
                ),
                mock.call(
                    'https://www.bookmyname.com/apis-cgi.cgi?'
                        'id=12345&pwd=a_password&fct=domain_list_ctc'
                )
            ]
        )

    def test_set_domain_zone_success(self):

        p = mock.MagicMock(requests.Response())
        p.text = b"""
<html>
  <body>
  </body>
</html>
        """
        self.manager.session.post.return_value = p
        gd = mock.MagicMock(requests.Response())
        gd.text = b"""
<html>
  <body>
    <form>
      <table>
        <tr>
          <td>
            <a href="dlist-12345.csv?cmd=csv">whatever</a>
          </td>
        </tr>
      </table>
    </form>
  </body>
</html>
        """
        gl = mock.MagicMock(requests.Response())
        gl.text = """
"bookmyname.invalid","1544007590","64","12345","12345","12345","12345","Active","unsigned"
        """
        gz = mock.MagicMock(requests.Response())
        gz.text = b"""
<html>
  <body>
    <form>
      <textarea name="gdp_zonefile">
        @ CNAME xyz
      </textarea>
    </form>
  </body>
</html>
        """
        self.manager.session.get.side_effect = [gd, gl, gz]

        self.manager.get_domains()
        self.manager.set_domain_zone('bookmyname.invalid', '@ CNAME xyz')

        self.manager.session.post.assert_has_calls(
            [
                mock.call(
                    "https://www.bookmyname.com/login.cgi",
                    {
                        'handle': 'a_login',
                        'passwd': 'a_password'
                    }
                ),
                mock.call(
                    'https://www.bookmyname.com/manager.cgi?cmd=gdp&mode=1',
                    {
                        'domain': 'bookmyname.invalid',
                        'gdp_zonefile': '@ CNAME xyz',
                        'mode': 1,
                        'Submit': 'Valider'
                    }
                )
            ]
        )

        self.manager.session.get.assert_has_calls(
            [
                mock.call(
                    'https://www.bookmyname.com/manager.cgi?cmd=dld'
                ),
                mock.call(
                    'https://www.bookmyname.com/apis-cgi.cgi?'
                        'id=12345&pwd=a_password&fct=domain_list_ctc'
                )
            ]
        )

    def test_set_domain_zone_empty_success(self):

        p = mock.MagicMock(requests.Response())
        p.text = b"""
<html>
  <body>
  </body>
</html>
        """
        self.manager.session.post.return_value = p
        gd = mock.MagicMock(requests.Response())
        gd.text = b"""
<html>
  <body>
    <form>
      <table>
        <tr>
          <td>
            <a href="dlist-12345.csv?cmd=csv">whatever</a>
          </td>
        </tr>
      </table>
    </form>
  </body>
</html>
        """
        gl = mock.MagicMock(requests.Response())
        gl.text = """
"bookmyname.invalid","1544007590","64","12345","12345","12345","12345","Active","unsigned"
        """
        gz = mock.MagicMock(requests.Response())
        gz.text = b"""
<html>
  <body>
    <form>
      <textarea name="gdp_zonefile">
      </textarea>
    </form>
  </body>
</html>
        """
        self.manager.session.get.side_effect = [gd, gl, gz]

        self.manager.get_domains()
        self.manager.set_domain_zone('bookmyname.invalid', '')

        self.manager.session.post.assert_has_calls(
            [
                mock.call(
                    "https://www.bookmyname.com/login.cgi",
                    {
                        'handle': 'a_login',
                        'passwd': 'a_password'
                    }
                ),
                mock.call(
                    'https://www.bookmyname.com/manager.cgi?cmd=gdp&mode=1',
                    {
                        'domain': 'bookmyname.invalid',
                        'gdp_zonefile': '\n',
                        'mode': 1,
                        'Submit': 'Valider'
                    }
                )
            ]
        )

        self.manager.session.get.assert_has_calls(
            [
                mock.call(
                    'https://www.bookmyname.com/manager.cgi?cmd=dld'
                ),
                mock.call(
                    "https://www.bookmyname.com/apis-cgi.cgi?"
                        "id=12345&pwd=a_password&fct=domain_list_ctc"
                )
            ]
        )

    def test_set_domain_zone_domain_failure(self):

        p = mock.MagicMock(requests.Response())
        p.text = b"""
<html>
  <body>
  </body>
</html>
        """
        self.manager.session.post.side_effect = [p, Exception]
        gd = mock.MagicMock(requests.Response())
        gd.text = b"""
<html>
  <body>
    <form>
      <table>
        <tr>
          <td>
            <a href="dlist-12345.csv?cmd=csv">whatever</a>
          </td>
        </tr>
      </table>
    </form>
  </body>
</html>
        """
        gl = mock.MagicMock(requests.Response())
        gl.text = """
"bookmyname.invalid","1544007590","64","12345","12345","12345","12345","Active","unsigned"
        """
        self.manager.session.get.side_effect = [gd, gl]

        self.manager.get_domains()
        self.assertRaises(
            bookmyname.ZoneError,
            self.manager.set_domain_zone,
            'bookmyname.invalid',
            '@ CNAME xyz'
        )

        self.manager.session.post.assert_has_calls(
            [
                mock.call(
                    "https://www.bookmyname.com/login.cgi",
                    {
                        'handle': 'a_login',
                        'passwd': 'a_password'
                    }
                ),
                mock.call(
                    'https://www.bookmyname.com/manager.cgi?cmd=gdp&mode=1',
                    {
                        'domain': 'bookmyname.invalid',
                        'gdp_zonefile': '@ CNAME xyz',
                        'mode': 1,
                        'Submit': 'Valider'
                    }
                )
            ]
        )

        self.manager.session.get.assert_has_calls(
            [
                mock.call(
                    'https://www.bookmyname.com/manager.cgi?cmd=dld'
                ),
                mock.call(
                    'https://www.bookmyname.com/apis-cgi.cgi?'
                        'id=12345&pwd=a_password&fct=domain_list_ctc'
                )
            ]
        )

    def test_set_domain_zone_zone_failure(self):

        p = mock.MagicMock(requests.Response())
        p.text = b"""
<html>
  <body>
  </body>
</html>
        """
        self.manager.session.post.side_effect = [p, Exception]
        gd = mock.MagicMock(requests.Response())
        gd.text = b"""
<html>
  <body>
    <form>
      <table>
        <tr>
          <td>
            <a href="dlist-12345.csv?cmd=csv">whatever</a>
          </td>
        </tr>
      </table>
    </form>
  </body>
</html>
        """
        gl = mock.MagicMock(requests.Response())
        gl.text = """
"bookmyname.invalid","1544007590","64","12345","12345","12345","12345","Active","unsigned"
        """
        self.manager.session.get.side_effect = [gd, gl]

        self.manager.get_domains()
        self.assertRaises(
            bookmyname.ZoneError,
            self.manager.set_domain_zone,
            'bookmyname.invalid',
            '@ CNAME xyz'
        )

        self.manager.session.post.assert_has_calls(
            [
                mock.call(
                    "https://www.bookmyname.com/login.cgi",
                    {
                        'handle': 'a_login',
                        'passwd': 'a_password'
                    }
                ),
                mock.call(
                    'https://www.bookmyname.com/manager.cgi?cmd=gdp&mode=1',
                    {
                        'domain': 'bookmyname.invalid',
                        'gdp_zonefile': '@ CNAME xyz',
                        'mode': 1,
                        'Submit': 'Valider'
                    }
                )
            ]
        )

        self.manager.session.get.assert_has_calls(
            [
                mock.call(
                    'https://www.bookmyname.com/manager.cgi?cmd=dld'
                ),
                mock.call(
                    'https://www.bookmyname.com/apis-cgi.cgi?'
                        'id=12345&pwd=a_password&fct=domain_list_ctc'
                )
            ]
        )


class BookMyNameClientTest(unittest.TestCase):

    def setUp(self):

        self.session = mock.MagicMock(spec=requests.session())

        # pylint: disable=protected-access
        self.bookmyname_client = bookmyname._BookMyNameClient(
            'a_login',
            'a_password',
            self.session
        )

        self.manager = mock.MagicMock(spec=self.bookmyname_client.manager)
        self.bookmyname_client.manager = self.manager

    def test_login_success(self):

        self.manager.get_domains.return_value = {'bookmyname.invalid'}

        self.bookmyname_client.login()

        self.manager.log_in.assert_called_once_with()
        self.manager.get_domains.assert_called_once_with()

    def test_login_log_in_failure(self):

        self.manager.log_in.side_effect = bookmyname.LoginError
        self.manager.get_domains.return_value = {'bookmyname.invalid'}

        self.assertRaises(
            errors.PluginError,
            self.bookmyname_client.login
        )

        self.manager.log_in.assert_called_once_with()
        self.manager.get_domains.assert_not_called()

    def test_login_domains_failure(self):

        self.manager.get_domains.side_effect = bookmyname.DomainError

        self.assertRaises(
            errors.PluginError,
            self.bookmyname_client.login
        )

        self.manager.log_in.assert_called_once_with()
        self.manager.get_domains.assert_called_once_with()

    def test_get_registered_domain_success(self):

        self.manager.get_domains.return_value = {'bookmyname.invalid'}

        self.assertEqual(
            self.bookmyname_client.get_registered_domain(
                'sub.bookmyname.invalid'
            ),
            'bookmyname.invalid'
        )

        self.assertEqual(
            self.bookmyname_client.get_registered_domain(
                'bookmyname.invalid'
            ),
            'bookmyname.invalid'
        )

        self.manager.get_domains.assert_called_once_with()

    def test_get_registered_domain_failure(self):
        self.manager.get_domains.return_value = {'bookmyname.invalid'}

        self.assertRaises(
            errors.PluginError,
            self.bookmyname_client.get_registered_domain,
            'bookmyname.not.invalid'
        )

    def test_add_txt_record_success(self):
        self.manager.get_domains.return_value = {'bookmyname.invalid'}
        self.manager.get_domain_zone.return_value = """
a 12345 CNAME b
b 67890 A 1.2.3.4
x 300 TXT "abcdef"
_acme_challenge 300 TXT "ABC123"
_acme_challenge.sub 300 TXT "DEF456"
""".strip()

        self.bookmyname_client.add_txt_record(
            'sub.bookmyname.invalid',
            '_acme_challenge.sub.bookmyname.invalid',
            'ghi789'
        )

        self.manager.set_domain_zone.assert_called_once_with(
            'bookmyname.invalid',
            """
a 12345 CNAME b
b 67890 A 1.2.3.4
x 300 TXT "abcdef"
_acme_challenge 300 TXT "ABC123"
_acme_challenge.sub 300 TXT "DEF456"
_acme_challenge.sub 300 TXT "ghi789"
""".strip()
        )

    def test_add_txt_record_failure_bad_domain(self):
        self.manager.get_domains.return_value = {'bookmyname.invalid'}
        self.manager.get_domain_zone.return_value = """
a 12345 CNAME b
b 67890 A 1.2.3.4
x 300 TXT "abcdef"
_acme_challenge 300 TXT "ABC123"
_acme_challenge.sub 300 TXT "DEF456"
""".strip()

        self.assertRaises(
            errors.PluginError,
            self.bookmyname_client.add_txt_record,
            'sub.bookmyname.not.invalid',
            '_acme_challenge.sub.bookmyname.not.invalid',
            'ghi789'
        )
        self.manager.set_domain_zone.assert_not_called()

    def test_add_txt_record_failure_other(self):
        self.manager.get_domains.return_value = {'bookmyname.invalid'}
        self.manager.get_domain_zone.return_value = """
a 12345 CNAME b
b 67890 A 1.2.3.4
x 300 TXT "abcdef"
_acme_challenge 300 TXT "ABC123"
_acme_challenge.sub 300 TXT "DEF456"
""".strip()
        self.manager.get_domain_zone.side_effect = bookmyname.DomainError

        self.assertRaises(
            errors.PluginError,
            self.bookmyname_client.add_txt_record,
            'sub.bookmyname.invalid',
            '_acme_challenge.sub.bookmyname.invalid',
            'ghi789'
        )

        self.manager.set_domain_zone.assert_not_called()

    def test_del_txt_record_success(self):
        self.manager.get_domains.return_value = {'bookmyname.invalid'}
        self.manager.get_domain_zone.return_value = """
a 12345 CNAME b
b 67890 A 1.2.3.4
x 300 TXT "abcdef"
_acme_challenge 300 TXT "ABC123"
_acme_challenge.sub 300 TXT "DEF456"
_acme_challenge.sub 300 TXT "ghi789"
""".strip()

        self.bookmyname_client.del_txt_record(
            'sub.bookmyname.invalid',
            '_acme_challenge.sub.bookmyname.invalid',
            'ghi789'
        )

        self.manager.set_domain_zone.assert_called_once_with(
            'bookmyname.invalid',
            """
a 12345 CNAME b
b 67890 A 1.2.3.4
x 300 TXT "abcdef"
_acme_challenge 300 TXT "ABC123"
_acme_challenge.sub 300 TXT "DEF456"
""".strip()
        )

    def test_del_txt_record_failure_bad_domain(self):
        self.manager.get_domains.return_value = {'bookmyname.invalid'}
        self.manager.get_domain_zone.return_value = """
a 12345 CNAME b
b 67890 A 1.2.3.4
x 300 TXT "abcdef"
_acme_challenge 300 TXT "ABC123"
""".strip()

        self.assertRaises(
            errors.PluginError,
            self.bookmyname_client.del_txt_record,
            'sub.bookmyname.not.invalid',
            '_acme_challenge.sub.bookmyname.not.invalid',
            'ghi789'
        )
        self.manager.set_domain_zone.assert_not_called()

    def test_del_txt_record_failure_other(self):
        self.manager.get_domains.return_value = {'bookmyname.invalid'}
        self.manager.get_domain_zone.return_value = """
a 12345 CNAME b
b 67890 A 1.2.3.4
x 300 TXT "abcdef"
_acme_challenge 300 TXT "ABC123"
_acme_challenge.sub 300 TXT "DEF456"
_acme_challenge.sub 300 TXT "ghi789"
""".strip()
        self.manager.get_domain_zone.side_effect = bookmyname.DomainError

        self.assertRaises(
            errors.PluginError,
            self.bookmyname_client.del_txt_record,
            'sub.bookmyname.invalid',
            '_acme_challenge.sub.bookmyname.invalid',
            'ghi789'
        )

        self.manager.set_domain_zone.assert_not_called()


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):

        super(AuthenticatorTest, self).setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write(
            {
                'bookmyname_login': 'a_login',
                'bookmyname_password': 'a_password'
            },
            path
        )

        self.credentials = mock.MagicMock(spec=CredentialsConfiguration,
                                     bookmyname_credentials=path,
                                     bookmyname_propagation_seconds=0)  # don't wait during tests
        self.credentials.conf.side_effect = ['a_login', 'a_password']

        self.auth = bookmyname.Authenticator(self.credentials, "bookmyname")

        # pylint: disable=protected-access
        self._configure_credentials = mock.MagicMock(
            spec=self.auth._configure_credentials
        )

        self.auth._configure_credentials = self._configure_credentials

        self.auth.credentials = self.credentials

        self.client = mock.MagicMock(spec=bookmyname._BookMyNameClient)

    def test_setup_credentials(self):

        # pylint: disable=protected-access
        self.auth._setup_credentials()
        self.auth._configure_credentials.assert_called_once_with(
            'credentials',
            'BookMyName credentials INI file',
            {
                'login': 'Login (ID) for BookMyName account',
                'password': 'Password for BookMyName account login/ID'
            }
        )

    def test_get_bookmyname_client_success(self):

        # pylint: disable=protected-access
        c = self.auth._get_bookmyname_client()
        self.assertTrue(isinstance(c, bookmyname._BookMyNameClient))
        self.credentials.conf.assert_has_calls(
            [
                mock.call('login'),
                mock.call('password'),
            ]
        )

    def test_perform(self):

        # pylint: disable=protected-access
        self.auth._get_bookmyname_client = mock.MagicMock()
        self.auth._get_bookmyname_client.return_value = self.client

        self.auth._perform(
            'bookmyname.invalid',
            '_acme_challenge.top.bookmyname.invalid',
            'ABCDefgh0123')

        self.client.add_txt_record.assert_called_once_with(
            'bookmyname.invalid',
            '_acme_challenge.top.bookmyname.invalid',
            'ABCDefgh0123')


    def test_cleanup(self):

        # pylint: disable=protected-access
        self.auth._get_bookmyname_client = mock.MagicMock()
        self.auth._get_bookmyname_client.return_value = self.client

        self.auth._cleanup(
            'bookmyname.invalid',
            '_acme_challenge.top.bookmyname.invalid',
            'ABCDefgh0123')

        self.client.del_txt_record.assert_called_once_with(
            'bookmyname.invalid',
            '_acme_challenge.top.bookmyname.invalid',
            'ABCDefgh0123')


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
