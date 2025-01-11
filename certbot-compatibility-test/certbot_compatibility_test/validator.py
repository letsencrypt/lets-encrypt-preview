"""Validators to determine the current webserver configuration"""
import logging
import socket
from typing import cast
from typing import Mapping
from typing import Optional
from typing import Union

from cryptography import x509
import requests

from acme import crypto_util
from acme import errors as acme_errors

logger = logging.getLogger(__name__)


_VALIDATION_TIMEOUT = 10


class Validator:
    """Collection of functions to test a live webserver's configuration"""

    def certificate(self, cert: x509.Certificate, name: Union[str, bytes],
                    alt_host: Optional[str] = None, port: int = 443) -> bool:
        """Verifies the certificate presented at name is cert"""
        if alt_host is None:
            # In fact, socket.gethostbyname accepts both bytes and str, but types do not know that.
            host = socket.gethostbyname(cast(str, name)).encode()
        elif isinstance(alt_host, bytes):
            host = alt_host
        else:
            host = alt_host.encode()
        name = name if isinstance(name, bytes) else name.encode()

        try:
            presented_cert = crypto_util.probe_sni(name, host, port).to_cryptography()
        except acme_errors.Error as error:
            logger.exception(str(error))
            return False

        return presented_cert == cert

    def redirect(self, name: str, port: int = 80,
                 headers: Optional[Mapping[str, str]] = None) -> bool:
        """Test whether webserver redirects to secure connection."""
        url = "http://{0}:{1}".format(name, port)
        if headers:
            response = requests.get(url, headers=headers,
                                    allow_redirects=False,
                                    timeout=_VALIDATION_TIMEOUT)
        else:
            response = requests.get(url, allow_redirects=False,
                                    timeout=_VALIDATION_TIMEOUT)

        redirect_location = response.headers.get("location", "")
        # We're checking that the redirect we added behaves correctly.
        # It's okay for some server configuration to redirect to an
        # http URL, as long as it's on some other domain.
        if not redirect_location.startswith("https://"):
            return False

        if response.status_code != 301:
            logger.error("Server did not redirect with permanent code")
            return False

        return True

    def any_redirect(self, name: str, port: int = 80,
                     headers: Optional[Mapping[str, str]] = None) -> bool:
        """Test whether webserver redirects."""
        url = "http://{0}:{1}".format(name, port)
        if headers:
            response = requests.get(url, headers=headers,
                                    allow_redirects=False,
                                    timeout=_VALIDATION_TIMEOUT)
        else:
            response = requests.get(url, allow_redirects=False,
                                    timeout=_VALIDATION_TIMEOUT)

        return response.status_code in range(300, 309)

    def hsts(self, name: str) -> bool:
        """Test for HTTP Strict Transport Security header"""
        headers = requests.get("https://" + name,
                               timeout=_VALIDATION_TIMEOUT).headers
        hsts_header = headers.get("strict-transport-security")

        if not hsts_header:
            return False

        # Split directives following RFC6797, section 6.1
        directives = [d.split("=") for d in hsts_header.split(";")]
        max_age = [d for d in directives if d[0] == "max-age"]

        if not max_age:
            logger.error("Server responded with invalid HSTS header field")
            return False

        try:
            max_age_value = int(max_age[0][1])
        except ValueError:
            logger.error("Server responded with invalid HSTS header field")
            return False

        # Test whether HSTS does not expire for at least two weeks.
        if max_age_value <= (2 * 7 * 24 * 3600):
            logger.error("HSTS should not expire in less than two weeks")
            return False

        return True

    def ocsp_stapling(self, name: str) -> None:
        """Verify ocsp stapling for domain."""
        raise NotImplementedError()
