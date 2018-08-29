"""API Wrap for Dnspod."""
import logging
import requests

logger = logging.getLogger(__name__)

URL_PRE = "https://dnsapi.cn/"

def get_sub_domain(domain, sub_domain):
    """
    Remove base domain name from FQDN
    """
    # www.example.com => www
    # example.com => @
    # .example.com => @
    # *.example.com => *
    if sub_domain is not None:
        sub_domain = sub_domain.replace("." + domain, "").replace(domain, "")
    if sub_domain is None or sub_domain == "":
        sub_domain = "@"
    return sub_domain

class DnspodClientError(Exception):
    """
    Dnspod Exception
    """
    pass

class DnspodClient(object):
    """
    Encapsulates all communication with the Dnspod API.
    """

    def __init__(self, _id, token):
        self.token = _id + "," + token
        self._domain_list = None

    def request(self, url, data): # pragma: no cover
        """
        Communicate with Dnspod API
        """
        url = URL_PRE + url
        base_data = {}
        base_data["login_token"] = self.token
        base_data["format"] = "json"
        base_data["lang"] = "en"
        base_data["error_on_empty"] = "no"
        data.update(base_data)
        headers = {
            "User-Agent": "certbot-dns-dnspod/1.0.0 (liaohuqiu@gmail.com)"
        }
        ret = requests.post(url, data, headers=headers)
        data = self._fetch_from_response(url, data, ret)
        return data

    def _fetch_from_response(self, url, request_data, response): # pragma: no cover
        """
        Fetch valid data from response

        :param str url: The API url.
        :param dict request data: The request data.
        :param requests.Response response: Response Dnspod API.
        :returns: valid respone data
        :rtype: dict
        """
        response_data = {} # type: ignore
        if response is None:
            return response_data
        if response.status_code != 200:
            logger.error("http request fail, url: %s status_code: %s", url, response.status_code)
            raise DnspodClientError("http request fail, url: %s status_code: %s" % (url,
                response.status_code))
        try:
            response_data = response.json()
        except ValueError:
            logger.error("response is not json format, url: %s, respone text %s", url,
                    response.text)
            raise DnspodClientError("response is not json format, url: %s, respone text %s" %
                    (url, response.text))
        code = int(response_data.get("status", {}).get("code", 0))
        if code != 1:
            raise DnspodClientError(
                    "Unexpected status code: %s, url: %s request_data: %s, message: %s" %
                    (code, url, request_data, response.text))
        return response_data

    def get_record_list(self, domain, record_type):
        """
        Fetch all records for a given type and a given domain

        :param str domain: The domain name for which to find the records.
        :param str record_type: The record type to find.
        :returns: All the records.
        :rtype: list
        """
        url = "Record.List"
        data = {}
        data["domain"] = domain
        if record_type:
            data["record_type"] = record_type

        ret = self.request(url, data)
        return ret["records"]

    def add_record(self, domain, sub_domain, record_type, value):
        """
        Add a record
        """
        sub_domain = get_sub_domain(domain, sub_domain)

        url = "Record.Create"
        data = {}
        data["domain"] = domain
        data["sub_domain"] = sub_domain
        data["record_type"] = record_type
        data["value"] = value
        data["record_line_id"] = 0

        ret = self.request(url, data)
        return ret

    def modify_record(self, domain, record_id, record_type, value):
        """
        Modify a record value
        """
        url = "Record.Modify"
        data = {}
        data["domain"] = domain
        data["record_id"] = record_id
        data["record_type"] = record_type
        data["value"] = value
        data["record_line_id"] = 0

        self.request(url, data)
        return True

    def remove_record(self, domain, record_id):
        """
        Remove a record
        """
        url = "Record.Remove"
        data = {}
        data["domain"] = domain
        data["record_id"] = record_id

        ret = self.request(url, data)
        return ret

    def domain_list(self):
        """
        List all domains in this account
        """
        if not self._domain_list:
            url = "Domain.List"
            data = {}
            data["length"] = 3000
            ret = self.request(url, data)
            self._domain_list = {item["name"]: item for item in ret["domains"]}
        return self._domain_list

    def remove_record_by_sub_domain(self, domain, sub_domain, record_type):
        """
        Remove a record for a given sub domain and a given type
        """
        sub_domain = get_sub_domain(domain, sub_domain)
        record_list = self.get_record_list(domain, record_type)
        record_existent = next((item for item in record_list if item["name"] == sub_domain), None)
        if record_existent is None:
            return # pragma: no cover
        else:
            record_id = record_existent["id"]
            self.remove_record(domain, record_id)
        return record_id

    def ensure_record(self, domain, sub_domain, record_type, value):
        """
        Make sure a record will be set.
        """
        sub_domain = get_sub_domain(domain, sub_domain)

        record_list = self.get_record_list(domain, record_type)
        record_existent = next((item for item in record_list if item["name"] == sub_domain), None)
        if record_existent is None:
            record_created = self.add_record(domain, sub_domain, record_type, value)
            record_id = record_created["record"]["id"]
        else:
            record_id = record_existent["id"]
            self.modify_record(domain, record_id, record_type, value)
        return record_id
