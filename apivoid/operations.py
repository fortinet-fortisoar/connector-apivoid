""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from integrations.crudhub import maybe_json_or_raise
from connectors.core.connector import get_logger, ConnectorError
from django.conf import settings
from integrations.crudhub import make_request
import requests
import socket
import validators
import os

logger = get_logger('apivoid')

TMP_LOC = os.path.dirname(os.path.realpath(__file__)) + "/apivoid"
ENDPOINT = '/{}/v1/pay-as-you-go/'
MACRO_LIST = ["IP_Enrichment_Playbooks_IRIs", "URL_Enrichment_Playbooks_IRIs", "Domain_Enrichment_Playbooks_IRIs",
              "Email_Enrichment_Playbooks_IRIs"]
CONNECTOR_NAME = "apivoid"
endpoints_map = {
    "threatlog": "host",
    "domainbl": "host",
    "iprep": "ip",
    "screenshot": "url",
    "urlrep": "url",
    "domainage": "host",
    "sitetrust": "host",
    "parkeddomain": "host",
    "urlstatus": "url",
    "emailverify": "email",
    "dnspropagation": "host",
    "urltohtml": "url",
    "sslinfo": "host"
}


def _is_valid_domain(domain):
    """Returns True if input string is a valid domain or fqdn (domain.com)."""
    return validators.domain(domain)


def _is_valid_url(url):
    """Returns True if input string is a valid url (http://domain.com)."""
    return validators.url(url)


def _is_valid_email(email):
    """Returns True if input string is a valid email (someone@domain.com)."""
    return validators.email(email)


def _is_valid_ip(ip):
    """Returns True if input string is ipv4/ipv6."""
    if not ip or "\x00" in ip:
        return False
    try:
        res = socket.getaddrinfo(
            ip, 0, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, socket.AI_NUMERICHOST
        )
        return bool(res)
    except socket.gaierror as e:
        if e.args[0] == socket.EAI_NONAME:
            return False
        raise ConnectorError(e)


def _get_input(params, key, type=str):
    ret_val = params.get(key, None)
    if ret_val:
        if isinstance(ret_val, bytes):
            ret_val = ret_val.decode('utf-8')
        if isinstance(ret_val, type):
            return ret_val
        else:
            logger.info(
                "Parameter Input Type is Invalid: Parameter is: {0}, Required Parameter Type"
                " is: {1}".format(str(key), str(type)))
            raise ConnectorError("Parameter Input Type is Invalid: Parameter is: {0}, Required "
                                 "Parameter Type is: {1}".format(str(key), str(type)))
    else:
        if ret_val == {} or ret_val == [] or ret_val == 0:
            return ret_val
        return None


def _get_config(config):
    verify_ssl = config.get("verify_ssl", None)
    server_url = _get_input(config, "server")
    api_key = _get_input(config, "api_key")
    # logger.debug('{}\n{}\n{}\n{}\n'.format(server_url, api_key, verify_ssl,config))
    if server_url[:7] != 'http://' and server_url[:8] != 'https://':
        server_url = 'https://{}'.format(server_url)
    return server_url, api_key, verify_ssl


def _api_request(endpoint, config, req_params=None, method='get'):
    ''' returns json or str '''
    try:
        server_url, api_key, verify_ssl = _get_config(config)
        url = server_url + endpoint
        if req_params is None:
            req_params = {}
        req_params.update({'key': api_key})
        api_response = requests.request(method=method, url=url, params=req_params, verify=verify_ssl)
        logger.debug("api_response: response_code :{0}  response_message:{1}".format(api_response.status_code,
                                                                                     api_response.text))
        response = maybe_json_or_raise(api_response)
        if 'error' not in response:
            return response
        else:
            logger.error('Fail To request API \n{0}\n response is : \n{1}\n'.
                         format(str(url), response))
            raise ConnectorError('Fail To request API \n{0}\n response is : \n{1}\n'.
                                 format(str(url), response))
    except Exception as Err:
        raise ConnectorError(Err)


def upload_file_to_cyops(file_name, file_content, file_description):
    try:
        # Conditional import based on the FortiSOAR version.
        try:
            from integrations.crudhub import make_file_upload_request
            response = make_file_upload_request(file_name, file_content, 'application/octet-stream')

        except:
            from cshmac.requests import HmacAuth
            from integrations.crudhub import maybe_json_or_raise
            from requests import post

            url = settings.CRUD_HUB_URL + '/api/3/files'
            auth = HmacAuth(url, 'POST', settings.APPLIANCE_PUBLIC_KEY,
                            settings.APPLIANCE_PRIVATE_KEY,
                            settings.APPLIANCE_PUBLIC_KEY.encode('utf-8'))
            files = {'file': (file_name, file_content, {'Expire': 0})}
            response = post(url, auth=auth, files=files, verify=False)
            response = maybe_json_or_raise(response)

        logger.info('File upload complete {0}'.format(str(response)))
        file_id = response['@id']
        attach_response = make_request('/api/3/attachments', 'POST',
                                       {'name': file_name, 'file': file_id, 'description': file_description})
        logger.info('attach file completed: {0}'.format(attach_response))
        return attach_response
    except Exception as err:
        logger.exception('An exception occurred {0}'.format(str(err)))
        raise ConnectorError('An exception occurred {0}'.format(str(err)))


def handle_upload_file_to_cyops(file_details, file_path):
    try:
        file_name = file_details.get("file_name")
        file_description = file_details.get("file_description")
        file_content = open(file_path, "rb")
        attach_response = upload_file_to_cyops(file_name, file_content, file_description)
        logger.debug('{0}'.format(str(type(attach_response))))
        os.remove(file_path)
        return attach_response
    except Exception as err:
        os.remove(file_path)
        logger.exception('An exception occurred {0}'.format(str(err)))
        raise ConnectorError('An exception occurred {0}'.format(str(err)))


def _save_file(filename, response):
    tmp_path = TMP_LOC
    import base64
    imgdata = base64.b64decode(response)
    if not os.path.isdir(tmp_path):
        os.mkdir(tmp_path)
    with open("{0}/{1}".format(tmp_path, filename), "wb") as file_to_write:
        file_to_write.write(imgdata)
    return "{0}/{1}".format(tmp_path, filename)


def _get_threat_intel(config, params):
    try:
        url_params = {}
        req_type = _get_input(params, "operation")
        req_value = _get_input(params, "req_value")
        if not validation_function_map[req_type](req_value):
            raise ConnectorError("Invalid {0} input paramter: {1}".format(req_type, req_value))
        if 'dnspropagation' in req_type:
            url_params.update({'dns_type': _get_input(params, "dns_record_type")})
        url_params.update({endpoints_map[req_type]: req_value})
        return {"result": _api_request(ENDPOINT.format(req_type), config, url_params),
                "status": "Success"}
    except Exception as Err:
        logger.error(str(Err))
        raise ConnectorError(str(Err))


def get_screenshot(config, params):
    try:
        req_value = _get_input(params, "req_value")
        resp = _get_threat_intel(config, params)
        # add file in attachment module
        file_name = req_value.split("/")[2] + ".png"
        file_details = {
            "file_name": file_name,
            "file_description": "apivoid- Screenshot captured for URL {0}".format(req_value)
        }
        temp_path = _save_file(file_name, resp['result']['data']['base64_file'])
        attachment_resp = handle_upload_file_to_cyops(file_details, temp_path)
        return attachment_resp
    except Exception as Err:
        logger.error(str(Err))
        raise ConnectorError(str(Err))


def _check_health(config):
    try:
        result = _api_request(ENDPOINT.format("iprep") + '?stats', config, req_params={"ip": "1.1.1.1"})
        if result:
            return True
        else:
            return False
    except Exception as err:
        if "Max retries exceeded with url" in str(err):
            raise ConnectorError("Invalid Server URL")
        elif "Fail To request API" in str(err):
            raise ConnectorError("Invalid API Key")
        else:
            raise ConnectorError(str(err))


operations = {
    "threatlog": _get_threat_intel,
    "domainbl": _get_threat_intel,
    "iprep": _get_threat_intel,
    "screenshot": get_screenshot,
    "urlrep": _get_threat_intel,
    "domainage": _get_threat_intel,
    "sitetrust": _get_threat_intel,
    "parkeddomain": _get_threat_intel,
    "urlstatus": _get_threat_intel,
    "emailverify": _get_threat_intel,
    "dnspropagation": _get_threat_intel,
    "urltohtml": _get_threat_intel,
    "sslinfo": _get_threat_intel
}

validation_function_map = {
    "threatlog": _is_valid_domain,
    "domainbl": _is_valid_domain,
    "iprep": _is_valid_ip,
    "screenshot": _is_valid_url,
    "urlrep": _is_valid_url,
    "domainage": _is_valid_domain,
    "sitetrust": _is_valid_domain,
    "parkeddomain": _is_valid_domain,
    "urlstatus": _is_valid_url,
    "emailverify": _is_valid_email,
    "dnspropagation": _is_valid_domain,
    "urltohtml": _is_valid_url,
    "sslinfo": _is_valid_domain
}
