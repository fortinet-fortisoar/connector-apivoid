""" Copyright start
  Copyright (C) 2008 - 2020 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from integrations.crudhub import maybe_json_or_raise
from connectors.core.connector import get_logger, ConnectorError
from connectors.cyops_utilities.builtins import download_file_from_cyops
import requests
import json
import socket
import validators
from requests_toolbelt.utils import dump

logger = get_logger('apivoid')

ENDPOINT = '/{}/v1/pay-as-you-go/'
endpoints_map = {
"threatlog":"host",
"domainbl":"host",
"iprep":"ip",
"screenshot":"url",
"urlrep":"url",
"domainage":"host",
"sitetrust":"host",
"parkeddomain":"host",
"urlstatus":"url",
"emailverify":"email",
"dnspropagation":"host",
"urltohtml":"url",
"sslinfo":"host"
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
    return True

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
    #logger.debug('{}\n{}\n{}\n{}\n'.format(server_url, api_key, verify_ssl,config))
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
        req_params.update({'key':api_key})
        api_response = requests.request(method=method, url=url, params=req_params, verify=verify_ssl)
        #logger.debug('\nreq data:\n{0}\n'.format(dump.dump_all(api_response).decode('utf-8')))
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


def _get_threat_intel(config, params):
    try:
        url_params = {}
        req_type = _get_input(params, "operation")
        req_value = _get_input(params, "req_value")
        if not validation_function_map[req_type](req_value):
            raise ConnectorError("Invalid {0} input paramter: {1}".format(req_type,req_value))
        if 'dnspropagation' in req_type:
            url_params.update({'dns_type':_get_input(params, "dns_record_type")})
        url_params.update({endpoints_map[req_type]:req_value})    
        return {"result":_api_request(ENDPOINT.format(req_type), config,url_params),
                "status": "Success"}
         
    except Exception as Err:
        logger.error(str(Err))
        raise ConnectorError(str(Err))   

def _check_health(config):
    try:
        result = _api_request(ENDPOINT.format("iprep")+'?stats', config,req_params={"ip":"1.1.1.1"})
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
"threatlog":_get_threat_intel,
"domainbl":_get_threat_intel,
"iprep":_get_threat_intel,
"screenshot":_get_threat_intel,
"urlrep":_get_threat_intel,
"domainage":_get_threat_intel,
"sitetrust":_get_threat_intel,
"parkeddomain":_get_threat_intel,
"urlstatus":_get_threat_intel,
"emailverify":_get_threat_intel,
"dnspropagation":_get_threat_intel,
"urltohtml":_get_threat_intel,
"sslinfo":_get_threat_intel 
}

validation_function_map = {
"threatlog":_is_valid_domain,
"domainbl":_is_valid_domain,
"iprep":_is_valid_ip,
"screenshot":_is_valid_url,
"urlrep":_is_valid_url,
"domainage":_is_valid_domain,
"sitetrust":_is_valid_domain,
"parkeddomain":_is_valid_domain,
"urlstatus":_is_valid_url,
"emailverify":_is_valid_email,
"dnspropagation":_is_valid_domain,
"urltohtml":_is_valid_url,
"sslinfo":_is_valid_domain
}