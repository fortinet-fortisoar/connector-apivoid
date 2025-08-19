"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

import requests, json
import os
from integrations.crudhub import make_request
from django.conf import settings
from integrations.crudhub import maybe_json_or_raise
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('apivoid')

TMP_LOC = os.path.dirname(os.path.realpath(__file__)) + "/apivoid"
MACRO_LIST = ["IP_Enrichment_Playbooks_IRIs", "URL_Enrichment_Playbooks_IRIs", "Domain_Enrichment_Playbooks_IRIs",
              "Email_Enrichment_Playbooks_IRIs"]

class APIVoid(object):
    def __init__(self, config, *args, **kwargs):
        self.api_key = config.get('api_key')
        url = config.get('server').strip('/')
        if not url.startswith('https://') and not url.startswith('http://'):
            self.url = 'https://{0}/v2/'.format(url)
        else:
            self.url = url + '/v2/'
        self.verify_ssl = config.get('verify_ssl')

    def make_rest_call(self, endpoint, method, data=None, params=None):
        try:
            url = self.url + endpoint
            headers = {
                'X-API-Key': self.api_key,
                'Content-Type': 'application/json'
            }
            logger.debug("Endpoint {0}".format(url))
            response = requests.request(method, url, data=data, params=params,
                                        headers=headers, verify=self.verify_ssl)
            logger.debug("response_content {0}:{1}".format(response.status_code, response.content))
            if response.ok or response.status_code == 204:
                logger.info('Successfully got response for url {0}'.format(url))
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response
            else:
                logger.error("{0}".format(response.status_code))
                raise ConnectorError("{0}:{1}".format(response.status_code, response.text))
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid Credentials')
        except Exception as err:
            raise ConnectorError(str(err))


def check_payload(payload):
    updated_payload = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            nested = check_payload(value)
            if len(nested.keys()) > 0:
                updated_payload[key] = nested
        elif value != '' and value is not None:
            updated_payload[key] = value
    return updated_payload


def get_domain_reputation(config, params):
    try:
        av = APIVoid(config)
        endpoint = 'domain-reputation'
        payload = {
            "host": params.get('req_value')
        }
        payload = check_payload(payload)
        logger.debug("Payload {0}".format(payload))
        response = av.make_rest_call(endpoint, 'POST', data=json.dumps(payload))
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_ip_reputation(config, params):
    try:
        av = APIVoid(config)
        endpoint = 'ip-reputation'
        payload = {
            "ip": params.get('req_value')
        }
        payload = check_payload(payload)
        logger.debug("Payload {0}".format(payload))
        response = av.make_rest_call(endpoint, 'POST', data=json.dumps(payload))
        return response
    except Exception as err:
        raise ConnectorError(str(err))

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

def get_url_screenshot(config, params):
    try:
        av = APIVoid(config)
        endpoint = 'screenshot'
        payload = {
            "url": params.get('req_value')
        }
        payload = check_payload(payload)
        logger.debug("Payload {0}".format(payload))
        resp = av.make_rest_call(endpoint, 'POST', data=json.dumps(payload))
        file_name = params.get('req_value').split("/")[2] + ".png"
        file_details = {
            "file_name": file_name,
            "file_description": "APIVoid- Screenshot captured for URL {0}".format(params.get('req_value'))
        }
        temp_path = _save_file(file_name, resp['rendered_file']['base64_file'])
        attachment_resp = handle_upload_file_to_cyops(file_details, temp_path)
        return attachment_resp
    except Exception as err:
        raise ConnectorError(str(err))


def get_url_reputation(config, params):
    try:
        av = APIVoid(config)
        endpoint = 'url-reputation'
        payload = {
            "url": params.get('req_value')
        }
        payload = check_payload(payload)
        logger.debug("Payload {0}".format(payload))
        response = av.make_rest_call(endpoint, 'POST', data=json.dumps(payload))
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_domain_age(config, params):
    try:
        av = APIVoid(config)
        endpoint = 'domain-age'
        payload = {
            "host": params.get('req_value')
        }
        payload = check_payload(payload)
        logger.debug("Payload {0}".format(payload))
        response = av.make_rest_call(endpoint, 'POST', data=json.dumps(payload))
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_domain_trustworthiness(config, params):
    try:
        av = APIVoid(config)
        endpoint = 'site-trust'
        payload = {
            "host": params.get('req_value')
        }
        payload = check_payload(payload)
        logger.debug("Payload {0}".format(payload))
        response = av.make_rest_call(endpoint, 'POST', data=json.dumps(payload))
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_domain_parked_status(config, params):
    try:
        av = APIVoid(config)
        endpoint = 'parked-domain'
        payload = {
            "host": params.get('req_value')
        }
        payload = check_payload(payload)
        logger.debug("Payload {0}".format(payload))
        response = av.make_rest_call(endpoint, 'POST', data=json.dumps(payload))
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_url_status(config, params):
    try:
        av = APIVoid(config)
        endpoint = 'url-status'
        payload = {
            "url": params.get('req_value')
        }
        payload = check_payload(payload)
        logger.debug("Payload {0}".format(payload))
        response = av.make_rest_call(endpoint, 'POST', data=json.dumps(payload))
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_email_reputation(config, params):
    try:
        av = APIVoid(config)
        endpoint = 'email-verify'
        payload = {
            "email": params.get('req_value')
        }
        payload = check_payload(payload)
        logger.debug("Payload {0}".format(payload))
        response = av.make_rest_call(endpoint, 'POST', data=json.dumps(payload))
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_dns_propagation(config, params):
    try:
        av = APIVoid(config)
        endpoint = 'dns-propagation'
        payload = {
            "host": params.get('req_value'),
            "dns_types": params.get('dns_record_type')
        }
        payload = check_payload(payload)
        logger.debug("Payload {0}".format(payload))
        response = av.make_rest_call(endpoint, 'POST', data=json.dumps(payload))
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_ssl_info(config, params):
    try:
        av = APIVoid(config)
        endpoint = 'ssl-info'
        payload = {
            "host": params.get('req_value')
        }
        payload = check_payload(payload)
        logger.debug("Payload {0}".format(payload))
        response = av.make_rest_call(endpoint, 'POST', data=json.dumps(payload))
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def execute_an_api_call(config, params):
    try:
        av = APIVoid(config)
        endpoint = params.get("endpoint")
        http_method = params.get("method")
        query_params = params.get("query_params") if params.get("query_params") else {}
        payload = params.get("payload") if params.get("payload") else {}
        logger.debug("Payload: {0}".format(payload))
        response = av.make_rest_call(endpoint, method=http_method, params=query_params, data=json.dumps(payload))
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def _check_health(config):
    try:
        response = get_domain_age(config, params={"req_value": "google.com"})
        if response:
            return True
    except Exception as err:
        logger.info(str(err))
        raise ConnectorError(str(err))


operations = {
    'get_domain_reputation': get_domain_reputation,
    'get_ip_reputation': get_ip_reputation,
    'get_url_screenshot': get_url_screenshot,
    'get_url_reputation': get_url_reputation,
    'get_domain_age': get_domain_age,
    'get_domain_trustworthiness': get_domain_trustworthiness,
    'get_domain_parked_status': get_domain_parked_status,
    'get_url_status': get_url_status,
    'get_email_reputation': get_email_reputation,
    'get_dns_propagation': get_dns_propagation,
    'get_ssl_info': get_ssl_info,
    'execute_an_api_call': execute_an_api_call
}