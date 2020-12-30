import datetime
import hashlib
import hmac
import json
import logging
import pathlib
import re
import urllib
import xml.etree.ElementTree as ET

import fire
import requests
import xmltodict

CANONICAL_URI = '/'
CONFIGURATION_FILE = 'config.json'
CONFIGURATION_FOLDER = '.osc_sdk'
DEFAULT_METHOD = 'POST'
DEFAULT_PROFILE = None
DEFAULT_REGION = 'eu-west-2'
DEFAULT_VERSION = datetime.date.today().strftime("%Y-%m-%d")
METHODS_SUPPORTED = ['GET', 'POST']
SDK_VERSION = '1.5'
SSL_VERIFY = True
SUCCESS_CODES = [200, 201, 202, 203, 204]
USER_AGENT = 'osc_sdk ' + SDK_VERSION

logger = logging.getLogger('osc_sdk')


class OscApiException(Exception):

    def __init__(self, http_response):
        super(OscApiException, self).__init__()
        self.status_code = http_response.status_code
        # Set error details
        self.error_code = None
        self.message = None
        self.request_id = None
        self._set(http_response)

    def __str__(self):
        return (
            'Error --> status = {}, code = {}, Reason = {}, request_id = '
            '{}'.format(self.status_code, self.error_code, self.message,
                        self.request_id))

    def _set(self, http_response):
        content = http_response.content.decode()
        # In case it is JSON error format
        try:
            error = json.loads(content)
        except json.JSONDecodeError:
            pass
        else:
            if '__type' in error:
                self.error_code = error.get('__type')
                self.message = error.get('message')
                self.request_id = http_response.headers.get('x-amz-requestid')
            else:
                self.request_id = (error.get('ResponseContext') or {}
                                   ).get('RequestId')
                errors = error.get('Errors')
                if errors:
                    error = errors[0]
                    self.error_code = error.get('Code')
                    self.message = error.get('Type')
            return

        # In case it is XML format
        try:
            error = ET.fromstring(content)
        except ET.ParseError:
            return
        else:
            for key, attr in [('Code', 'error_code'),
                              ('Message', 'message'),
                              ('RequestId', 'request_id'),
                              ('RequestID', 'request_id')]:
                value = next((x.text
                              for x in error.iter()
                              if x.tag.endswith(key)),
                             None)
                if value:
                    setattr(self, attr, value)


class ApiCall(object):
    API_NAME = None
    CONTENT_TYPE = 'application/x-www-form-urlencoded'
    REQUEST_TYPE = 'aws4_request'
    SIG_ALGORITHM = 'AWS4-HMAC-SHA256'
    SIG_TYPE = 'AWS4'

    def __init__(self, **kwargs):
        self.method = kwargs.pop('method', DEFAULT_METHOD)
        self.access_key = kwargs.pop('access_key')
        self.secret_key = kwargs.pop('secret_key')
        self.version = kwargs.pop('version', DEFAULT_VERSION)
        self.protocol = 'https' if kwargs.pop('https', None) else 'http'
        self.region = kwargs.pop('region_name', DEFAULT_REGION)
        self.ssl_verify = kwargs.pop('ssl_verify', SSL_VERIFY)
        self.client_certificate = kwargs.get('client_certificate')
        endpoint, host = (kwargs.get(x) for x in ['endpoint', 'host'])
        if endpoint:
            self.endpoint = endpoint
        elif host:
            self.endpoint = '.'.join([self.API_NAME, self.region, host])

        self.response = None
        # These wil be set in _set_datestamp
        self.date = None
        self.datestamp = None

    @property
    def endpoint(self):
        return self.__endpoint

    @property
    def host(self):
        return self.__host

    @endpoint.setter
    def endpoint(self, value):
        parsed_url = urllib.parse.urlparse(value)
        if parsed_url.scheme:
            self.__endpoint = value
            self.__host = parsed_url.netloc
        else:
            self.__endpoint = '{}://{}'.format(self.protocol, value)
            self.__host = value

    @property
    def method(self):
        return self._method

    @method.setter
    def method(self, method):
        if method not in METHODS_SUPPORTED:
            raise Exception(
                'Wrong method {}. Supported: {}.'.format(method,
                                                         METHODS_SUPPORTED)
            )
        self._method = method

    def _set_datestamp(self):
        date = datetime.datetime.utcnow()
        self.date = date.strftime('%Y%m%dT%H%M%SZ')
        self.datestamp = date.strftime('%Y%m%d')

    def get_url(self, call, request_params=None):
        value = self.endpoint
        if self.method == 'GET':
            value += '?{}'.format(request_params)
        return value

    def get_canonical_uri(self, call):
        return CANONICAL_URI

    def get_authorization_header(self, canonical_request, signed_headers):
        credentials = [self.datestamp, self.region, self.API_NAME,
                       self.REQUEST_TYPE]
        credential_scope = '/'.join(credentials)
        string_to_sign = '\n'.join(
            [
                self.SIG_ALGORITHM,
                self.date,
                credential_scope,
                hashlib.sha256(canonical_request.encode('utf-8')).hexdigest(),
            ]
        )
        key = (self.SIG_TYPE + self.secret_key).encode('utf-8')
        for msg in credentials:
            key = hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
        signature = hmac.new(key,
                             string_to_sign.encode('utf-8'),
                             hashlib.sha256).hexdigest()

        return (
            '{} Credential={}/{}, SignedHeaders={}, Signature={}'.format(
                self.SIG_ALGORITHM,
                self.access_key,
                credential_scope,
                signed_headers,
                signature)
        )

    def get_response(self, request):
        raise NotImplementedError

    def get_parameters(self, data, prefix=''):
        ret = {}
        if isinstance(data, list):
            if prefix:
                prefix += '.'
            for i, value in enumerate(data, start=1):
                ret.update(self.get_parameters(value, prefix + str(i)))
            return ret
        if isinstance(data, dict):
            if prefix:
                prefix += '.'
            for key, value in data.items():
                ret.update(self.get_parameters(value, prefix + key))
            return ret
        if data is not None:
            if data == '':
                return {prefix: ''}
            return {prefix: str(data)}

    def make_request(self, call, *args, **kwargs):
        self._set_datestamp()

        # Calculate request params
        request_params = self.get_parameters(data=kwargs)
        request_params['Action'] = call
        if 'Version' not in request_params:
            request_params['Version'] = self.version
        request_params = urllib.parse.urlencode(request_params)

        # Calculate URL before request_params value is modified
        url = self.get_url(call, request_params)

        if self.method == 'GET':
            headers = {
                'host': self.host,
                'x-amz-date': self.date,
            }
            payload_hash = hashlib.sha256(''.encode('utf-8')).hexdigest()
            canonical_params = request_params
            request_params = None
        else:
            headers = {
                'content-type': self.CONTENT_TYPE,
                'host': self.host,
                'x-amz-date': self.date,
                'x-amz-target':
                    '{}_{}.{}'.format(self.API_NAME,
                                      datetime.date.today().strftime('%Y%m%d'),
                                      call),
            }

            payload_hash = (
                hashlib.sha256(request_params.encode('utf-8')).hexdigest()
            )
            canonical_params = ''

        canonical_headers = ''.join('{}:{}\n'.format(k, v)
                                    for k, v in headers.items())
        signed_headers = ';'.join(headers)
        canonical_request = '\n'.join(
            [
                self.method,
                self.get_canonical_uri(call),
                canonical_params,
                canonical_headers,
                signed_headers,
                payload_hash,
            ]
        )

        authorization_header = self.get_authorization_header(
            canonical_request,
            signed_headers,
        )

        headers.update({
            'Authorization': authorization_header,
            'User-agent': USER_AGENT,
        })

        self.response = self.get_response(
            requests.request(
                cert=self.client_certificate,
                data=request_params,
                headers=headers,
                method=self.method,
                url=url,
                verify=self.ssl_verify
            )
        )


class FcuCall(ApiCall):
    API_NAME = 'fcu'

    def get_response(self, http_response):
        if http_response.status_code not in SUCCESS_CODES:
            raise OscApiException(http_response)
        try:
            response = xmltodict.parse(http_response.content)
        except Exception:
            response = "Unable to parse response: '{}'".format(http_response.text)
        return response


class LbuCall(FcuCall):
    API_NAME = 'lbu'

    def get_parameters(self, data, prefix=''):
        ret = {}
        if isinstance(data, list):
            if prefix:
                prefix += '.member.'
            i = 1
            for value in data:
                ret.update(self.get_parameters(value, prefix + str(i)))
            return ret
        if isinstance(data, dict):
            if prefix:
                prefix += '.'
            for key, value in data.items():
                ret.update(self.get_parameters(value, prefix + key))
            return ret
        if data is not None:
            if data == '':
                return {prefix: ''}
            return {prefix: str(data)}


class EimCall(FcuCall):
    API_NAME = 'eim'

    def get_parameters(self, data):
        if isinstance(data, dict):
            policy_document = data.get('PolicyDocument')
            if policy_document:
                data['PolicyDocument'] = json.dumps(policy_document)
        return data


class JsonApiCall(ApiCall):
    SERVICE = ''
    CONTENT_TYPE = 'application/x-amz-json-1.1'

    def get_parameters(self, data, call):
        return data

    def get_response(self, http_response):
        if http_response.status_code not in SUCCESS_CODES:
            raise OscApiException(http_response)

        return json.loads(http_response.text)

    def build_headers(self, target, json_parameters):
        signed_headers = 'host;x-amz-date;x-amz-target'
        canonical_headers = (
            'host:{}\n'
            'x-amz-date:{}\n'
            'x-amz-target:{}\n'.format(self.host, self.date, target)
        )
        headers = {
            'content-type': self.CONTENT_TYPE,
            'x-amz-date': self.date,
            'x-amz-target': target,
            'User-agent': USER_AGENT,
            'content-length': str(len(json_parameters)),
        }
        return signed_headers, canonical_headers, headers

    def make_request(self, call, *args, **kwargs):
        self._set_datestamp()

        request_params = self.get_parameters(kwargs, call)
        json_params = json.dumps(request_params)

        target = '.'.join([self.SERVICE, call])

        signed_headers, canonical_headers, headers = self.build_headers(
            target, json_params)

        canonical_request = '\n'.join(
            [
                'POST',
                self.get_canonical_uri(call),
                '',
                canonical_headers,
                signed_headers,
                hashlib.sha256(json_params.encode('utf-8')).hexdigest(),
            ]
        )

        if (
            not request_params.get('AuthenticationMethod')
            or request_params['AuthenticationMethod'] == 'accesskey'
        ):
            headers['Authorization'] = self.get_authorization_header(
                canonical_request,
                signed_headers,
            )

        self.response = self.get_response(
            requests.request(
                cert=self.client_certificate,
                data=json_params,
                headers=headers,
                method=self.method,
                url=self.get_url(call),
                verify=self.ssl_verify,
            )
        )


class IcuCall(JsonApiCall):
    API_NAME = 'icu'
    SERVICE = 'TinaIcuService'
    FILTERS_NAME_PATTERN = re.compile('^Filters.([0-9]*).Name$')
    FILTERS_VALUES_STR = '^Filters.%s.Values.[0-9]*$'

    def get_parameters(self, data, call):
        auth = data.pop('authentication_method', 'accesskey')
        if auth not in {'accesskey', 'password'}:
            raise RuntimeError('Bad authentication method {}'.format(auth))
        if auth == 'password':
            try:
                data.update({
                    'Login': data.pop('login'),
                    'Password': data.pop('password'),
                })
            except KeyError:
                raise RuntimeError('Missing login and/or password, yet '
                                   'password authentication has been '
                                   'required')

        filters = self.get_filters(data)
        data = {k: v for k, v in data.items() if not k.startswith('Filters.')}
        return {'Action': call,
                'AuthenticationMethod': auth,
                'Filters': filters,
                'Version': self.version,
                **data}

    def get_filters(self, data):
        filters = []
        for k, v in data.items():
            match = re.search(self.FILTERS_NAME_PATTERN, k)
            if match:
                value_pattern = re.compile(self.FILTERS_VALUES_STR
                                           % match.group(1))
                values = [v for k, v in data.items()
                          if re.match(value_pattern, k)]
                if values:
                    filters.append({
                        'Name': v,
                        'Values': values,
                    })
        return filters


class DirectLinkCall(JsonApiCall):
    API_NAME = 'directlink'
    SERVICE = 'OvertureService'

    def get_response(self, http_response):
        if http_response.status_code not in SUCCESS_CODES:
            raise OscApiException(http_response)

        res = json.loads(http_response.text)
        res['requestid'] = http_response.headers['x-amz-requestid']
        return res


class OKMSCall(JsonApiCall):
    API_NAME = 'kms'
    SERVICE = 'TrentService'


class OSUCall(ApiCall):
    SERVICE = 'osu2'
    API_NAME = 'iam'

    def get_response(self, http_response):
        if http_response.status_code not in SUCCESS_CODES:
            raise OscApiException(http_response)
        return http_response.content.decode()


class OSCCall(JsonApiCall):
    API_NAME = 'api'
    CONTENT_TYPE = 'application/json'
    REQUEST_TYPE = 'osc4_request'
    SIG_ALGORITHM = 'OSC4-HMAC-SHA256'
    SIG_TYPE = 'OSC4'
    SERVICE = 'OutscaleService'

    def get_parameters(self, data, call):
        parameters = {}
        for k, v in data.items():
            self.format_data(parameters, k, v)
        return parameters

    def format_data(self, parameters, key, value):
        if '.' in key:
            head_key, queue_key = key.split('.', 1)
            parameters.setdefault(head_key, {})
            self.format_data(parameters[head_key], queue_key, value)
        else:
            parameters[key] = (
                value[1:-1].split(',')
                if isinstance(value, str) and value.startswith('[')
                else value
            )

    def get_canonical_uri(self, call):
        return '/{}/latest/{}'.format(self.API_NAME, call)

    def get_url(self, call, request_params=None):
        return '/'.join([self.endpoint, self.get_canonical_uri(call)])

    def build_headers(self, target, json_parameters):
        signed_headers = 'host;x-osc-date;x-osc-target'
        canonical_headers = (
            'host:{}\n'
            'x-osc-date:{}\n'
            'x-osc-target:{}\n'.format(self.host, self.date, target)
        )
        headers = {
            'Content-Type': self.CONTENT_TYPE,
            'User-agent': USER_AGENT,
            'X-Osc-Date': self.date,
            'x-osc-target': target,
        }
        return signed_headers, canonical_headers, headers


def get_conf(profile):
    conf_path = pathlib.Path.home() / CONFIGURATION_FOLDER / CONFIGURATION_FILE
    if not conf_path.exists():
        raise RuntimeError('No configuration file found in home folder')

    conf = json.loads(conf_path.read_text())
    try:
        return conf[profile]
    except KeyError:
        raise RuntimeError('Profile {} not found in configuration file'.format(profile))


def api_connect(service, call, profile='default', *args, **kwargs):
    calls = {
        'api': OSCCall,
        'directlink': DirectLinkCall,
        'eim': EimCall,
        'fcu': FcuCall,
        'icu': IcuCall,
        'lbu': LbuCall,
        'okms': OKMSCall,
        'oos': OSUCall,
    }
    conf = get_conf(profile)
    handler = calls[service](**conf)
    handler.make_request(call, *args, **kwargs)
    if handler.response:
        print(json.dumps(handler.response, indent=4))


def main():
    logging.basicConfig(level=logging.ERROR)
    fire.Fire(api_connect)


if __name__ == '__main__':
    main()
