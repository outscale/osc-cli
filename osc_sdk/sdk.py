import datetime
import hashlib
import hmac
import json
import logging
import pathlib
import urllib

import fire
import requests
import xmltodict

SDK_VERSION = '0.1'
USER_AGENT = 'osc_sdk ' + SDK_VERSION
CONFIGURATION_FOLDER = '.osc_sdk'
CONFIGURATION_FILE = 'config.json'

SSL_VERIFY = True
DEFAULT_METHOD = 'POST'
DEFAULT_PROFILE = None
DEFAULT_REGION = 'eu-west-2'
DEFAULT_VERSION = datetime.date.today().strftime("%Y-%m-%d")
SUCCESS_CODES = [200, 201, 202, 203, 204]

SIG_ALGORITHM = 'AWS4-HMAC-SHA256'
CANONICAL_URI = '/'

logger = logging.getLogger('osc_sdk')


class OscApiException(Exception):

    def __init__(self, http_response, stack=None):
        super(OscApiException, self).__init__()
        self.status_code = http_response.status_code
        self.error_code = None
        self.message = None
        self.request_id = None
        self.stack = stack
        self.response = http_response.text
        if hasattr(self.response, 'Errors'):
            if hasattr(self.response.Errors, 'Error'):
                self.error_code = self.response.Errors.Error.Code
                self.message = self.response.Errors.Error.Message
            elif type(self.response.Errors) is list:
                self.error_code = self.response.Errors[0].error_code
                if hasattr(self.response.Errors[0], 'description'):
                    self.message = self.response.Errors[0].description
                elif hasattr(self.response.Errors[0], 'data'):
                    self.message = self.response.Errors[0].data
        if hasattr(self.response, 'Error'):
            self.error_code = self.response.Error.Code
            self.message = self.response.Error.Message
        if hasattr(self.response, 'RequestID'):
            self.request_id = self.response.RequestID
        elif hasattr(self.response, 'RequestId'):
            self.request_id = self.response.RequestId
        elif hasattr(self.response, 'requestId'):
            self.request_id = self.response.requestId
        if hasattr(self.response, 'Message'):
            self.message = self.response.Message
        if (hasattr(self.response, 'result')
                and hasattr(self.response.result, 'result')):
            self.error_code = self.response.result.faultcode
            self.message = self.response.result.faultmessage
        if hasattr(self.response, '__type'):
            self.error_code = getattr(self.response, '__type')
        if hasattr(self.response, 'faultcode'):
            self.error_code = self.response.faultcode
            self.message = self.response.faultstring
        if hasattr(self.response, 'error'):
            if hasattr(self.response.error, 'message'):
                self.error_code = self.response.error.code
                self.message = self.response.error.message
            else:
                self.message = self.response.error
        if isinstance(self.response, str):
            self.message = self.response

    def __str__(self):
        return (
            'Error --> status = ' + str(self.status_code)
            + ', code = ' + str(self.error_code)
            + ', Reason = ' + str(self.message)
            + ', request_id = ' + str(self.request_id))

    def get_error_message(self):
        return str(self)


class ApiCall(object):
    SERVICE = None
    CONTENT_TYPE = 'application/x-www-form-urlencoded'

    def __init__(self, **kwargs):
        self.method = kwargs.pop('method', DEFAULT_METHOD)
        self.access_key = kwargs.pop('access_key')
        self.secret_key = kwargs.pop('secret_key')
        self.version = kwargs.pop('version', DEFAULT_VERSION)
        self.protocol = 'https' if kwargs.pop('https', None) else 'http'
        self.region = kwargs.pop('region_name', DEFAULT_REGION)
        self.host = '.'.join([self.SERVICE, self.region, kwargs.pop('host')])

        date = datetime.datetime.utcnow()
        self.amz_date = date.strftime('%Y%m%dT%H%M%SZ')
        self.datestamp = date.strftime('%Y%m%d')

    @property
    def method(self):
        return self._method

    @method.setter
    def method(self, method):
        if method not in {'GET', 'POST'}:
            raise Exception(
                'Wrong method {}: only GET or POST supported.'.format(method))
        self._method = method

    def sign(self, key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def get_signature_key(self, key, timestamp, region_name, service_name):
        key_date = self.sign(('AWS4' + key).encode('utf-8'), timestamp)
        key_region = self.sign(key_date, region_name)
        key_service = self.sign(key_region, service_name)
        return self.sign(key_service, 'aws4_request')

    def get_authorization_header(self, amz_date,
                                 credential_scope, canonical_request,
                                 signed_headers, timestamp):
        string_to_sign = '\n'.join([
            SIG_ALGORITHM,
            self.amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()])
        signing_key = self.get_signature_key(self.secret_key, timestamp,
                                             self.region, self.SERVICE)
        signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'),
                             hashlib.sha256).hexdigest()
        return '{} Credential={}/{}, SignedHeaders={}, Signature={}'.format(
            SIG_ALGORITHM,
            self.access_key,
            credential_scope,
            signed_headers,
            signature)

    def get_response(self, request):
        raise NotImplementedError

    def get_parameters(self, data, prefix=''):
        ret = {}
        if isinstance(data, list):
            if prefix:
                prefix += '.'
            i = 1
            for value in data:
                ret.update(self.get_parameters(value,
                                               prefix + str(i)))
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
        date = datetime.datetime.utcnow()
        self.amz_date = date.strftime('%Y%m%dT%H%M%SZ')
        self.datestamp = date.strftime('%Y%m%d')

        request_parameters = self.get_parameters(data=kwargs)
        request_parameters['Action'] = call
        if 'Version' not in request_parameters:
            request_parameters['Version'] = self.version

        credential_scope = '/'.join([self.datestamp,
                                     self.region,
                                     self.SERVICE,
                                     'aws4_request'])

        if self.method == 'GET':
            canonical_headers = '\n'.join(['host:' + self.host,
                                           'x-amz-date:' + self.amz_date,
                                           ''])
            signed_headers = 'host;x-amz-date'
            payload_hash = hashlib.sha256(''.encode('utf-8')).hexdigest()
            request_parameters = urllib.parse.urlencode(
                request_parameters)
            canonical_request = '\n'.join([
                self.method, CANONICAL_URI,
                request_parameters, canonical_headers,
                signed_headers, payload_hash])
            request_url = "{}://{}?{}".format(self.protocol, self.host,
                                              request_parameters)
            request_parameters = None
        else:
            amz_target = '{}_{}.{}'.format(
                self.SERVICE,
                datetime.date.today().strftime("%Y%m%d"),
                call)
            request_parameters = urllib.parse.urlencode(
                request_parameters)
            canonical_headers = (
                'content-type:{}\n'
                'host:{}\n'
                'x-amz-date:{}\n'
                'x-amz-target:{}\n'.format(
                    self.CONTENT_TYPE,
                    self.host,
                    self.amz_date,
                    amz_target))
            signed_headers = 'content-type;host;x-amz-date;x-amz-target'

            payload_hash = hashlib.sha256(
                request_parameters.encode('utf-8')).hexdigest()
            canonical_request = '\n'.join([self.method, CANONICAL_URI, '',
                                           canonical_headers, signed_headers,
                                           payload_hash])

        authorization_header = self.get_authorization_header(
            self.amz_date, credential_scope, canonical_request,
            signed_headers, self.datestamp)

        headers = {
            'Authorization': authorization_header,
            'x-amz-date': self.amz_date,
            'User-agent': USER_AGENT,
        }
        if self.method == 'POST':
            headers['content-type'] = self.CONTENT_TYPE
            headers['x-amz-target'] = amz_target
            request_url = "{}://{}".format(self.protocol, self.host)

        self.response = self.get_response(
            requests.request(
                method=self.method,
                url=request_url,
                data=request_parameters,
                headers=headers,
                verify=SSL_VERIFY))

        print(json.dumps(self.response, indent=4))


class FcuCall(ApiCall):
    SERVICE = 'fcu'

    def get_response(self, http_response):
        if http_response.status_code not in SUCCESS_CODES:
            raise OscApiException(http_response)

        try:
            response = xmltodict.parse(http_response.content)
        except Exception:
            response = "Unable to parse response: '{}'".format(
                    http_response.text)

        return response


class LbuCall(FcuCall):
    SERVICE = 'lbu'

    def get_parameters(self, data, prefix=''):
        ret = {}
        if isinstance(data, list):
            if prefix:
                prefix += '.member.'
            i = 1
            for value in data:
                ret.update(self.get_parameters(value,
                                               prefix + str(i)))
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
    SERVICE = 'eim'


class JsonApiCall(ApiCall):
    CONTENT_TYPE = 'application/x-amz-json-1.1'

    def get_parameters(self, data, call):
        return data

    def get_response(self, http_response):
        if http_response.status_code not in SUCCESS_CODES:
            raise OscApiException(http_response)

        return json.loads(http_response.text)

    def make_request(self, call, *args, **kwargs):
        request_parameters = self.get_parameters(kwargs, call)
        json_parameters = json.dumps(request_parameters)

        signed_headers = 'host;x-amz-date;x-amz-target'
        credential_scope = '/'.join([self.datestamp,
                                     self.region,
                                     self.SERVICE,
                                     'aws4_request'])

        amz_target = '.'.join([self.amz_service, call])
        canonical_headers = (
            'host:{}\n'
            'x-amz-date:{}\n'
            'x-amz-target:{}\n'.format(
                self.host,
                self.amz_date,
                amz_target))

        canonical_request = '\n'.join(
            ['POST', CANONICAL_URI, '',
             canonical_headers,
             signed_headers,
             hashlib.sha256(
                 json_parameters.encode('utf-8')).hexdigest()])

        headers = {
            'content-type': self.CONTENT_TYPE,
            'x-amz-date': self.amz_date,
            'x-amz-target': amz_target,
            'User-agent': USER_AGENT,
            'content-length': str(len(json_parameters)),
        }
        if (not request_parameters.get('AuthenticationMethod')
                or request_parameters['AuthenticationMethod'] == 'accesskey'):
            headers['Authorization'] = self.get_authorization_header(
                self.amz_date, credential_scope, canonical_request,
                signed_headers, self.datestamp)

        request_url = "{}://{}".format(self.protocol, self.host)

        self.response = self.get_response(
            requests.request(
                method=self.method,
                url=request_url,
                data=json_parameters,
                headers=headers,
                verify=SSL_VERIFY))

        print(json.dumps(self.response, indent=4))


class IcuCall(JsonApiCall):
    SERVICE = 'icu'
    amz_service = 'TinaIcuService'

    def get_parameters(self, request_parameters, call):
        auth = request_parameters.pop('authentication_method', 'accesskey')
        if auth not in {'accesskey', 'password'}:
            raise RuntimeError('Bad authentication method {}'.format(
                auth))
        if auth == 'password':
            try:
                request_parameters.update({
                    'AuthenticationMethod': 'password',
                    'Login': request_parameters.pop('login'),
                    'Password': request_parameters.pop('password'),
                })
            except KeyError:
                raise RuntimeError(
                    'Missing login and/or password, yet password authentification has been required')
        else:
            request_parameters.update({
                'AuthenticationMethod': 'accesskey',
            })
        return {
            'Action': call,
            'Version': self.version,
            **request_parameters,
        }


class DirectLinkCall(JsonApiCall):
    SERVICE = 'directlink'
    amz_service = 'OvertureService'

    def get_response(self, http_response):
        if http_response.status_code not in SUCCESS_CODES:
            raise OscApiException(http_response)

        res = json.loads(http_response.text)
        res['requestid'] = http_response.headers['x-amz-requestid']
        return res


class OKMSCall(JsonApiCall):
    SERVICE = 'kms'
    amz_service = 'TrentService'


def get_conf(profile):
    conf_path = pathlib.Path.home() / CONFIGURATION_FOLDER / CONFIGURATION_FILE
    if not conf_path.exists():
        raise RuntimeError('No configuration file found in home folder')

    conf = json.loads(conf_path.read_text())
    try:
        return conf[profile]
    except KeyError:
        raise RuntimeError('Profile {} not found in configuration file'.format(
            profile))


def api_connect(service, call, profile='default', *args, **kwargs):
    calls = {
        'directlink': DirectLinkCall,
        'eim': EimCall,
        'fcu': FcuCall,
        'icu': IcuCall,
        'lbu': LbuCall,
        'okms': OKMSCall,
    }
    conf = get_conf(profile)
    return calls[service](
        **conf).make_request(
            call, *args, **kwargs)


def main():
    logging.basicConfig(level=logging.ERROR)
    fire.Fire(api_connect)


if __name__ == '__main__':
    main()
