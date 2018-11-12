import datetime
import hashlib
import hmac
import json
import keyword
import logging

import fire
import requests
import urllib
import xmltodict

SDK_VERSION = '0.1'
USER_AGENT = 'osc_sdk ' + SDK_VERSION

DEFAULT_METHOD = 'POST'
DEFAULT_PROFILE = None
DEFAULT_REGION = 'eu-west-2'
DEFAULT_VERSION = datetime.date.today().strftime("%Y-%m-%d")
MAX_RETRIES = 3
SERVICES_BUILT_WITH_MEMBERS = {'lbu'}
SUCCESS_CODES = [200, 201, 202, 203, 204]

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


class OscObject(object):

    def display(self, tab=""):
        ret = ""
        ret += "{}{}:\n".format(tab, self._name)
        tab = tab.replace("*", " ")
        for key, value in self.__dict__.items():
            if key.startswith("_"):
                pass
            elif isinstance(value, list):
                value_list = value
                ret += "{}|- {}:\n".format(tab, key)
                for val in value_list:
                    if isinstance(val, OscObject):
                        ret += val.display(tab + "|  * ")
                    else:
                        if isinstance(val, str):
                            val = val.encode('utf-8')
                        ret += "{}|  * {}\n".format(tab, val)
            elif isinstance(value, OscObject):
                ret += "{}|- {}:\n".format(tab, key)
                ret += value.display(tab + "|  ")
            else:
                if isinstance(value, str):
                    value = value.encode('utf-8')
                ret += "{}|- {}:{}\n".format(tab, key, value)
        return ret


class OscObjectXml(OscObject):

    def __init__(self, elem, name=None):
        # name is set when we parse an "item" element
        if name:
            self._name = name
        else:
            self._name = elem.tag
        logger.debug("Parse object: %s", self._name)

        for child in elem:
            if not child.getchildren():
                setattr(self, (
                    "osc_{}".format(child.tag)
                    if child.tag in keyword.kwlist
                    else child.tag.replace('.', '_')), child.text)
                logger.debug("Add %s.%s = %s",
                             self._name, child.tag, child.text)
            elif child.getchildren()[0].tag in {'item', 'member'}:
                common_name = child.getchildren()[0].tag
                item_list = []
                logger.debug("Add %s.%s = [...]", self._name, child.tag)
                for sub_child in child:
                    if sub_child.tag != common_name:
                        logger.error(
                            "[%s->%s]: \'\' should contain only \'%s\'",
                            child.tag, sub_child.tag, common_name)
                    elif not sub_child.getchildren():
                        logger.debug("Append %s.%s: %s",
                                     self._name, child.tag, sub_child.text)
                        item_list.append(sub_child.text)
                    else:
                        logger.debug("Append %s.%s: %s()",
                                     self._name, child.tag, sub_child.tag)
                        item_list.append(OscObjectXml(sub_child,
                                                      sub_child.tag))
                setattr(self, ("osc_{}".format(child.tag)
                               if child.tag in keyword.kwlist else
                               child.tag.replace('.', '_')), item_list)
            else:
                logger.debug("Add %s.%s = %s()",
                             self._name, child.tag, child.tag)
                setattr(self, ("osc_{}".format(child.tag)
                               if child.tag in keyword.kwlist
                               else child.tag.replace('.', '_')),
                        OscObjectXml(child))


class OscObjectDict(OscObject):

    def __init__(self, elem, name=None):
        self._name = name
        logger.debug("Parse object: %s", self._name)

        for key, value in elem.items():
            if isinstance(value, list):
                item_list = []
                logger.debug("  Add %s.%s = [...]", self._name, key)
                for item in value:
                    if isinstance(item, dict):
                        item_list.append(OscObjectDict(item,
                                                       "{}_item".format(key)))
                        logger.debug("  Append %s.%s: %s()",
                                     self._name, key, "{}_item".format(key))
                    else:
                        item_list.append(item)
                        logger.debug("  Append %s.%s: %s",
                                     self._name, key, item)
                setattr(self, key.replace('.', '_'), item_list)
            elif isinstance(value, dict):
                setattr(self, key.replace('.', '_'), OscObjectDict(value, key))
                logger.debug("  Add %s.%s = %s()", self._name, key, key)
            else:
                setattr(self, key.replace('.', '_'), value)
                logger.debug("  Add %s.%s = %s", self._name, key, value)


class ApiCall(object):

    def __init__(self, **kwargs):
        self.max_retries = kwargs.pop('max_retries', MAX_RETRIES)
        self.method = kwargs.pop('method', DEFAULT_METHOD)
        self.profile = kwargs.pop('profile', DEFAULT_PROFILE)
        self.version = kwargs.pop('version', DEFAULT_VERSION)
        self.protocol = 'https' if kwargs.pop('https') else 'http'
        self.region = kwargs.pop('region_name', DEFAULT_REGION)
        self.host = kwargs.pop('host')
        self.service = None

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

    def get_authorization_header(self, algorithm, amzdate,
                                 credential_scope, canonical_request,
                                 signed_headers, timestamp):
        string_to_sign = '\n'.join([
            algorithm,
            amzdate,
            credential_scope,
            hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()])
        signing_key = self.get_signature_key(self.profile['sk'], timestamp,
                                             self.region, self.service)
        signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'),
                             hashlib.sha256).hexdigest()
        return '{} Credential={}/{}, SignedHeaders={}, Signature={}'.format(
            algorithm,
            self.profile['ak'],
            credential_scope,
            signed_headers,
            signature)

    def get_response(self, request):
        raise NotImplementedError

    def param_to_dict(self, data, prefix=''):
        ret = {}
        if isinstance(data, list):
            if prefix:
                prefix += '.'
            if self.service in SERVICES_BUILT_WITH_MEMBERS:
                prefix += 'member.'
            i = 1
            for value in data:
                ret.update(self.param_to_dict(data=value,
                                              prefix=prefix + str(i)))
            return ret
        if isinstance(data, dict):
            if prefix:
                prefix += '.'
            for key, value in data.items():
                ret.update(self.param_to_dict(data=value, prefix=prefix + key))
            return ret
        if data is not None:
            if data == '':
                return {prefix: ''}
            return {prefix: str(data)}

    def make_request(self, call, *args, **kwargs):
        host = '.'.join([self.service, self.host])

        date = datetime.datetime.utcnow()
        amzdate = date.strftime('%Y%m%dT%H%M%SZ')
        datestamp = date.strftime('%Y%m%d')

        request_parameters = self.param_to_dict(data=kwargs)
        request_parameters['Action'] = call
        if 'Version' not in request_parameters:
            request_parameters['Version'] = self.version

        canonical_uri = '/'
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = '/'.join([datestamp,
                                     self.region,
                                     self.service,
                                     'aws4_request'])

        if self.method == 'GET':
            canonical_headers = '\n'.join(['host:' + host,
                                           'x-amz-date:' + amzdate,
                                           ''])
            signed_headers = 'host;x-amz-date'
            payload_hash = hashlib.sha256('').hexdigest()
            request_parameters = urllib.parse.urlencode(
                request_parameters)
            canonical_request = '\n'.join([
                self.method, canonical_uri,
                request_parameters, canonical_headers,
                signed_headers, payload_hash])
            request_url = "{}://{}?{}".format(self.protocol, host,
                                              request_parameters)
        else:
            content_type = 'application/x-www-form-urlencoded'
            amz_target = '{}_{}.{}'.format(
                self.service,
                datetime.date.today().strftime("%Y%m%d"),
                call)
            request_parameters = urllib.parse.urlencode(
                request_parameters)
            canonical_headers = (
                'content-type:{}\n'
                'host:{}\n'
                'x-amz-date:{}\n'
                'x-amz-target:{}\n'.format(
                    content_type,
                    host,
                    amzdate,
                    amz_target))
            signed_headers = 'content-type;host;x-amz-date;x-amz-target'

            payload_hash = hashlib.sha256(
                request_parameters.encode('utf-8')).hexdigest()
            canonical_request = '\n'.join([self.method, canonical_uri, '',
                                           canonical_headers, signed_headers,
                                           payload_hash])

        authorization_header = self.get_authorization_header(
            algorithm, amzdate, credential_scope, canonical_request,
            signed_headers, datestamp)

        headers = {
            'Authorization': authorization_header,
            'x-amz-date': amzdate,
            'User-agent': USER_AGENT,
        }
        if self.method == 'POST':
            headers['content-type'] = content_type
            headers['x-amz-target'] = amz_target
            request_url = "{}://{}".format(self.protocol, host)

        self.response = self.get_response(
            requests.request(
                method=self.method,
                url=request_url,
                data=request_parameters,
                headers=headers,
                verify=False))

        print(json.dumps(self.response, indent=4))


class FcuCall(ApiCall):

    def __init__(self, **kwargs):
        super(FcuCall, self).__init__(**kwargs)
        self.service = 'fcu'

    def get_response(self, http_response):
        if http_response.status_code not in SUCCESS_CODES:
            raise OscApiException(http_response)

        try:
            response = xmltodict.parse(http_response.content)
        except Exception:
            response = "Unable to parse response: '{}'".format(
                    http_response.text)

        return response

    def make_request(self, call, *args, **kwargs):
        host = '.'.join([self.service, self.host])

        date = datetime.datetime.utcnow()
        amzdate = date.strftime('%Y%m%dT%H%M%SZ')
        datestamp = date.strftime('%Y%m%d')

        request_parameters = self.param_to_dict(data=kwargs)
        request_parameters['Action'] = call
        if 'Version' not in request_parameters:
            request_parameters['Version'] = self.version

        canonical_uri = '/'
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = '/'.join([datestamp,
                                     self.region,
                                     self.service,
                                     'aws4_request'])

        if self.method == 'GET':
            canonical_headers = '\n'.join(['host:' + host,
                                           'x-amz-date:' + amzdate,
                                           ''])
            signed_headers = 'host;x-amz-date'
            payload_hash = hashlib.sha256('').hexdigest()
            request_parameters = urllib.parse.urlencode(
                request_parameters)
            canonical_request = '\n'.join([
                self.method, canonical_uri,
                request_parameters, canonical_headers,
                signed_headers, payload_hash])
            request_url = "{}://{}?{}".format(self.protocol, host,
                                              request_parameters)
        else:
            content_type = 'application/x-www-form-urlencoded'
            amz_target = '{}_{}.{}'.format(
                self.service,
                datetime.date.today().strftime("%Y%m%d"),
                call)
            request_parameters = urllib.parse.urlencode(
                request_parameters)
            canonical_headers = (
                'content-type:{}\n'
                'host:{}\n'
                'x-amz-date:{}\n'
                'x-amz-target:{}\n'.format(
                    content_type,
                    host,
                    amzdate,
                    amz_target))
            signed_headers = 'content-type;host;x-amz-date;x-amz-target'

            payload_hash = hashlib.sha256(
                request_parameters.encode('utf-8')).hexdigest()
            canonical_request = '\n'.join([self.method, canonical_uri, '',
                                           canonical_headers, signed_headers,
                                           payload_hash])

        authorization_header = self.get_authorization_header(
            algorithm, amzdate, credential_scope, canonical_request,
            signed_headers, datestamp)

        headers = {
            'Authorization': authorization_header,
            'x-amz-date': amzdate,
            'User-agent': 'osc_sdk ' + SDK_VERSION
        }
        if self.method == 'POST':
            headers['content-type'] = content_type
            headers['x-amz-target'] = amz_target
            request_url = "{}://{}".format(self.protocol, host)

        self.response = self.get_response(
            requests.request(
                method=self.method,
                url=request_url,
                data=request_parameters,
                headers=headers,
                verify=False))

        print(json.dumps(self.response, indent=4))


class LbuCall(FcuCall):

    def __init__(self, **kwargs):
        super(LbuCall, self).__init__(**kwargs)
        self.service = 'lbu'


class EimCall(FcuCall):

    def __init__(self, **kwargs):
        super(EimCall, self).__init__(**kwargs)
        self.service = 'eim'


class JsonApiCall(ApiCall):

    def make_request(self, call, *args, **kwargs):
        pass

    def get_response(self, http_response):
        if http_response.status_code not in SUCCESS_CODES:
            raise OscApiException(http_response)
        print(http_response.__dict__)

        return json.loads(http_response.text)


class IcuCall(JsonApiCall):

    def __init__(self, **kwargs):
        super(IcuCall, self).__init__(**kwargs)
        self.service = 'icu'
        self.amz_service = "TinaIcuService"

    def param_to_dict(self, data):
        return data

    def make_request(self, call, *args, **kwargs):
        auth = kwargs.pop('authentication-method', 'accesskey')
        if auth not in {'accesskey', 'password'}:
            raise OscApiException('Bad authentication method {}'.format(
                auth))
        if auth == 'password':
            try:
                login = kwargs.pop('login')
                password = kwargs.pop('password')
            except KeyError:
                logger.error('Missing login and/or password')
        host = '.'.join([self.service, self.host])

        date = datetime.datetime.utcnow()
        amzdate = date.strftime('%Y%m%dT%H%M%SZ')
        datestamp = date.strftime('%Y%m%d')

        request_parameters = self.param_to_dict(data=kwargs)
        amz_target = '.'.join([self.amz_service, call])
        request_parameters['Action'] = call
        if 'Version' not in request_parameters:
            request_parameters['Version'] = self.version
        if auth == 'password':
            request_parameters['AuthenticationMethod'] = 'password'
            request_parameters['Login'] = login
            request_parameters['Password'] = password
        else:
            request_parameters['AuthenticationMethod'] = 'accesskey'

        canonical_uri = '/'
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = '/'.join([datestamp,
                                     self.region,
                                     self.service,
                                     'aws4_request'])

        content_type = 'application/x-amz-json-1.1'
        json_parameters = json.dumps(request_parameters)
        canonical_headers = (
            'host:{}\n'
            'x-amz-date:{}\n'
            'x-amz-target:{}\n'.format(
                host,
                amzdate,
                amz_target))
        signed_headers = 'host;x-amz-date;x-amz-target'

        canonical_request = '\n'.join(
            ['POST', canonical_uri, '',
             canonical_headers,
             signed_headers,
             hashlib.sha256(
                 json_parameters.encode('utf-8')).hexdigest()])

        headers = {
            'content-type': content_type,
            'x-amz-date': amzdate,
            'x-amz-target': amz_target,
            'User-agent': USER_AGENT,
        }
        if auth == 'accesskey':
            headers['Authorization'] = self.get_authorization_header(
                algorithm, amzdate, credential_scope, canonical_request,
                signed_headers, datestamp)

        headers['content-length'] = str(len(json_parameters))

        request_url = "{}://{}".format(self.protocol, host)

        self.response = self.get_response(
            requests.request(
                method=self.method,
                url=request_url,
                data=json_parameters,
                headers=headers,
                verify=False))

        print(json.dumps(self.response, indent=4))


class DirectLinkCall(JsonApiCall):

    def __init__(self, **kwargs):
        super(DirectLinkCall, self).__init__(**kwargs)
        self.service = 'directlink'
        self.amz_service = "OvertureService"

    def get_response(self, http_response):
        if http_response.status_code not in SUCCESS_CODES:
            raise OscApiException(http_response)
        print(http_response.__dict__)

        res = json.loads(http_response.text)
        res['requestid'] = http_response.headers['x-amz-requestid']
        return res

    def make_request(self, call, *args, **kwargs):
        host = '.'.join([self.service, self.host])

        date = datetime.datetime.utcnow()
        amzdate = date.strftime('%Y%m%dT%H%M%SZ')
        datestamp = date.strftime('%Y%m%d')

        request_parameters = kwargs
        amz_target = '.'.join([self.amz_service, call])

        canonical_uri = '/'
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = '/'.join([datestamp,
                                     self.region,
                                     self.service,
                                     'aws4_request'])

        content_type = 'application/x-amz-json-1.1'
        json_parameters = json.dumps(request_parameters)
        canonical_headers = (
            'host:{}\n'
            'x-amz-date:{}\n'
            'x-amz-target:{}\n'.format(
                host,
                amzdate,
                amz_target))
        signed_headers = 'host;x-amz-date;x-amz-target'

        payload_hash = hashlib.sha256(
            json_parameters.encode('utf-8')).hexdigest()
        canonical_request = '\n'.join(['POST', canonical_uri, '',
                                       canonical_headers,
                                       signed_headers, payload_hash])

        headers = {
            'content-type': content_type,
            'x-amz-date': amzdate,
            'x-amz-target': amz_target,
            'User-agent': USER_AGENT,
            'Authorization': self.get_authorization_header(
                algorithm, amzdate, credential_scope, canonical_request,
                signed_headers, datestamp),
            'content-length': str(len(json_parameters)),
        }

        request_url = "{}://{}".format(self.protocol, host)
        self.response = self.get_response(
            requests.request(
                method=self.method,
                url=request_url,
                data=json_parameters,
                headers=headers,
                verify=False))

        print(json.dumps(self.response, indent=4))


def main():
    logging.basicConfig(level=logging.DEBUG)
    conf = {
        'host': 'dk-west-1.outscale.local',
        'https': True,
        'max_retries': 3,
        'method': 'POST',
        'profile': {'ak': 'SR50409NMMKDKW4MWNLE',
                    'sk': 'H9uBXvbSPuRATQg393jk00BifJ25O6WJ3KL4Sraj'},
        'region_name': 'dk-west-1',
        'version': DEFAULT_VERSION,
    }
    fire.Fire({
        'fcu': FcuCall(**conf).make_request,
        'lbu': LbuCall(**conf).make_request,
        'eim': EimCall(**conf).make_request,
        'directlink': DirectLinkCall(**conf).make_request,
        'icu': IcuCall(**conf).make_request,
    })


if __name__ == '__main__':
    main()
