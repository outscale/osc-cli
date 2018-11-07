import datetime
import hashlib
import hmac
import json
import keyword
import logging
import re

import fire
import lxml.etree
import requests
import urllib


DEFAULT_METHOD = 'POST'
DEFAULT_PROFILE = None
DEFAULT_REGION = 'eu-west-2'
DEFAULT_VERSION = datetime.date.today().strftime("%Y-%m-%d")
MAX_RETRIES = 3
SERVICES_BUILT_WITH_MEMBERS = {'lbu'}
SUCCESS_CODES = [200, 201, 202, 203, 204]

logging.basicConfig()
logger = logging.getLogger('osc_sdk')


class OscApiException(Exception):

    def __init__(self, status_code, response, stack=None):
        super(OscApiException, self).__init__()
        self.status_code = status_code
        self.error_code = None
        self.message = None
        self.request_id = None
        self.stack = stack
        if hasattr(response, 'Errors'):
            if hasattr(response.Errors, 'Error'):
                self.error_code = response.Errors.Error.Code
                self.message = response.Errors.Error.Message
            elif type(response.Errors) is list:
                self.error_code = response.Errors[0].error_code
                if hasattr(response.Errors[0], 'description'):
                    self.message = response.Errors[0].description
                elif hasattr(response.Errors[0], 'data'):
                    self.message = response.Errors[0].data
        if hasattr(response, 'Error'):
            self.error_code = response.Error.Code
            self.message = response.Error.Message
        if hasattr(response, 'RequestID'):
            self.request_id = response.RequestID
        elif hasattr(response, 'RequestId'):
            self.request_id = response.RequestId
        elif hasattr(response, 'requestId'):
            self.request_id = response.requestId
        if hasattr(response, 'Message'):
            self.message = response.Message
        if hasattr(response, 'result') and hasattr(response.result, 'result'):
            self.error_code = response.result.faultcode
            self.message = response.result.faultmessage
        if hasattr(response, '__type'):
            self.error_code = getattr(response, '__type')
        if hasattr(response, 'faultcode'):
            self.error_code = response.faultcode
            self.message = response.faultstring
        if hasattr(response, 'error'):
            if hasattr(response.error, 'message'):
                self.error_code = response.error.code
                self.message = response.error.message
            else:
                self.message = response.error
        if isinstance(response, str):
            self.message = response

    def __str__(self):
        return (
            'Error --> status = ' + str(self.status_code)
            + ', code = ' + str(self.error_code)
            + ', Reason = ' + str(self.message)
            + ', request_id = ' + str(self.request_id))

    def get_error_message(self):
        return str(self)


class OscObjectXml(object):

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


class OscObjectDict(object):

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


class OscResponse(object):

    def __init__(self, http_response):
        self.status_code = http_response.status_code
        self.text = http_response.text

        self.response = None
        # hack for icu calls returning '""'
        if (http_response.text
                and http_response.text != "''"
                and http_response.text != '""'):
            if (http_response.text.startswith("<")
                    and not http_response.text.startswith("<html")):
                self.response = OscObjectXml(
                    lxml.etree.ElementTree.fromstring(
                        re.sub(' xmlns="[^"]+"',
                               '',
                               http_response.text,
                               count=1)))
            elif http_response.text.startswith("{"):
                self.response = OscObjectDict(json.loads(http_response.text))
            else:
                self.response = "Unable to parse response: '{}'".format(
                    http_response.text)

        if self.status_code not in SUCCESS_CODES:
            raise OscApiException(self.status_code, self.response)


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

    def call(self, call, *args, **kwargs):
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
            'User-agent': 'osc_sdk'
        }
        if self.method == 'POST':
            headers['content-type'] = content_type
            headers['x-amz-target'] = amz_target
            request_url = "{}://{}".format(self.protocol, host)
        import pdb; pdb.set_trace()  # XXX BREAKPOINT

        response = OscResponse(
            requests.request(
                method=self.method,
                url=request_url,
                data=request_parameters,
                headers=headers,
                verify=False))

        return response


class FcuCall(ApiCall):

    def __init__(self, **kwargs):
        super(FcuCall, self).__init__(**kwargs)
        self.service = 'fcu'


def main():
    conf = {
        'profile': {'ak': 'HGHGHGHGHGHG',
                    'sk': 'HGFHGISFDINODFN'},
        'https': False,
        'host': 'fcu.dk-west-1.outscale.local',
    }
    fire.Fire(FcuCall(**conf).call)


if __name__ == '__main__':
    main()
