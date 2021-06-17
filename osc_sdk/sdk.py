import datetime
import hashlib
import hmac
import json
import logging
import pathlib
import re
import urllib
import defusedxml.ElementTree as ET
import sys
import fire
import requests
import xmltodict
import os
import stat
import getpass
import M2Crypto
import urllib3

CANONICAL_URI = '/'
CONFIGURATION_FILE = 'config.json'
CONFIGURATION_FOLDER = '.osc'
CONFIGURATION_FOLDER_DEPRECATED = '.osc_sdk'
DEFAULT_METHOD = 'POST'
DEFAULT_PROFILE = 'default'
DEFAULT_REGION = 'eu-west-2'
DEFAULT_VERSION = datetime.date.today().strftime("%Y-%m-%d")
DEFAULT_AUTHENTICATION_METHOD = 'accesskey'
# Manually manage tmp file as we want to find it between process instanciations without deletion
DEFAULT_TMP_DIR = '/tmp' # nosec
DEFAULT_EPHEMERAL_AK_DURATION_S = 12 * 60 * 60 # Default 12h
METHODS_SUPPORTED = ['GET', 'POST']
SDK_VERSION = '1.5'
SSL_VERIFY = True
SUCCESS_CODES = [200, 201, 202, 203, 204]
USER_AGENT = 'osc_sdk ' + SDK_VERSION


logger = logging.getLogger('osc_sdk')

def abort(error_message):
    logger.error(error_message)
    sys.exit(1)

class OscApiException(Exception):

    def __init__(self, http_response):
        super(OscApiException, self).__init__()
        self.status_code = http_response.status_code
        # Set error details
        self.error_code = None
        self.message = None
        self.code_type = None
        self.request_id = None
        self._set(http_response)

    def __str__(self):
        return (
            f'status = {self.status_code}, '
            f'code = {self.error_code}, '
            f'{"code_type = " if self.code_type is not None else ""}'
            f'{self.code_type + ", " if self.code_type is not None else ""}'
            f'Reason = {self.message}, '
            f'request_id = {self.request_id}')

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
                    if error.get('Details'):
                        self.code_type = self.message
                        self.message = error.get('Details')
                    else:
                        self.code_type = None
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

    def __init__(self, profile=DEFAULT_PROFILE, login=None, password=None, authentication_method=DEFAULT_AUTHENTICATION_METHOD, ephemeral_ak_duration=DEFAULT_EPHEMERAL_AK_DURATION_S ,interactive=False):
        self.response = None
        self.date = None
        self.datestamp = None
        self.tmp_dir = DEFAULT_TMP_DIR

        self.load_config_file(profile)
        self.setup_cmd_options(profile, login, password, authentication_method, ephemeral_ak_duration, interactive)
        self.setup_interactive_options()
        self.check_options()
        self.init_ephemeral_auth()

    def load_config_file(self, profile):
        conf_path = pathlib.Path.home() / CONFIGURATION_FOLDER / CONFIGURATION_FILE
        if conf_path.exists():
            logger.info("loading config file %s", conf_path)
            self.setup_profile_options(conf_path, profile)
            return
        conf_path_deprecated = pathlib.Path.home() / CONFIGURATION_FOLDER_DEPRECATED / CONFIGURATION_FILE
        if conf_path_deprecated.exists():
            logger.warning("loading deprecated config file %s", conf_path_deprecated)
            self.setup_profile_options_deprecated(conf_path_deprecated, profile)
            return
        RuntimeError('No configuration file found in home folder')

    def setup_profile_options(self, conf_path, profile):
        profiles = json.loads(conf_path.read_text())
        try:
            conf = profiles[profile]
        except KeyError:
            raise RuntimeError('Profile {} not found in configuration file'.format(profile))

        # From standard options
        self.profile_name = profile
        self.access_key = conf.get('access_key')
        self.secret_key = conf.get('secret_key')
        self.x509_client_cert = conf.get('x509_client_cert')
        self.x509_client_key = conf.get('x509_client_key')
        self.client_certificate = (self.x509_client_cert, self.x509_client_key)
        self.protocol = conf.get('protocol', 'https')
        self.method = conf.get('method', DEFAULT_METHOD)
        if isinstance(self.method, str):
            self.method = self.method.upper()
        self.region = conf.get('region', DEFAULT_REGION)
        self.host = None
        self.path = None
        endpoints = conf.get('endpoints')
        if isinstance(endpoints, dict):
            endpoint = endpoints.get(self.API_NAME)
            self.setup_host_path(endpoint)

        # Additionnal specific osc-cli options
        self.ssl_verify = conf.get('ssl_verify', SSL_VERIFY)
        self.version = conf.get('version', DEFAULT_VERSION)
        self.ssl_engine_id = conf.get('ssl_engine_id')
        self.ssl_engine_path = conf.get('ssl_engine_path')
        self.ssl_module_path = conf.get('ssl_module_path')

    def setup_profile_options_deprecated(self, conf_path, profile):
        self.ssl_engine_id = None
        self.ssl_engine_path = None
        self.ssl_module_path = None
        conf = json.loads(conf_path.read_text())
        try:
            conf = conf[profile]
        except KeyError:
            raise RuntimeError('Profile {} not found in configuration file'.format(profile))
        self.profile_name = profile
        self.method = conf.get('method', DEFAULT_METHOD)
        self.access_key = conf.get('access_key')
        self.secret_key = conf.get('secret_key')
        self.version = conf.get('version', DEFAULT_VERSION)
        self.protocol = conf.get('protocol', 'https')
        self.region = conf.get('region_name', DEFAULT_REGION)
        self.ssl_verify = conf.get('ssl_verify', SSL_VERIFY)
        self.client_certificate = conf.get('client_certificate')
        endpoint = conf.get('endpoint')
        self.setup_host_path(endpoint)
        host = conf.get('host')
        if host and self.region:
            self.path = ''
            self.host = '{}.{}.{}'.format(self.API_NAME, self.region, host)
        if self.API_NAME == "api":
            self.path = '/api/v1'

    def setup_host_path(self, endpoint):
        self.host = None
        self.path = None
        if not isinstance(endpoint, str):
            return
        url = "{}://{}".format(self.method, endpoint)
        p = urllib.parse.urlparse(url)
        self.host = p.netloc
        self.path = p.path

    def setup_cmd_options(self, profile, login, password, authentication_method, ephemeral_ak_duration, interactive):
        self.profile = profile
        self.login = login
        self.password = password
        self.authentication_method = authentication_method
        self.ephemeral_ak_duration = ephemeral_ak_duration
        self.interactive = interactive

    def setup_interactive_options(self):
        if not self.interactive:
            return
        if self.authentication_method == 'password':
            if self.login == None:
                self.login = self.user_input_interactive('Login: ')
            if self.password == None:
                self.password = self.user_input_interactive_secure('Password: ')
        if self.authentication_method == 'accesskey':
            if self.access_key == None:
                self.access_key = self.user_input_interactive('Access Key: ')
            if self.secret_key == None:
                self.secret_key = self.user_input_interactive_secure('Secret Key: ')

    def user_input_interactive(self, prompt=''):
        # avoid input (W1632)
        print(prompt, end='', flush=True)
        r = sys.stdin.readline().splitlines()[0]
        if len(r) == 0:
            return None
        return r

    def user_input_interactive_secure(self, prompt=''):
        secret = getpass.getpass(prompt=prompt)
        if len(secret) == 0:
            return None
        return secret

    def check_options(self):
        if self.authentication_method not in ['accesskey', 'password', 'ephemeral']:
            abort('Unsupported authentication method (accesskey, password or ephemeral)')
        if self.authentication_method == 'accesskey':
            if self.access_key == None:
                abort('Missing Access Key for authentication')
            if self.secret_key == None:
                abort('Missing Secret Key for authentication')
        if self.authentication_method == 'password':
            if self.login == None:
                abort('Missing login for authentication')
            if self.password == None:
                abort('Missing password for authentication')
        if self.host == None or self.path == None:
            abort('Endpoint is not configured')
        if self.method not in METHODS_SUPPORTED:
            abort('Method {} is not supported'.format(self.method))
        if self.ssl_engine_id:
            if self.protocol != 'https':
                abort('Protocol must be "https" with ssl_engine_id')

    def init_ephemeral_auth(self):
        if self.authentication_method != 'ephemeral':
            return
        if not self.ephemeral_auth_file_get():
            logger.info("Ephemeral key not available, generating one...")
            if not self.ephemeral_auth_file_init():
                abort('Cannot initiate ephemeral authentication')

    def ephemeral_auth_file_path(self):
        uid = str(os.getuid())
        file_name = 'osc-cli_' + uid + '_' + self.profile_name + '.json'
        return os.path.join(self.tmp_dir, file_name)

    def ephemeral_auth_file_get(self):
        path = self.ephemeral_auth_file_path()
        try:
            file_stat = os.stat(path)

            # Does file is owned by the same uid ?
            if file_stat.st_uid != os.getuid():
                logger.error("Ephemeral temp file %s does belong to user", path)
                return False

            # Is file's mode greater than 600 ?
            if file_stat.st_mode & 0o177 > 0:
                logger.error("Ephemeral temp file %s has extented rights", path)
                return False

            # Finally, get file's content
            f = open(path, "r")
            j = json.load(f)
            f.close()
            ak = j.get("access_key")
            sk = j.get("secret_key")
            ed = j.get("expiration_date")
            if ak is None or sk is None or ed is None:
                return False
            expiration_date = datetime.datetime.fromisoformat(ed)
            now = datetime.datetime.now()
            if expiration_date <= now:
                logger.warning("Ephemeral Access Key has expired")
                return False
            self.access_key = ak
            self.secret_key = sk
        except Exception as e:
            print(e)
            return False
        return True

    def ephemeral_auth_file_init(self):
        created, ak, sk, ed = self.ephemeral_auth_ak_create()
        if not created:
            logger.error("Cannot create ephemeral Access Key")
            return False

        try:
            # Remove previously created file
            # Prevents to use eventual elevated file permissions
            self.ephemeral_auth_file_clean()

            # Create file with correct permissions
            path = self.ephemeral_auth_file_path()
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            mode = stat.S_IRUSR | stat.S_IWUSR # 600
            f = os.fdopen(os.open(path, flags, mode), 'w')

            auth_file_str = {
                "access_key": ak,
                "secret_key": sk,
                "expiration_date": ed
            }
            json.dump(auth_file_str, f)
        except Exception as e:
            print(e)
            logger.error("Cannot store ephemeral Access Key in %s", path)
            return False

        self.access_key = ak
        self.secret_key = sk
        return True

    def ephemeral_auth_file_clean(self):
        try:
            os.remove(self.ephemeral_auth_file_path())
        except OSError:
            pass

    def ephemeral_auth_ak_create(self):
        res = False
        ak = None
        sk = None
        ed = None

        expiration_date = datetime.datetime.now() + datetime.timedelta(seconds=self.ephemeral_ak_duration)
        try:
            # TODO: create AK with Outscale API, instead, read first AK waiting for API fix
            #call = OSCCall(profile=self.profile_name, login=self.login, password=self.password, authentication_method='password', interactive=self.interfactive)
            #r = call.make_request('CreateAccessKey', ExpirationDate=expiration_date.isoformat())
            ed = "2705-10-27T16:40:27.864019"
            call = IcuCall(profile=self.profile_name, login=self.login, password=self.password, authentication_method='password', interactive=self.interactive)
            call.make_request('ListAccessKeys')
            ak = call.response['accessKeys'][0]['accessKeyId']
            call.make_request('GetAccessKey', AccessKeyId=ak)
            sk = call.response['accessKey']['secretAccessKey']
            res = True
        except Exception  as e:
            print(e)
        return res, ak, sk, ed


    def _set_datestamp(self):
        date = datetime.datetime.utcnow()
        self.date = date.strftime('%Y%m%dT%H%M%SZ')
        self.datestamp = date.strftime('%Y%m%d')

    def get_url(self, action, request_params=None):
        url = '{}://{}'.format(self.protocol, self.host)
        if self.method == 'GET':
            url += '?{}'.format(request_params)
        return url

    def get_canonical_uri(self, action):
        return '/'

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

    def get_password_params(self):
        return {
            'AuthenticationMethod': 'password',
            'Login': self.login,
            'Password': self.password
        }

    def get_response(self, request, raw_content):
        raise NotImplementedError

    def build_request(self, action, *args, **kwargs):
        raise NotImplementedError

    def make_request(self, action, *args, **kwargs):
        url, headers, data = self.build_request(action, *args, **kwargs)

        request = requests.Session()
        if self.ssl_engine_id:
            adapter = HttpsAdapter(self.ssl_engine_id, self.ssl_engine_path, self.ssl_module_path)
            request.mount("https://", adapter)

        res = request.request(
            cert=self.client_certificate,
            data=data,
            headers=headers,
            method=self.method,
            url=url,
            verify=self.ssl_verify
        )

        # If we get an authentication error at this point with ephemeral,
        # this mean that either:
        # 1/ Ephemeral Access Key has been manually removed from account or
        # 2/ File containing ephemeral Access Key has been alterated
        # In either case, ephemeral auth file is removed an request retried
        if res.status_code == 403 and self.authentication_method == 'ephemeral':
            logger.error("Invalid ephemeral Access Key")
            self.ephemeral_auth_file_clean()
            self.init_ephemeral_auth()
            return self.make_request(action, args, kwargs)

        raw_content = self.get_raw_content(res)
        self.response = self.get_response(res, raw_content)

    def get_raw_content(self, res):
        raw_content = None
        if res.text is not None and len(res.text) > 0:
            raw_content = res.text
        elif res.content is not None and len(res.content) > 0:
            raw_content = res.content
        elif res.raw.data is not None and len(res.raw.data) > 0:
            encoding = res.encoding
            if encoding == None:
                encoding = "utf-8"
            raw_content = res.raw.data.decode(encoding)
        return raw_content


class XmlApiCall(ApiCall):
    def get_response(self, http_response, raw_content):
        if http_response.status_code not in SUCCESS_CODES:
            raise OscApiException(http_response)
        try:
            response = xmltodict.parse(raw_content)
        except Exception:
            response = "Unable to parse response: '{}'".format(raw_content)
        return response

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

    def build_request(self, action, *args, **kwargs):
        self._set_datestamp()

        # Calculate request params
        request_params = self.get_parameters(data=kwargs)

        if self.authentication_method == "password":
            request_params.update(self.get_password_params())

        request_params['Action'] = action
        if 'Version' not in request_params:
            request_params['Version'] = self.version
        request_params = urllib.parse.urlencode(request_params)

        # Calculate URL before request_params value is modified
        url = self.get_url(action, request_params)

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
                                      action),
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
                self.get_canonical_uri(action),
                canonical_params,
                canonical_headers,
                signed_headers,
                payload_hash,
            ]
        )
        headers.update({'User-agent': USER_AGENT})
        if self.authentication_method in ['accesskey', 'ephemeral']:
            headers.update({'Authorization': self.get_authorization_header(
                canonical_request,
                signed_headers,
            )})

        return url, headers, request_params


class FcuCall(XmlApiCall):
    API_NAME = 'fcu'


class LbuCall(XmlApiCall):
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


class EimCall(XmlApiCall):
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

    def get_parameters(self, data, action):
        return data

    def get_response(self, http_response, raw_content):
        if http_response.status_code not in SUCCESS_CODES:
            raise OscApiException(http_response)
        return json.loads(raw_content)

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

    def build_request(self, action, *args, **kwargs):
        self._set_datestamp()

        request_params = self.get_parameters(kwargs, action)

        if self.authentication_method == "password":
            request_params.update(self.get_password_params())

        json_params = json.dumps(request_params)

        target = '.'.join([self.SERVICE, action])

        signed_headers, canonical_headers, headers = self.build_headers(
            target, json_params)

        canonical_request = '\n'.join(
            [
                'POST',
                self.get_canonical_uri(action),
                '',
                canonical_headers,
                signed_headers,
                hashlib.sha256(json_params.encode('utf-8')).hexdigest(),
            ]
        )
        if self.authentication_method in ['accesskey', 'ephemeral']:
            headers.update({'Authorization': self.get_authorization_header(
                canonical_request,
                signed_headers,
            )})
        return self.get_url(action), headers, json_params

class IcuCall(JsonApiCall):
    API_NAME = 'icu'
    SERVICE = 'TinaIcuService'
    FILTERS_NAME_PATTERN = re.compile('^Filters.([0-9]*).Name$')
    FILTERS_VALUES_STR = '^Filters.%s.Values.[0-9]*$'

    def get_parameters(self, data, action):
        # Specific to Icu
        if self.authentication_method in ['accesskey', 'ephemeral']:
            data.update({'AuthenticationMethod': 'accesskey'})

        filters = self.get_filters(data)
        data = {k: v for k, v in data.items() if not k.startswith('Filters.')}
        return {'Action': action,
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

    def get_response(self, http_response, raw_content):
        if http_response.status_code not in SUCCESS_CODES:
            raise OscApiException(http_response)

        res = json.loads(raw_content)
        res['requestid'] = http_response.headers['x-amz-requestid']
        return res


class OKMSCall(JsonApiCall):
    API_NAME = 'kms'
    SERVICE = 'TrentService'


class OSCCall(JsonApiCall):
    API_NAME = 'api'
    CONTENT_TYPE = 'application/json'
    REQUEST_TYPE = 'osc4_request'
    SIG_ALGORITHM = 'OSC4-HMAC-SHA256'
    SIG_TYPE = 'OSC4'
    SERVICE = 'OutscaleService'

    def get_parameters(self, data, action):
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

    def get_url(self, action, request_params=None):
        url = '{}://{}'.format(self.protocol, self.host)
        if isinstance(self.path, str) and len(self.path) > 0:
            url += '{}'.format(self.path)
        if isinstance(action, str) and len(action) > 0:
            url += '/{}'.format(action)
        if self.method == 'GET':
            url += '?{}'.format(request_params)
        return url

    def get_canonical_uri(self, action):
        uri = ''
        if isinstance(self.path, str) and len(self.path) > 0:
            uri += '{}'.format(self.path)
        if isinstance(action, str) and len(action) > 0:
            uri += '/{}'.format(action)
        if len(uri) == 0:
            uri = '/'
        return uri

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


class HttpsAdapter(requests.adapters.BaseAdapter):
    """
    Adapter to use an external SSL engine (thanks to M2Crypto)
    https://docs.python-requests.org/en/master/_modules/requests/adapters/
    """

    def __init__(self, ssl_engine_id, ssl_engine_path, ssl_module_path):
        super(HttpsAdapter, self).__init__()
        self.ssl_engine_id = ssl_engine_id
        self.ssl_engine_path = ssl_engine_path
        self.ssl_module_path = ssl_module_path

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):

        url_parse = urllib.parse.urlparse(request.url)
        url_path_query = url_parse.path
        if url_parse.query:
            url_path_query += "?" + url_parse.query

        cert_path = None
        key_path = None
        try:
            (cert_path, key_path) = cert
        except ValueError:
            raise ValueError("Certificate and/or private key not configured")

        ssl_context = self.init_ssl_context(verify=verify, cert_path=cert_path, key_path=key_path)
        connection = M2Crypto.httpslib.HTTPSConnection(host=url_parse.netloc, ssl_context=ssl_context)
        connection.request(method=request.method, url=url_path_query, body=request.body, headers=request.headers)

        resp = urllib3.response.HTTPResponse.from_httplib(connection.getresponse())
        response = requests.models.Response()
        response.connection = self
        response.url = url_parse.geturl()
        response.headers = requests.structures.CaseInsensitiveDict(getattr(resp, "headers", {}))
        response.reason = getattr(resp, "reason", None)
        response.status_code = getattr(resp, "status", None)
        response.request = request
        response.raw = resp
        response.encoding = requests.utils.get_encoding_from_headers(response.headers)
        return response

    def close(self):
        pass

    def init_ssl_context(self, verify, cert_path, key_path):
        # More details on https://gitlab.com/m2crypto/m2crypto/-/blob/master/src/M2Crypto/SSL/Context.py
        ssl_context = M2Crypto.SSL.Context()
        if not verify:
            ssl_context.set_allow_unknown_ca(True)

        ssl_engine = self.init_ssl_engine()
        cert = ssl_engine.load_certificate(cert_path)
        key = ssl_engine.load_private_key(key_path)
        M2Crypto.m2.ssl_ctx_use_x509(ssl_context.ctx, cert.x509) # pylint: disable=E1101 # is part of swig
        M2Crypto.m2.ssl_ctx_use_pkey_privkey(ssl_context.ctx, key.pkey) # pylint: disable=E1101 # is part of swig
        return ssl_context

    def init_ssl_engine(self):
        if self.ssl_engine_path is not None:
            M2Crypto.Engine.load_dynamic_engine(self.ssl_engine_id, self.ssl_engine_path)
        ssl_engine = M2Crypto.Engine.Engine(self.ssl_engine_id)
        if self.ssl_module_path is not None:
            ssl_engine.ctrl_cmd_string("MODULE_PATH", self.ssl_module_path)

        M2Crypto.m2.engine_init(M2Crypto.m2.engine_by_id(self.ssl_engine_id)) # pylint: disable=E1101 # is part of swig
        return ssl_engine


def api_connect(service, action, profile=DEFAULT_PROFILE, login=None, password=None, authentication_method=DEFAULT_AUTHENTICATION_METHOD, ephemeral_ak_duration=DEFAULT_EPHEMERAL_AK_DURATION_S, interactive=False, *args, **kwargs):
    calls = {
        'api': OSCCall,
        'directlink': DirectLinkCall,
        'eim': EimCall,
        'fcu': FcuCall,
        'icu': IcuCall,
        'lbu': LbuCall,
        'okms': OKMSCall,
    }
    handler = calls[service](profile, login, password, authentication_method, ephemeral_ak_duration, interactive)
    handler.make_request(action, *args, **kwargs)
    if handler.response:
        print(json.dumps(handler.response, indent=4))


def main():
    logging.basicConfig(level=logging.INFO)
    fire.Fire(api_connect)


if __name__ == '__main__':
    try:
        main()
    except OscApiException as e:
        abort("{}".format(e))
    except Exception as e:
        abort("Unexpected error: {}".format(e))
