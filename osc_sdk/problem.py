import json

import defusedxml.ElementTree as ET


class ProblemDecoder(json.JSONDecoder):
    def decode(self, s):
        data = super().decode(s)
        if isinstance(data, dict):
            return self._make_problem(data)
        return data

    def _make_problem(self, data):
        type_ = data.pop("type", None)
        status = data.pop("status", None)
        title = data.pop("title", None)
        detail = data.pop("detail", None)
        instance = data.pop("instance", None)
        return Problem(type_, status, title, detail, instance, **data)


class Problem(Exception):
    def __init__(self, type_, status, title, detail, instance, **kwargs):
        self._type = type_ or "about:blank"
        self.status = status
        self.title = title
        self.detail = detail
        self.instance = instance
        self.extras = kwargs

        for k in self.extras:
            if k in ["type", "status", "title", "detail", "instance"]:
                raise ValueError(f"Reserved key '{k}' used in Problem extra arguments.")

    def __str__(self):
        return self.title

    def __repr__(self):
        return f"{self.__class__.__name__}<type={self._type}; status={self.status}; title={self.title}>"

    def msg(self):
        msg = (
            f"type = {self._type}, "
            f"status = {self.status}, "
            f"title = {self.title}, "
            f"detail = {self.detail}, "
            f"instance = {self.instance}, "
            f"extras = {self.extras}"
        )
        return msg

    @property
    def type(self):
        return self._type


class LegacyProblemDecoder(json.JSONDecoder):
    def decode(self, s):
        data = super().decode(s)
        if isinstance(data, dict):
            return self._make_legacy_problem(data)
        return data

    def _make_legacy_problem(self, data):
        request_id = None
        error_code = None
        code_type = None

        if "__type" in data:
            error_code = data.get("__type")
        else:
            request_id = (data.get("ResponseContext") or {}).get("RequestId")
            errors = data.get("Errors")
            if errors:
                error = errors[0]
                error_code = error.get("Code")
                reason = error.get("Type")
                if error.get("Details"):
                    code_type = reason
                else:
                    code_type = None
        return LegacyProblem(None, error_code, code_type, request_id, None)


class LegacyProblem(Exception):
    def __init__(self, status, error_code, code_type, request_id, url):
        self.status = status
        self.error_code = error_code
        self.code_type = code_type
        self.request_id = request_id
        self.url = url

    def msg(self):
        msg = (
            f"status = {self.status}, "
            f"code = {self.error_code}, "
            f"{'code_type = ' if self.code_type is not None else ''}"
            f"{self.code_type + ', ' if self.code_type is not None else ''}"
            f"request_id = {self.request_id}, "
            f"url = {self.url}"
        )
        return msg


def api_error(response):
    try:
        problem = None
        ct = response.headers.get("content-type") or ""
        if "application/json" in ct:
            problem = response.json(cls=LegacyProblemDecoder)
            problem.status = problem.status or str(response.status_code)
            problem.url = response.url
        elif "application/problem+json" in ct:
            problem = response.json(cls=ProblemDecoder)
            problem.status = problem.status or str(response.status_code)

        if problem:
            return problem
    except json.JSONDecodeError:
        pass

    try:
        error = ET.fromstring(response.text)

        err = dict()
        for key, attr in [
            ("Code", "error_code"),
            ("Message", "status"),
            ("RequestId", "request_id"),
            ("RequestID", "request_id"),
        ]:
            value = next((x.text for x in error.iter() if x.tag.endswith(key)), None)
            if value:
                err[attr] = value

        return LegacyProblem(**err)
    except:
        raise Exception(
            f"Could not decode error response from {response.url} with status code {response.status_code}"
        )
