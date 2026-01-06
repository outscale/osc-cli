import os
from dataclasses import dataclass

import pytest

from . import sdk


@dataclass
class Env(object):
    access_key: str
    secret_key: str
    endpoint_api: str
    region: str


@pytest.fixture
def env() -> Env:
    return Env(
        access_key=os.getenv("OSC_TEST_ACCESS_KEY", ""),
        secret_key=os.getenv("OSC_TEST_SECRET_KEY", ""),
        endpoint_api=os.getenv("OSC_TEST_ENDPOINT_API", ""),
        region=os.getenv("OSC_TEST_REGION", ""),
    )


def test_api_auth_ak_sk(env):
    api = sdk.OSCCall(
        access_key=env.access_key,
        secret_key=env.secret_key,
        endpoint=env.endpoint_api,
        region_name=env.region,
    )
    api.make_request("ReadAccounts")
    assert len(api.response) > 0
