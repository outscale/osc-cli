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


# issue #116
def test_bad_filter(env):
    oapi = sdk.OSCCall(
        access_key=env.access_key,
        secret_key=env.secret_key,
        endpoint=env.endpoint_api,
        region_name=env.region,
    )
    with pytest.raises(sdk.OscApiException) as e:
        oapi.make_request("ReadImages", Filters='"bad_filter"')
    assert e.value.status_code == 400
