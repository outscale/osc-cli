import os
from dataclasses import dataclass

import pytest

from . import sdk


@dataclass
class Env(object):
    access_key: str
    secret_key: str
    endpoint_icu: str
    region: str


@pytest.fixture
def env() -> Env:
    return Env(
        access_key=os.getenv("OSC_TEST_ACCESS_KEY", ""),
        secret_key=os.getenv("OSC_TEST_SECRET_KEY", ""),
        endpoint_icu=os.getenv("OSC_TEST_ENDPOINT_ICU", ""),
        region=os.getenv("OSC_TEST_REGION", ""),
    )


def test_icu_auth_ak_sk(env):
    icu = sdk.IcuCall(
        access_key=env.access_key,
        secret_key=env.secret_key,
        endpoint=env.endpoint_icu,
        region_name=env.region,
    )
    icu.make_request("GetAccount")
    assert len(icu.response) > 0
