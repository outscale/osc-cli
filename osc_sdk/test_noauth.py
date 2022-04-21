import os
from dataclasses import dataclass

import pytest

from . import sdk


@dataclass
class Env:
    access_key: str
    secret_key: str
    endpoint_icu: str
    endpoint_api: str
    endpoint_fcu: str
    region: str


@pytest.fixture
def env() -> Env:
    return Env(
        access_key=os.getenv("OSC_TEST_ACCESS_KEY", ""),
        secret_key=os.getenv("OSC_TEST_SECRET_KEY", ""),
        endpoint_icu=os.getenv("OSC_TEST_ENDPOINT_ICU", ""),
        endpoint_api=os.getenv("OSC_TEST_ENDPOINT_API", ""),
        endpoint_fcu=os.getenv("OSC_TEST_ENDPOINT_FCU", ""),
        region=os.getenv("OSC_TEST_REGION", ""),
    )


def test_icu_noauth_call_with_auth_env(env):
    icu = sdk.IcuCall(
        access_key=env.access_key,
        secret_key=env.secret_key,
        endpoint=env.endpoint_icu,
        region_name=env.region,
    )
    icu.make_request("ReadPublicCatalog")
    assert len(icu.response)


def test_icu_noauth_call_with_empty_auth_env(env):
    icu = sdk.IcuCall(  # nosec
        access_key="",
        secret_key="",
        endpoint=env.endpoint_icu,
        region_name=env.region,
    )
    icu.make_request("ReadPublicCatalog")
    assert len(icu.response)


def test_icu_noauth_basic(env):
    icu = sdk.IcuCall(
        endpoint=env.endpoint_icu,
        region_name=env.region,
    )
    icu.make_request("ReadPublicCatalog")
    assert len(icu.response)


def test_api_noauth_call_with_auth_env(env):
    api = sdk.OSCCall(
        access_key=env.access_key,
        secret_key=env.secret_key,
        endpoint=env.endpoint_api,
        region_name=env.region,
    )
    api.make_request("ReadRegions")
    assert len(api.response)


def test_api_noauth_call_with_empty_auth_env(env):
    api = sdk.OSCCall(  # nosec
        access_key="",
        secret_key="",
        endpoint=env.endpoint_api,
        region_name=env.region,
    )
    api.make_request("ReadRegions")
    assert len(api.response)


def test_api_noauth_basic(env):
    api = sdk.OSCCall(
        endpoint=env.endpoint_api,
        region_name=env.region,
    )
    api.make_request("ReadRegions")
    assert len(api.response)


def test_fcu_noauth_call_with_auth_env(env):
    fcu = sdk.FcuCall(
        access_key=env.access_key,
        secret_key=env.secret_key,
        endpoint=env.endpoint_fcu,
        region_name=env.region,
    )
    fcu.make_request("ReadPublicIpRanges")
    assert len(fcu.response)


def test_fcu_noauth_call_with_empty_auth_env(env):
    fcu = sdk.FcuCall(  # nosec
        access_key="",
        secret_key="",
        endpoint=env.endpoint_fcu,
        region_name=env.region,
    )
    fcu.make_request("ReadPublicIpRanges")
    assert len(fcu.response)


def test_fcu_noauth_basic(env):
    fcu = sdk.FcuCall(
        endpoint=env.endpoint_fcu,
        region_name=env.region,
    )
    fcu.make_request("ReadPublicIpRanges")
    assert len(fcu.response)
