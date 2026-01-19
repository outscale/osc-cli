import json
from typing import List

import pytest

from .sdk import Problem, ProblemDecoder

RAW_JSONS: List[str] = [
    r'{"type":"/errors/unsupported_media_type","status":415,"title":"Unsupported Media Type","detail":"Expected request with `Content-Type: application/json`"}',
    r'{"type":"/errors/invalid_parameter","status":400,"title":"Bad Request","detail":"Origin: unknown variant `BAD_VALUE`, expected `OSC_KMS` or `EXTERNAL`"}',
    r'{"type":"/errors/invalid_parameter","status":400,"title":"Bad Request","detail":"missing field `KeyId`"}',
    """{"type":"/errors/invalid_parameter","status":400,"title":"Bad Request","detail":"KeyId: 'mck-toto' is not a key ID, an alias name, a key ORN or an alias ORN"}""",
    r'{"type":"/errors/invalid_parameter","status":404,"title":"Not Found","detail":"Key not found: mck-6480ba0cd94845deb4967f18c6b32cb1"}',
]


@pytest.mark.parametrize("raw_json", RAW_JSONS)
def test_decode_raw_json_errors(raw_json: str):
    """Test that ProblemDecoder can correctly decode raw JSON error strings."""
    decoded = json.loads(raw_json, cls=ProblemDecoder)
    assert isinstance(decoded, Problem)
