"""Tests for protocol validator."""
import pytest
from capiscio_sdk.validators.protocol import ProtocolValidator


@pytest.fixture
def validator():
    """Create protocol validator instance."""
    return ProtocolValidator()


def test_validate_supported_version(validator):
    """Test validation of supported protocol version."""
    result = validator.validate_protocol_version("1.0.0")
    assert result.success
    assert result.score == 100


def test_validate_unsupported_version(validator):
    """Test validation of unsupported protocol version."""
    result = validator.validate_protocol_version("2.0.0")
    assert result.success  # Still succeeds but with warning
    assert result.score == 60
    assert any(i.code == "UNSUPPORTED_VERSION" for i in result.warnings)


def test_validate_missing_version(validator):
    """Test validation with missing version."""
    result = validator.validate_protocol_version("")
    assert not result.success
    assert result.score == 0
    assert any(i.code == "MISSING_VERSION" for i in result.errors)


def test_validate_headers_valid(validator):
    """Test validation of valid headers."""
    headers = {
        "content-type": "application/json",
        "x-a2a-version": "1.0",
    }
    result = validator.validate_headers(headers)
    assert result.success
    assert result.score >= 90


def test_validate_headers_wrong_content_type(validator):
    """Test validation with wrong content type."""
    headers = {"content-type": "text/plain"}
    result = validator.validate_headers(headers)
    assert result.success  # Still succeeds but with warning
    assert any(i.code == "UNEXPECTED_CONTENT_TYPE" for i in result.warnings)


def test_validate_headers_missing_version(validator):
    """Test validation with missing version header."""
    headers = {"content-type": "application/json"}
    result = validator.validate_headers(headers)
    assert result.success  # Still succeeds but with warning
    assert any(i.code == "MISSING_HEADER" for i in result.warnings)


def test_validate_headers_proxy_detected(validator):
    """Test validation with proxy headers."""
    headers = {
        "content-type": "application/json",
        "x-forwarded-for": "1.2.3.4",
        "x-a2a-version": "1.0",
    }
    result = validator.validate_headers(headers)
    assert result.success
    assert any(i.code == "PROXY_HEADER" for i in result.issues)


def test_validate_message_type_valid(validator):
    """Test validation of valid message type."""
    result = validator.validate_message_type("request")
    assert result.success
    assert result.score == 100


def test_validate_message_type_unknown(validator):
    """Test validation of unknown message type."""
    result = validator.validate_message_type("custom")
    assert result.success  # Still succeeds
    assert result.score == 80
    assert any(i.code == "UNKNOWN_MESSAGE_TYPE" for i in result.warnings)


def test_validate_message_type_missing(validator):
    """Test validation with missing message type."""
    result = validator.validate_message_type(None)
    assert result.success  # Still succeeds
    assert result.score == 70
    assert any(i.code == "MISSING_MESSAGE_TYPE" for i in result.warnings)
