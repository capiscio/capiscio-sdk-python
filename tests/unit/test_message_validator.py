"""Tests for message validator."""
import pytest
from capiscio_sdk.validators.message import MessageValidator


@pytest.fixture
def validator():
    """Create message validator instance."""
    return MessageValidator()


@pytest.fixture
def valid_message():
    """Create a valid test message (per A2A v1 ProtoJSON spec)."""
    return {
        "messageId": "msg_123",
        "role": "ROLE_USER",
        "parts": [{"text": "Hello, world!"}],
    }


def test_validate_valid_message(validator, valid_message):
    """Test validation of a valid message."""
    result = validator.validate(valid_message)
    assert result.success
    assert result.compliance.total == 100
    assert len(result.issues) == 0


def test_validate_missing_required_field(validator, valid_message):
    """Test validation with missing required field."""
    del valid_message["messageId"]
    result = validator.validate(valid_message)
    assert not result.success
    assert result.compliance.total < 100
    assert any(i.code == "MISSING_REQUIRED_FIELD" for i in result.issues)


def test_validate_invalid_message_id(validator, valid_message):
    """Test validation with invalid messageId type."""
    valid_message["messageId"] = 123
    result = validator.validate(valid_message)
    assert not result.success
    assert any(i.code == "INVALID_TYPE" and i.path == "messageId" for i in result.errors)


def test_validate_empty_message_id(validator, valid_message):
    """Test validation with empty messageId."""
    valid_message["messageId"] = ""
    result = validator.validate(valid_message)
    assert not result.success
    assert any(i.code == "EMPTY_FIELD" and i.path == "messageId" for i in result.errors)


def test_validate_invalid_role(validator, valid_message):
    """Test validation with invalid role."""
    valid_message["role"] = "invalid_role"
    result = validator.validate(valid_message)
    assert not result.success
    assert any(i.code == "INVALID_VALUE" and i.path == "role" for i in result.errors)


def test_validate_missing_role(validator, valid_message):
    """Test validation with missing role."""
    del valid_message["role"]
    result = validator.validate(valid_message)
    assert not result.success
    assert any(i.code == "MISSING_REQUIRED_FIELD" and i.path == "role" for i in result.errors)


def test_validate_valid_agent_role(validator, valid_message):
    """Test validation with valid agent role."""
    valid_message["role"] = "ROLE_AGENT"
    result = validator.validate(valid_message)
    assert result.success
    assert result.compliance.total == 100


def test_validate_invalid_parts_type(validator, valid_message):
    """Test validation with invalid parts type."""
    valid_message["parts"] = "not_an_array"
    result = validator.validate(valid_message)
    assert not result.success
    assert any(i.code == "INVALID_TYPE" and i.path == "parts" for i in result.errors)


def test_validate_empty_parts(validator, valid_message):
    """Test validation with empty parts array."""
    valid_message["parts"] = []
    result = validator.validate(valid_message)
    assert result.success  # Empty parts is just a warning
    assert any(i.code == "EMPTY_ARRAY" for i in result.warnings)


def test_validate_part_with_text_content(validator, valid_message):
    """Test validation with valid text part (A2A v1 oneof content)."""
    valid_message["parts"] = [{"text": "Hello"}]
    result = validator.validate(valid_message)
    assert result.success


def test_validate_part_missing_content(validator, valid_message):
    """Test validation with part missing all oneof content fields."""
    valid_message["parts"] = [{"metadata": {}}]  # No text/raw/url/data
    result = validator.validate(valid_message)
    assert not result.success
    assert any(i.code == "MISSING_FIELD" for i in result.errors)


def test_validate_url_part(validator, valid_message):
    """Test validation with valid URL part."""
    valid_message["parts"] = [{"url": "https://example.com/file.txt"}]
    result = validator.validate(valid_message)
    assert result.success


def test_validate_data_part_valid(validator, valid_message):
    """Test validation with valid data part (A2A v1 oneof)."""
    valid_message["parts"] = [{"data": {"key": "value"}}]
    result = validator.validate(valid_message)
    assert result.success


def test_validate_multiple_errors(validator):
    """Test validation with multiple errors."""
    invalid_message = {"parts": "not_an_array"}
    result = validator.validate(invalid_message)
    assert not result.success
    assert len(result.errors) >= 3  # Missing messageId, role, invalid parts
    assert result.compliance.total <= 60  # Score should be low (missing 2 required fields + invalid parts)
