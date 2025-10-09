"""Tests for message validator."""
import pytest
from capiscio_a2a_security.validators.message import MessageValidator
from capiscio_a2a_security.types import ValidationSeverity


@pytest.fixture
def validator():
    """Create message validator instance."""
    return MessageValidator()


@pytest.fixture
def valid_message():
    """Create a valid test message."""
    return {
        "id": "msg_123",
        "sender": {"id": "agent_1", "url": "https://agent1.example.com"},
        "recipient": {"id": "agent_2", "url": "https://agent2.example.com"},
        "timestamp": 1234567890.0,
        "parts": [{"type": "text", "content": "Hello, world!"}],
    }


def test_validate_valid_message(validator, valid_message):
    """Test validation of a valid message."""
    result = validator.validate(valid_message)
    assert result.success
    assert result.score == 100
    assert len(result.issues) == 0


def test_validate_missing_required_field(validator, valid_message):
    """Test validation with missing required field."""
    del valid_message["id"]
    result = validator.validate(valid_message)
    assert not result.success
    assert result.score < 100
    assert any(i.code == "MISSING_FIELD" for i in result.errors)


def test_validate_invalid_message_id(validator, valid_message):
    """Test validation with invalid message ID type."""
    valid_message["id"] = 123
    result = validator.validate(valid_message)
    assert not result.success
    assert any(i.code == "INVALID_TYPE" and i.path == "id" for i in result.errors)


def test_validate_invalid_sender(validator, valid_message):
    """Test validation with invalid sender."""
    valid_message["sender"] = "not_an_object"
    result = validator.validate(valid_message)
    assert not result.success
    assert any(i.code == "INVALID_TYPE" and "sender" in i.path for i in result.errors)


def test_validate_sender_missing_id_and_url(validator, valid_message):
    """Test validation with sender missing both id and url."""
    valid_message["sender"] = {"name": "Agent 1"}
    result = validator.validate(valid_message)
    assert not result.success
    assert any(i.code == "MISSING_FIELD" and "sender.id" in i.path for i in result.errors)


def test_validate_invalid_timestamp(validator, valid_message):
    """Test validation with invalid timestamp."""
    valid_message["timestamp"] = "not_a_number"
    result = validator.validate(valid_message)
    assert not result.success
    assert any(i.code == "INVALID_TYPE" and i.path == "timestamp" for i in result.errors)


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


def test_validate_part_missing_type(validator, valid_message):
    """Test validation with part missing type field."""
    valid_message["parts"] = [{"content": "Hello"}]
    result = validator.validate(valid_message)
    assert not result.success
    assert any(i.code == "MISSING_FIELD" and "type" in i.path for i in result.errors)


def test_validate_part_unknown_type(validator, valid_message):
    """Test validation with unknown part type."""
    valid_message["parts"] = [{"type": "unknown_type", "content": "Hello"}]
    result = validator.validate(valid_message)
    assert result.success  # Unknown type is just a warning
    assert any(i.code == "UNKNOWN_TYPE" for i in result.warnings)


def test_validate_part_missing_content(validator, valid_message):
    """Test validation with part missing content/data."""
    valid_message["parts"] = [{"type": "text"}]
    result = validator.validate(valid_message)
    assert result.success  # Missing content is just a warning
    assert any(i.code == "MISSING_FIELD" for i in result.warnings)


def test_validate_multiple_errors(validator):
    """Test validation with multiple errors."""
    invalid_message = {"parts": "not_an_array"}
    result = validator.validate(invalid_message)
    assert not result.success
    assert len(result.errors) >= 5  # Multiple required fields missing
    assert result.score <= 10  # Score should be very low
