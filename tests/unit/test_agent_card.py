"""Tests for Agent Card validator."""

import pytest
from unittest.mock import AsyncMock, Mock
import httpx

from capiscio_a2a_security.validators.agent_card import AgentCardValidator
from capiscio_a2a_security.types import ValidationSeverity


@pytest.fixture
def validator():
    """Create agent card validator instance."""
    return AgentCardValidator()


@pytest.fixture
def valid_agent_card():
    """Create a valid agent card for testing."""
    return {
        "name": "Test Agent",
        "description": "A test agent for validation",
        "url": "https://example.com",
        "version": "1.0.0",
        "protocolVersion": "1.0.0",
        "preferredTransport": "JSONRPC",
        "capabilities": {
            "streaming": True,
            "pushNotifications": False,
            "batchProcessing": True
        },
        "provider": {
            "name": "Test Provider",
            "url": "https://provider.example.com"
        },
        "skills": [
            {
                "name": "test-skill",
                "description": "A test skill"
            }
        ]
    }


def test_validate_valid_agent_card(validator, valid_agent_card):
    """Test validation of a valid agent card."""
    result = validator.validate_agent_card(valid_agent_card)
    assert result.success
    assert result.score >= 80
    # May have warnings but no errors
    assert all(i.severity != ValidationSeverity.ERROR for i in result.issues)


def test_validate_missing_required_fields(validator):
    """Test validation fails when required fields are missing."""
    card = {"name": "Test Agent"}  # Missing most required fields
    result = validator.validate_agent_card(card)
    assert not result.success
    assert result.score < 50
    
    # Check that errors are reported for missing fields
    error_codes = [i.code for i in result.issues if i.severity == ValidationSeverity.ERROR]
    assert "MISSING_REQUIRED_FIELD" in error_codes


def test_validate_empty_required_fields(validator, valid_agent_card):
    """Test validation fails when required fields are empty."""
    valid_agent_card["name"] = ""
    valid_agent_card["description"] = "   "  # Whitespace only
    
    result = validator.validate_agent_card(valid_agent_card)
    assert not result.success
    
    error_codes = [i.code for i in result.issues if i.severity == ValidationSeverity.ERROR]
    assert "EMPTY_REQUIRED_FIELD" in error_codes


def test_validate_invalid_transport(validator, valid_agent_card):
    """Test validation fails with invalid transport protocol."""
    valid_agent_card["preferredTransport"] = "INVALID_TRANSPORT"
    
    result = validator.validate_agent_card(valid_agent_card)
    assert not result.success
    
    error_codes = [i.code for i in result.issues if i.severity == ValidationSeverity.ERROR]
    assert "INVALID_TRANSPORT" in error_codes


def test_validate_valid_transports(validator, valid_agent_card):
    """Test all valid transport protocols are accepted."""
    valid_transports = ["JSONRPC", "GRPC", "HTTP+JSON"]
    
    for transport in valid_transports:
        valid_agent_card["preferredTransport"] = transport
        result = validator.validate_agent_card(valid_agent_card)
        
        # Should not have transport errors
        transport_errors = [
            i for i in result.issues 
            if i.code == "INVALID_TRANSPORT" and i.severity == ValidationSeverity.ERROR
        ]
        assert len(transport_errors) == 0, f"Transport {transport} should be valid"


def test_validate_invalid_capabilities_type(validator, valid_agent_card):
    """Test validation fails when capabilities is not an object."""
    valid_agent_card["capabilities"] = "not an object"
    
    result = validator.validate_agent_card(valid_agent_card)
    assert not result.success
    
    error_codes = [i.code for i in result.issues if i.severity == ValidationSeverity.ERROR]
    assert "INVALID_CAPABILITIES_TYPE" in error_codes


def test_validate_empty_capabilities(validator, valid_agent_card):
    """Test warning when capabilities is empty."""
    valid_agent_card["capabilities"] = {}
    
    result = validator.validate_agent_card(valid_agent_card)
    # Should succeed but with warning
    assert result.success
    
    warning_codes = [i.code for i in result.issues if i.severity == ValidationSeverity.WARNING]
    assert "EMPTY_CAPABILITIES" in warning_codes


def test_validate_invalid_provider_type(validator, valid_agent_card):
    """Test validation fails when provider is not an object."""
    valid_agent_card["provider"] = "not an object"
    
    result = validator.validate_agent_card(valid_agent_card)
    assert not result.success
    
    error_codes = [i.code for i in result.issues if i.severity == ValidationSeverity.ERROR]
    assert "INVALID_PROVIDER_TYPE" in error_codes


def test_validate_provider_missing_name(validator, valid_agent_card):
    """Test validation fails when provider name is missing."""
    valid_agent_card["provider"] = {"url": "https://example.com"}
    
    result = validator.validate_agent_card(valid_agent_card)
    assert not result.success
    
    error_codes = [i.code for i in result.issues if i.severity == ValidationSeverity.ERROR]
    assert "MISSING_PROVIDER_FIELD" in error_codes


def test_validate_invalid_skills_type(validator, valid_agent_card):
    """Test validation fails when skills is not an array."""
    valid_agent_card["skills"] = "not an array"
    
    result = validator.validate_agent_card(valid_agent_card)
    assert not result.success
    
    error_codes = [i.code for i in result.issues if i.severity == ValidationSeverity.ERROR]
    assert "INVALID_SKILLS_TYPE" in error_codes


def test_validate_empty_skills(validator, valid_agent_card):
    """Test warning when skills array is empty."""
    valid_agent_card["skills"] = []
    
    result = validator.validate_agent_card(valid_agent_card)
    # Should succeed but with warning
    assert result.success
    
    warning_codes = [i.code for i in result.issues if i.severity == ValidationSeverity.WARNING]
    assert "EMPTY_SKILLS" in warning_codes


def test_validate_skill_missing_name(validator, valid_agent_card):
    """Test validation fails when skill is missing name."""
    valid_agent_card["skills"] = [
        {"description": "A skill without a name"}
    ]
    
    result = validator.validate_agent_card(valid_agent_card)
    assert not result.success
    
    error_codes = [i.code for i in result.issues if i.severity == ValidationSeverity.ERROR]
    assert "MISSING_SKILL_NAME" in error_codes


def test_validate_skill_missing_description(validator, valid_agent_card):
    """Test warning when skill is missing description."""
    valid_agent_card["skills"] = [
        {"name": "test-skill"}  # Missing description
    ]
    
    result = validator.validate_agent_card(valid_agent_card)
    # Should succeed but with warning
    assert result.success
    
    warning_codes = [i.code for i in result.issues if i.severity == ValidationSeverity.WARNING]
    assert "MISSING_SKILL_DESCRIPTION" in warning_codes


def test_validate_additional_interfaces(validator, valid_agent_card):
    """Test validation of additional interfaces."""
    valid_agent_card["additionalInterfaces"] = [
        {
            "url": "https://example.com/grpc",
            "transport": "GRPC"
        }
    ]
    
    result = validator.validate_agent_card(valid_agent_card)
    assert result.success


def test_validate_additional_interfaces_invalid_type(validator, valid_agent_card):
    """Test validation fails when additionalInterfaces is not an array."""
    valid_agent_card["additionalInterfaces"] = "not an array"
    
    result = validator.validate_agent_card(valid_agent_card)
    assert not result.success
    
    error_codes = [i.code for i in result.issues if i.severity == ValidationSeverity.ERROR]
    assert "INVALID_INTERFACES_TYPE" in error_codes


def test_validate_additional_interface_missing_url(validator, valid_agent_card):
    """Test validation fails when interface is missing URL."""
    valid_agent_card["additionalInterfaces"] = [
        {"transport": "GRPC"}  # Missing URL
    ]
    
    result = validator.validate_agent_card(valid_agent_card)
    assert not result.success
    
    error_codes = [i.code for i in result.issues if i.severity == ValidationSeverity.ERROR]
    assert "MISSING_INTERFACE_URL" in error_codes


def test_validate_additional_interface_missing_transport(validator, valid_agent_card):
    """Test validation fails when interface is missing transport."""
    valid_agent_card["additionalInterfaces"] = [
        {"url": "https://example.com/grpc"}  # Missing transport
    ]
    
    result = validator.validate_agent_card(valid_agent_card)
    assert not result.success
    
    error_codes = [i.code for i in result.issues if i.severity == ValidationSeverity.ERROR]
    assert "MISSING_INTERFACE_TRANSPORT" in error_codes


def test_validate_transport_url_conflict(validator, valid_agent_card):
    """Test validation fails when same URL has conflicting transports."""
    valid_agent_card["preferredTransport"] = "JSONRPC"
    valid_agent_card["additionalInterfaces"] = [
        {
            "url": "https://example.com",  # Same as main URL
            "transport": "GRPC"  # Different transport
        }
    ]
    
    result = validator.validate_agent_card(valid_agent_card)
    assert not result.success
    
    error_codes = [i.code for i in result.issues if i.severity == ValidationSeverity.ERROR]
    assert "TRANSPORT_URL_CONFLICT" in error_codes


@pytest.mark.asyncio
async def test_fetch_and_validate_success(validator, valid_agent_card):
    """Test successful agent card fetching and validation."""
    mock_response = Mock()
    mock_response.json.return_value = valid_agent_card
    mock_response.raise_for_status = Mock()
    
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    
    validator.http_client = mock_client
    
    result = await validator.fetch_and_validate("https://example.com")
    
    # Verify HTTP call was made
    assert mock_client.get.call_count >= 1
    call_url = str(mock_client.get.call_args[0][0])
    assert "/.well-known/agent-card.json" in call_url
    
    # Should succeed (may have minor warnings)
    assert result.success or result.score >= 50


@pytest.mark.asyncio
async def test_fetch_and_validate_http_error(validator):
    """Test handling of HTTP errors when fetching agent card."""
    mock_response = Mock()
    mock_response.status_code = 404
    
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(
        side_effect=httpx.HTTPStatusError(
            "Not Found",
            request=Mock(),
            response=mock_response
        )
    )
    
    validator.http_client = mock_client
    
    result = await validator.fetch_and_validate("https://example.com")
    
    assert not result.success
    error_codes = [i.code for i in result.issues if i.severity == ValidationSeverity.ERROR]
    # May get AGENT_CARD_HTTP_ERROR or AGENT_CARD_VALIDATION_ERROR depending on where it fails
    assert any(code in error_codes for code in ["AGENT_CARD_HTTP_ERROR", "AGENT_CARD_VALIDATION_ERROR"])


@pytest.mark.asyncio
async def test_fetch_and_validate_network_error(validator):
    """Test handling of network errors when fetching agent card."""
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(
        side_effect=httpx.RequestError("Connection failed")
    )
    
    validator.http_client = mock_client
    
    result = await validator.fetch_and_validate("https://example.com")
    
    assert not result.success
    error_codes = [i.code for i in result.issues if i.severity == ValidationSeverity.ERROR]
    # May get AGENT_CARD_FETCH_FAILED or AGENT_CARD_VALIDATION_ERROR depending on where it fails
    assert any(code in error_codes for code in ["AGENT_CARD_FETCH_FAILED", "AGENT_CARD_VALIDATION_ERROR"])
