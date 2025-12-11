"""Tests for CoreValidator (Go core-backed validation)."""
from unittest.mock import MagicMock, patch

from capiscio_sdk.validators._core import CoreValidator, validate_agent_card
from capiscio_sdk.types import ValidationSeverity


# Sample agent card for testing
VALID_AGENT_CARD = {
    "name": "Test Agent",
    "description": "A test agent for validation",
    "url": "https://example.com/agent",
    "version": "1.0.0",
    "protocolVersion": "0.3.0",
    "preferredTransport": "JSONRPC",
    "capabilities": {
        "streaming": True,
        "pushNotifications": False,
    },
    "provider": {
        "name": "Test Provider",
        "url": "https://provider.example.com",
    },
    "skills": [
        {
            "id": "skill1",
            "name": "Test Skill",
            "description": "A test skill",
            "tags": ["test"],
        }
    ],
    "defaultInputModes": ["text"],
    "defaultOutputModes": ["text"],
}

INVALID_AGENT_CARD = {
    "name": "Missing Fields Agent",
    # Missing required fields: url, version, protocolVersion, etc.
}

# Mock Go core response
MOCK_GO_CORE_RESPONSE = {
    "overall_score": 0.85,
    "rating": 2,  # RATING_GOOD
    "categories": [
        {"category": 1, "score": 0.9},  # COMPLIANCE
        {"category": 2, "score": 0.8},  # SECURITY
    ],
    "rule_results": [],
    "validation": {
        "valid": True,
        "issues": [],
    },
    "rule_set_id": "default",
    "rule_set_version": "1.0.0",
}

MOCK_GO_CORE_RESPONSE_INVALID = {
    "overall_score": 0.3,
    "rating": 4,  # RATING_POOR
    "categories": [
        {"category": 1, "score": 0.3},
        {"category": 2, "score": 0.3},
    ],
    "rule_results": [
        {
            "rule_id": "MISSING_URL",
            "passed": False,
            "message": "Agent card missing required field: url",
        },
        {
            "rule_id": "MISSING_VERSION",
            "passed": False,
            "message": "Agent card missing required field: version",
        },
    ],
    "validation": {
        "valid": False,
        "issues": [
            {
                "code": "MISSING_URL",
                "message": "Agent card missing required field: url",
                "severity": 1,  # ERROR
                "field": "url",
            },
            {
                "code": "MISSING_VERSION",
                "message": "Agent card missing required field: version",
                "severity": 1,
                "field": "version",
            },
        ],
    },
    "rule_set_id": "default",
    "rule_set_version": "1.0.0",
}


class TestCoreValidator:
    """Tests for CoreValidator class."""

    @patch("capiscio_sdk.validators._core.CapiscioRPCClient")
    def test_validate_valid_card(self, mock_client_class):
        """Test validation of a valid agent card."""
        # Setup mock
        mock_client = MagicMock()
        mock_client.scoring.score_agent_card.return_value = (MOCK_GO_CORE_RESPONSE, None)
        mock_client_class.return_value = mock_client

        # Run validation
        validator = CoreValidator()
        result = validator.validate_agent_card(VALID_AGENT_CARD)

        # Assertions
        assert result.success is True
        assert result.compliance is not None
        assert result.compliance.total == 90  # 0.9 * 100
        assert result.trust is not None
        assert result.trust.total == 80  # 0.8 * 100
        assert len(result.issues) == 0

        # Verify Go core was called
        mock_client.scoring.score_agent_card.assert_called_once()
        call_args = mock_client.scoring.score_agent_card.call_args[0][0]
        assert "Test Agent" in call_args

    @patch("capiscio_sdk.validators._core.CapiscioRPCClient")
    def test_validate_invalid_card(self, mock_client_class):
        """Test validation of an invalid agent card."""
        # Setup mock
        mock_client = MagicMock()
        mock_client.scoring.score_agent_card.return_value = (MOCK_GO_CORE_RESPONSE_INVALID, None)
        mock_client_class.return_value = mock_client

        # Run validation
        validator = CoreValidator()
        result = validator.validate_agent_card(INVALID_AGENT_CARD)

        # Assertions
        assert result.success is False
        assert len(result.issues) == 2
        assert any(i.code == "MISSING_URL" for i in result.issues)
        assert any(i.code == "MISSING_VERSION" for i in result.issues)
        assert all(i.severity == ValidationSeverity.ERROR for i in result.issues)

    @patch("capiscio_sdk.validators._core.CapiscioRPCClient")
    def test_validate_error_handling(self, mock_client_class):
        """Test error handling when Go core returns an error."""
        # Setup mock to return error
        mock_client = MagicMock()
        mock_client.scoring.score_agent_card.return_value = (None, "Connection failed")
        mock_client_class.return_value = mock_client

        # Run validation
        validator = CoreValidator()
        result = validator.validate_agent_card(VALID_AGENT_CARD)

        # Assertions
        assert result.success is False
        assert len(result.issues) == 1
        assert result.issues[0].code == "CORE_VALIDATION_ERROR"
        assert "Connection failed" in result.issues[0].message

    @patch("capiscio_sdk.validators._core.CapiscioRPCClient")
    def test_validate_metadata_populated(self, mock_client_class):
        """Test that metadata is populated from Go core response."""
        # Setup mock
        mock_client = MagicMock()
        mock_client.scoring.score_agent_card.return_value = (MOCK_GO_CORE_RESPONSE, None)
        mock_client_class.return_value = mock_client

        # Run validation
        validator = CoreValidator()
        result = validator.validate_agent_card(VALID_AGENT_CARD)

        # Assertions
        assert result.metadata.get("source") == "go_core"
        assert result.metadata.get("overall_score") == 0.85
        assert result.metadata.get("rule_set_id") == "default"

    @patch("capiscio_sdk.validators._core.CapiscioRPCClient")
    def test_context_manager(self, mock_client_class):
        """Test CoreValidator as context manager."""
        mock_client = MagicMock()
        mock_client.scoring.score_agent_card.return_value = (MOCK_GO_CORE_RESPONSE, None)
        mock_client_class.return_value = mock_client

        with CoreValidator() as validator:
            result = validator.validate_agent_card(VALID_AGENT_CARD)
            assert result.success is True

        # Verify close was called
        mock_client.close.assert_called_once()


class TestValidateAgentCardFunction:
    """Tests for validate_agent_card convenience function."""

    @patch("capiscio_sdk.validators._core.CapiscioRPCClient")
    def test_convenience_function(self, mock_client_class):
        """Test the validate_agent_card convenience function."""
        mock_client = MagicMock()
        mock_client.scoring.score_agent_card.return_value = (MOCK_GO_CORE_RESPONSE, None)
        mock_client_class.return_value = mock_client

        result = validate_agent_card(VALID_AGENT_CARD)

        assert result.success is True
        assert result.compliance.total == 90


class TestIssueConversion:
    """Tests for issue severity conversion from Go core."""

    @patch("capiscio_sdk.validators._core.CapiscioRPCClient")
    def test_severity_mapping(self, mock_client_class):
        """Test that Go core severity values map correctly to SDK types."""
        mock_response = {
            "overall_score": 0.5,
            "rating": 3,
            "categories": [],
            "rule_results": [],
            "validation": {
                "valid": False,
                "issues": [
                    {"code": "TEST_ERROR", "message": "Error", "severity": 1, "field": "test"},
                    {"code": "TEST_WARNING", "message": "Warning", "severity": 2, "field": "test"},
                    {"code": "TEST_INFO", "message": "Info", "severity": 3, "field": "test"},
                ],
            },
            "rule_set_id": "default",
            "rule_set_version": "1.0.0",
        }

        mock_client = MagicMock()
        mock_client.scoring.score_agent_card.return_value = (mock_response, None)
        mock_client_class.return_value = mock_client

        validator = CoreValidator()
        result = validator.validate_agent_card(VALID_AGENT_CARD)

        # Check severity mapping
        error_issues = [i for i in result.issues if i.severity == ValidationSeverity.ERROR]
        warning_issues = [i for i in result.issues if i.severity == ValidationSeverity.WARNING]
        info_issues = [i for i in result.issues if i.severity == ValidationSeverity.INFO]

        assert len(error_issues) == 1
        assert len(warning_issues) == 1
        assert len(info_issues) == 1
