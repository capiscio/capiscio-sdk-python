"""Tests for error types."""
from capiscio_a2a_security.errors import (
    CapiscioSecurityError,
    CapiscioValidationError,
    CapiscioSignatureError,
    CapiscioRateLimitError,
)
from capiscio_a2a_security.types import (
    ValidationResult,
    ValidationIssue,
    ValidationSeverity,
)


def test_base_error():
    """Test base error."""
    error = CapiscioSecurityError("Test error", details={"key": "value"})
    assert str(error) == "Test error"
    assert error.details == {"key": "value"}


def test_validation_error():
    """Test validation error."""
    result = ValidationResult(
        success=False,
        score=50,
        issues=[
            ValidationIssue(
                severity=ValidationSeverity.ERROR, code="TEST", message="Test issue"
            )
        ],
    )
    error = CapiscioValidationError("Validation failed", result)
    assert error.validation_result == result
    assert len(error.errors) == 1
    assert error.errors[0] == "Test issue"


def test_signature_error():
    """Test signature error."""
    error = CapiscioSignatureError(
        "Signature invalid",
        agent_url="https://example.com",
        reason="Key not found",
    )
    assert error.agent_url == "https://example.com"
    assert error.reason == "Key not found"


def test_rate_limit_error():
    """Test rate limit error."""
    error = CapiscioRateLimitError("Rate limit exceeded", retry_after_seconds=60)
    assert error.retry_after_seconds == 60
