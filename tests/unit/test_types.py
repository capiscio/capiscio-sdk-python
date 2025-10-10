"""Tests for core types."""
from capiscio_a2a_security.types import (
    ValidationSeverity,
    ValidationIssue,
    ValidationResult,
    RateLimitInfo,
)


def test_validation_result_success():
    """Test successful validation result."""
    result = ValidationResult(success=True, score=100)
    assert result.success
    assert result.score == 100
    assert len(result.issues) == 0


def test_validation_result_with_issues():
    """Test validation result with issues."""
    result = ValidationResult(
        success=False,
        score=45,
        issues=[
            ValidationIssue(
                severity=ValidationSeverity.ERROR,
                code="SCHEMA_INVALID",
                message="Missing required field",
                path="message.parts",
            ),
            ValidationIssue(
                severity=ValidationSeverity.WARNING,
                code="DEPRECATED_FIELD",
                message="Field will be removed",
                path="message.old_field",
            ),
        ],
    )
    assert not result.success
    assert len(result.errors) == 1
    assert len(result.warnings) == 1
    assert result.errors[0].code == "SCHEMA_INVALID"
    assert result.warnings[0].code == "DEPRECATED_FIELD"


def test_rate_limit_info():
    """Test rate limit calculations."""
    info = RateLimitInfo(
        requests_allowed=100, requests_used=75, reset_at=1234567890.0
    )
    assert info.requests_remaining == 25


def test_rate_limit_info_exhausted():
    """Test rate limit when exhausted."""
    info = RateLimitInfo(
        requests_allowed=100, requests_used=100, reset_at=1234567890.0
    )
    assert info.requests_remaining == 0


def test_rate_limit_info_over_limit():
    """Test rate limit when over limit."""
    info = RateLimitInfo(
        requests_allowed=100, requests_used=105, reset_at=1234567890.0
    )
    assert info.requests_remaining == 0  # Can't go negative
