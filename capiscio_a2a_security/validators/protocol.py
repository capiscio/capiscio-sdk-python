"""Protocol-level validation logic."""
from typing import Dict, List, Optional
from ..types import ValidationResult, ValidationIssue, ValidationSeverity, create_simple_validation_result
from .semver import SemverValidator


class ProtocolValidator:
    """Validates A2A protocol compliance."""

    SUPPORTED_VERSIONS = ["1.0", "1.0.0", "0.3.0"]
    VALID_MESSAGE_TYPES = ["request", "response", "event", "error"]

    def __init__(self) -> None:
        """Initialize protocol validator."""
        self._semver_validator = SemverValidator()

    def validate_protocol_version(self, version: str) -> ValidationResult:
        """
        Validate A2A protocol version.

        Args:
            version: Protocol version string

        Returns:
            ValidationResult indicating if version is supported
        """
        issues: List[ValidationIssue] = []
        score = 100

        if not version:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="MISSING_VERSION",
                    message="Protocol version is required",
                    path="version",
                )
            )
            score = 0
        else:
            # Validate semver format
            semver_result = self._semver_validator.validate_version(version, "protocolVersion")
            issues.extend(semver_result.issues)
            
            # Check if version is supported
            if version not in self.SUPPORTED_VERSIONS:
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        code="UNSUPPORTED_VERSION",
                        message=f"Protocol version '{version}' may not be supported",
                        path="version",
                    )
                )
                score = 60

        return create_simple_validation_result(
            success=score > 0 and not any(i.severity == ValidationSeverity.ERROR for i in issues),
            issues=issues,
            simple_score=score,
            dimension="compliance"
        )

    def validate_headers(self, headers: Dict[str, str]) -> ValidationResult:
        """
        Validate A2A protocol headers.

        Args:
            headers: HTTP headers dictionary

        Returns:
            ValidationResult for headers
        """
        issues: List[ValidationIssue] = []
        score = 100

        # Check Content-Type
        content_type = headers.get("content-type", "").lower()
        if content_type and "application/json" not in content_type:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="UNEXPECTED_CONTENT_TYPE",
                    message=f"Expected application/json, got {content_type}",
                    path="headers.content-type",
                )
            )
            score -= 10

        # Check for A2A version header
        if "x-a2a-version" not in headers and "X-A2A-Version" not in headers:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="MISSING_HEADER",
                    message="X-A2A-Version header is recommended",
                    path="headers.x-a2a-version",
                )
            )
            score -= 5

        # Check for suspicious headers
        for header in headers:
            if header.lower().startswith("x-forwarded-"):
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.INFO,
                        code="PROXY_HEADER",
                        message=f"Proxy header detected: {header}",
                        path=f"headers.{header}",
                    )
                )

        score = max(0, score)

        return create_simple_validation_result(
            success=score >= 70,
            issues=issues,
            simple_score=score,
            dimension="compliance"
        )

    def validate_message_type(self, message_type: Optional[str]) -> ValidationResult:
        """
        Validate message type.

        Args:
            message_type: Type of message

        Returns:
            ValidationResult for message type
        """
        issues: List[ValidationIssue] = []
        score = 100

        if not message_type:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="MISSING_MESSAGE_TYPE",
                    message="Message type not specified",
                    path="type",
                )
            )
            score = 70
        elif message_type not in self.VALID_MESSAGE_TYPES:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="UNKNOWN_MESSAGE_TYPE",
                    message=f"Unknown message type: {message_type}",
                    path="type",
                )
            )
            score = 80

        return create_simple_validation_result(
            success=True,  # Message type is informational
            issues=issues,
            simple_score=score,
            dimension="compliance"
        )
