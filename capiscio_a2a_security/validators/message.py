"""Message validation logic."""
from typing import Any, Dict, List, Optional
from ..types import ValidationResult, ValidationIssue, ValidationSeverity
from .url_security import URLSecurityValidator


class MessageValidator:
    """Validates A2A message structure and content."""

    REQUIRED_FIELDS = ["id", "sender", "recipient", "timestamp", "parts"]
    VALID_PART_TYPES = ["text", "data", "tool_call", "tool_result", "error"]

    def __init__(self):
        """Initialize message validator."""
        self._url_validator = URLSecurityValidator()

    def validate(self, message: Dict[str, Any]) -> ValidationResult:
        """
        Validate an A2A message.

        Args:
            message: The message to validate

        Returns:
            ValidationResult with success status and any issues
        """
        issues: List[ValidationIssue] = []
        score = 100

        # Check required fields
        for field in self.REQUIRED_FIELDS:
            if field not in message:
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        code="MISSING_FIELD",
                        message=f"Required field '{field}' is missing",
                        path=field,
                    )
                )
                score -= 20

        # Validate message ID
        if "id" in message and not isinstance(message["id"], str):
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="INVALID_TYPE",
                    message="Message ID must be a string",
                    path="id",
                )
            )
            score -= 10

        # Validate sender
        if "sender" in message:
            sender_issues = self._validate_participant(message["sender"], "sender")
            issues.extend(sender_issues)
            score -= len(sender_issues) * 10

        # Validate recipient
        if "recipient" in message:
            recipient_issues = self._validate_participant(
                message["recipient"], "recipient"
            )
            issues.extend(recipient_issues)
            score -= len(recipient_issues) * 10

        # Validate timestamp
        if "timestamp" in message:
            if not isinstance(message["timestamp"], (int, float)):
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        code="INVALID_TYPE",
                        message="Timestamp must be a number",
                        path="timestamp",
                    )
                )
                score -= 10

        # Validate parts
        if "parts" in message:
            if not isinstance(message["parts"], list):
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        code="INVALID_TYPE",
                        message="Parts must be an array",
                        path="parts",
                    )
                )
                score -= 15
            else:
                parts_issues = self._validate_parts(message["parts"])
                issues.extend(parts_issues)
                score -= len(parts_issues) * 5

        # Ensure score doesn't go negative
        score = max(0, score)

        return ValidationResult(
            success=score >= 60 and not any(i.severity == ValidationSeverity.ERROR for i in issues),
            score=score,
            issues=issues,
        )

    def _validate_participant(
        self, participant: Any, field_name: str
    ) -> List[ValidationIssue]:
        """Validate sender or recipient structure."""
        issues: List[ValidationIssue] = []

        if not isinstance(participant, dict):
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="INVALID_TYPE",
                    message=f"{field_name.capitalize()} must be an object",
                    path=field_name,
                )
            )
            return issues

        # Check for ID or URL
        if "id" not in participant and "url" not in participant:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="MISSING_FIELD",
                    message=f"{field_name.capitalize()} must have 'id' or 'url'",
                    path=f"{field_name}.id",
                )
            )

        # Validate URL if present (with security checks)
        if "url" in participant and participant["url"]:
            url_result = self._url_validator.validate_url(
                participant["url"],
                field_name=f"{field_name}.url",
                require_https=True
            )
            # Add URL validation issues
            issues.extend(url_result.issues)

        return issues

    def _validate_parts(self, parts: List[Any]) -> List[ValidationIssue]:
        """Validate message parts array."""
        issues: List[ValidationIssue] = []

        if len(parts) == 0:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="EMPTY_ARRAY",
                    message="Parts array is empty",
                    path="parts",
                )
            )

        for i, part in enumerate(parts):
            if not isinstance(part, dict):
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        code="INVALID_TYPE",
                        message=f"Part {i} must be an object",
                        path=f"parts[{i}]",
                    )
                )
                continue

            # Validate type field
            if "type" not in part:
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        code="MISSING_FIELD",
                        message=f"Part {i} missing 'type' field",
                        path=f"parts[{i}].type",
                    )
                )
            elif part["type"] not in self.VALID_PART_TYPES:
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        code="UNKNOWN_TYPE",
                        message=f"Part {i} has unknown type '{part['type']}'",
                        path=f"parts[{i}].type",
                    )
                )

            # Validate content or data field
            if "content" not in part and "data" not in part:
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        code="MISSING_FIELD",
                        message=f"Part {i} should have 'content' or 'data'",
                        path=f"parts[{i}]",
                    )
                )

        return issues
