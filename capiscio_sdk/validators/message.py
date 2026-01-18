"""Message validation logic."""
from typing import TYPE_CHECKING, Any, Dict, List
from ..types import ValidationResult, ValidationIssue, ValidationSeverity
# Import legacy scorer directly to avoid deprecation warning (we only use score_not_tested)
from ..scoring.availability import AvailabilityScorer as _LegacyAvailabilityScorer

if TYPE_CHECKING:
    from ..scoring.types import ComplianceScore
from .url_security import URLSecurityValidator


class MessageValidator:
    """Validates A2A message structure and content (per official A2A spec)."""

    # Based on official A2A specification from a2a-python SDK
    REQUIRED_FIELDS = ["messageId", "role", "parts"]
    VALID_ROLES = ["agent", "user"]
    VALID_PART_KINDS = ["text", "file", "data"]

    def __init__(self) -> None:
        """Initialize message validator."""
        self._url_validator = URLSecurityValidator()
        # Use legacy scorer directly (not the deprecated wrapper) for score_not_tested()
        self._availability_scorer = _LegacyAvailabilityScorer()

    def validate(self, message: Dict[str, Any], skip_signature_verification: bool = True) -> ValidationResult:
        """
        Validate an A2A message against official specification.

        Args:
            message: The message to validate (dict representation of Message object)
            skip_signature_verification: Whether to skip signature verification

        Returns:
            ValidationResult with three-dimensional scoring
        """
        issues: List[ValidationIssue] = []

        # Check required fields
        for field in self.REQUIRED_FIELDS:
            if field not in message:
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        code="MISSING_REQUIRED_FIELD",
                        message=f"Required field '{field}' is missing",
                        path=field,
                    )
                )

        # Validate messageId
        if "messageId" in message:
            if not isinstance(message["messageId"], str):
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        code="INVALID_TYPE",
                        message="messageId must be a string",
                        path="messageId",
                    )
                )
            elif not message["messageId"]:
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        code="EMPTY_FIELD",
                        message="messageId cannot be empty",
                        path="messageId",
                    )
                )

        # Validate role
        if "role" in message:
            if not isinstance(message["role"], str):
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        code="INVALID_TYPE",
                        message="role must be a string",
                        path="role",
                    )
                )
            elif message["role"] not in self.VALID_ROLES:
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        code="INVALID_VALUE",
                        message=f"role must be one of {self.VALID_ROLES}, got '{message['role']}'",
                        path="role",
                    )
                )

        # Validate parts
        if "parts" in message:
            if not isinstance(message["parts"], list):
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        code="INVALID_TYPE",
                        message="parts must be an array",
                        path="parts",
                    )
                )
            else:
                if len(message["parts"]) == 0:
                    issues.append(
                        ValidationIssue(
                            severity=ValidationSeverity.WARNING,
                            code="EMPTY_ARRAY",
                            message="parts array is empty",
                            path="parts",
                        )
                    )
                else:
                    parts_issues = self._validate_parts(message["parts"])
                    issues.extend(parts_issues)

        # Validate optional fields if present
        if "contextId" in message and message["contextId"] is not None:
            if not isinstance(message["contextId"], str):
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        code="INVALID_TYPE",
                        message="contextId must be a string if provided",
                        path="contextId",
                    )
                )

        if "taskId" in message and message["taskId"] is not None:
            if not isinstance(message["taskId"], str):
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        code="INVALID_TYPE",
                        message="taskId must be a string if provided",
                        path="taskId",
                    )
                )

        # Calculate compliance score (message structure adherence)
        compliance = self._calculate_message_compliance(message, issues)
        
        # Trust score not applicable to messages (only for agent cards)
        from ..scoring.types import TrustScore, TrustBreakdown, SignaturesBreakdown, ProviderBreakdown, SecurityBreakdown, DocumentationBreakdown, TrustRating
        trust = TrustScore(
            total=0,
            raw_score=0,
            rating=TrustRating.UNTRUSTED,
            confidence_multiplier=0.6,
            breakdown=TrustBreakdown(
                signatures=SignaturesBreakdown(score=0, max_score=0, tested=False, has_valid_signature=False, multiple_signatures=False, covers_all_fields=False, is_recent=False, has_invalid_signature=False, has_expired_signature=False),
                provider=ProviderBreakdown(score=0, max_score=0, tested=False, has_organization=False, has_url=False, url_reachable=None),
                security=SecurityBreakdown(score=0, max_score=0, https_only=False, has_security_schemes=False, has_strong_auth=False, has_http_urls=False),
                documentation=DocumentationBreakdown(score=0, max_score=0, has_documentation_url=False, has_terms_of_service=False, has_privacy_policy=False)
            ),
            issues=["Trust scoring not applicable to runtime messages (only for agent discovery/cards)"],
            partial_validation=True
        )
        
        # Availability not applicable for message validation
        availability = self._availability_scorer.score_not_tested("Not applicable for message validation")
        
        # Determine success
        has_errors = any(i.severity == ValidationSeverity.ERROR for i in issues)

        return ValidationResult(
            success=not has_errors,
            compliance=compliance,
            trust=trust,
            availability=availability,
            issues=issues,
        )
    
    def _calculate_message_compliance(self, message: Dict[str, Any], issues: List[ValidationIssue]) -> "ComplianceScore":
        """Calculate compliance score for message structure per A2A spec.
        
        Official A2A message structure scoring:
        - Required fields present (messageId, role, parts): 60 points
        - Valid types and values: 20 points  
        - Valid parts structure: 15 points
        - Data quality (non-empty messageId, valid part kinds): 5 points
        """
        from ..scoring.types import (
            ComplianceScore, ComplianceBreakdown,
            CoreFieldsBreakdown, SkillsQualityBreakdown,
            FormatComplianceBreakdown, DataQualityBreakdown,
            get_compliance_rating
        )
        
        score = 100
        
        # Check for missing required fields (60 points total, 20 per field)
        missing_fields = [f for f in self.REQUIRED_FIELDS if f not in message]
        score -= len(missing_fields) * 20
        
        # Check for type errors (20 points)
        type_errors = [i for i in issues if i.code == "INVALID_TYPE"]
        score -= min(len(type_errors) * 5, 20)
        
        # Check for invalid values (role, part kinds) (15 points)
        value_errors = [i for i in issues if i.code in ("INVALID_VALUE", "UNKNOWN_TYPE")]
        score -= min(len(value_errors) * 5, 15)
        
        # Check parts errors and data quality (5 points)
        parts_errors = [i for i in issues if i.path and "parts" in i.path and i.severity == ValidationSeverity.ERROR]
        score -= min(len(parts_errors) * 2, 5)
        
        score = max(0, min(100, score))
        
        # Create simplified breakdown
        present_fields = [f for f in self.REQUIRED_FIELDS if f in message]
        breakdown = ComplianceBreakdown(
            core_fields=CoreFieldsBreakdown(
                score=int(len(present_fields) / len(self.REQUIRED_FIELDS) * 60),
                max_score=60,
                present=present_fields,
                missing=missing_fields
            ),
            skills_quality=SkillsQualityBreakdown(score=0, max_score=0),  # N/A for messages
            format_compliance=FormatComplianceBreakdown(
                score=20 - min(len(type_errors) * 5, 20),
                max_score=20,
                valid_semver=True,  # N/A
                valid_protocol_version=True,  # N/A
                valid_url=True,  # N/A for messages
                valid_transports=True,  # N/A
                valid_mime_types=True  # N/A
            ),
            data_quality=DataQualityBreakdown(
                score=20 - min(len(value_errors) * 5 + len(parts_errors) * 2, 20),
                max_score=20,
                no_duplicate_skill_ids=True,  # N/A
                field_lengths_valid=bool("messageId" in message and message.get("messageId")),
                no_ssrf_risks=len([i for i in issues if "SSRF" in i.code or (i.path and "uri" in i.path.lower())]) == 0
            )
        )
        
        issue_messages = [i.message for i in issues if i.severity == ValidationSeverity.ERROR]
        
        return ComplianceScore(
            total=score,
            rating=get_compliance_rating(score),
            breakdown=breakdown,
            issues=issue_messages
        )

    def _validate_parts(self, parts: List[Any]) -> List[ValidationIssue]:
        """Validate message parts array (per A2A spec: TextPart, FilePart, DataPart)."""
        issues: List[ValidationIssue] = []

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

            # Check for 'kind' field (discriminator for Part types)
            if "kind" not in part:
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        code="MISSING_FIELD",
                        message=f"Part {i} missing 'kind' field",
                        path=f"parts[{i}].kind",
                    )
                )
                continue

            kind = part["kind"]
            if kind not in self.VALID_PART_KINDS:
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        code="UNKNOWN_TYPE",
                        message=f"Part {i} has unknown kind '{kind}' (expected: {self.VALID_PART_KINDS})",
                        path=f"parts[{i}].kind",
                    )
                )

            # Validate based on part type
            if kind == "text":
                if "text" not in part:
                    issues.append(
                        ValidationIssue(
                            severity=ValidationSeverity.ERROR,
                            code="MISSING_FIELD",
                            message=f"TextPart {i} must have 'text' field",
                            path=f"parts[{i}].text",
                        )
                    )
                elif not isinstance(part["text"], str):
                    issues.append(
                        ValidationIssue(
                            severity=ValidationSeverity.ERROR,
                            code="INVALID_TYPE",
                            message=f"TextPart {i} 'text' must be a string",
                            path=f"parts[{i}].text",
                        )
                    )

            elif kind == "file":
                if "file" not in part:
                    issues.append(
                        ValidationIssue(
                            severity=ValidationSeverity.ERROR,
                            code="MISSING_FIELD",
                            message=f"FilePart {i} must have 'file' field",
                            path=f"parts[{i}].file",
                        )
                    )
                else:
                    file_obj = part["file"]
                    if not isinstance(file_obj, dict):
                        issues.append(
                            ValidationIssue(
                                severity=ValidationSeverity.ERROR,
                                code="INVALID_TYPE",
                                message=f"FilePart {i} 'file' must be an object",
                                path=f"parts[{i}].file",
                            )
                        )
                    else:
                        # Must have either 'bytes' or 'uri'
                        if "bytes" not in file_obj and "uri" not in file_obj:
                            issues.append(
                                ValidationIssue(
                                    severity=ValidationSeverity.ERROR,
                                    code="MISSING_FIELD",
                                    message=f"FilePart {i} must have either 'bytes' or 'uri'",
                                    path=f"parts[{i}].file",
                                )
                            )

            elif kind == "data":
                if "data" not in part:
                    issues.append(
                        ValidationIssue(
                            severity=ValidationSeverity.ERROR,
                            code="MISSING_FIELD",
                            message=f"DataPart {i} must have 'data' field",
                            path=f"parts[{i}].data",
                        )
                    )
                elif not isinstance(part["data"], dict):
                    issues.append(
                        ValidationIssue(
                            severity=ValidationSeverity.ERROR,
                            code="INVALID_TYPE",
                            message=f"DataPart {i} 'data' must be an object",
                            path=f"parts[{i}].data",
                        )
                    )

        return issues
