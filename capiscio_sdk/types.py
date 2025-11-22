"""Core types for Capiscio Python SDK."""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from enum import Enum
import warnings


class ValidationSeverity(str, Enum):
    """Severity level for validation issues."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ValidationIssue(BaseModel):
    """A single validation issue."""

    severity: ValidationSeverity
    code: str
    message: str
    path: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class ValidationResult(BaseModel):
    """Result of a validation operation with multi-dimensional scoring.
    
    Provides three independent score dimensions:
    - compliance: A2A protocol specification adherence (0-100)
    - trust: Security and authenticity signals (0-100)
    - availability: Operational readiness (0-100, optional)
    
    The legacy `score` field is maintained for backward compatibility
    and returns the compliance.total value.
    """

    success: bool
    issues: List[ValidationIssue] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    # Three-dimensional scores
    compliance: Optional["ComplianceScore"] = None
    trust: Optional["TrustScore"] = None
    availability: Optional["AvailabilityScore"] = None
    
    # Legacy single score (deprecated, for backward compatibility)
    legacy_score: Optional[int] = Field(default=None, alias="score")
    
    @property
    def score(self) -> int:
        """Legacy score property for backward compatibility.
        
        Returns the compliance score total. This property is deprecated.
        Use result.compliance.total instead.
        
        Returns:
            Compliance score (0-100)
        """
        warnings.warn(
            "The 'score' property is deprecated. Use 'compliance.total', "
            "'trust.total', or 'availability.total' instead for more specific scoring.",
            DeprecationWarning,
            stacklevel=2
        )
        
        # Return compliance score if available, otherwise legacy score, otherwise 0
        if self.compliance:
            return self.compliance.total
        if self.legacy_score is not None:
            return self.legacy_score
        return 0
    
    @property
    def recommendation(self) -> str:
        """Get overall recommendation based on all score dimensions.
        
        Returns:
            Human-readable recommendation string
        """
        if not self.compliance or not self.trust:
            return "Incomplete validation - run full validation for recommendations"
        
        compliance_total = self.compliance.total
        trust_total = self.trust.total
        
        # Both high
        if compliance_total >= 90 and trust_total >= 80:
            return "Excellent - Highly compliant and trusted agent"
        
        # High compliance, lower trust
        if compliance_total >= 90 and trust_total < 60:
            return "Good compliance but low trust - verify signatures and security"
        
        # High trust, lower compliance
        if trust_total >= 80 and compliance_total < 75:
            return "Trusted but not fully compliant - fix spec violations"
        
        # Both moderate
        if compliance_total >= 60 and trust_total >= 40:
            return "Acceptable - improvements recommended"
        
        # Low scores
        return "Not recommended - significant issues found"

    @property
    def errors(self) -> List[ValidationIssue]:
        """Get only error-level issues."""
        return [i for i in self.issues if i.severity == ValidationSeverity.ERROR]

    @property
    def warnings(self) -> List[ValidationIssue]:
        """Get only warning-level issues."""
        return [i for i in self.issues if i.severity == ValidationSeverity.WARNING]


# Import here to avoid circular dependency
from .scoring.types import ComplianceScore, TrustScore, AvailabilityScore  # noqa: E402

# Update forward references
ValidationResult.model_rebuild()


# Helper function for simple validators
def create_simple_validation_result(
    success: bool,
    issues: List[ValidationIssue],
    simple_score: int = 100,
    dimension: str = "compliance"
) -> ValidationResult:
    """Create a ValidationResult for simple validators that don't need full scoring.
    
    Args:
        success: Whether validation succeeded
        issues: List of validation issues
        simple_score: Simple 0-100 score
        dimension: Which dimension to apply score to ("compliance" or "trust")
        
    Returns:
        ValidationResult with simplified scoring
    """
    from .scoring.types import (
        ComplianceScore, TrustScore, ComplianceBreakdown, TrustBreakdown,
        CoreFieldsBreakdown, SkillsQualityBreakdown,
        FormatComplianceBreakdown, DataQualityBreakdown,
        SignaturesBreakdown, ProviderBreakdown,
        SecurityBreakdown, DocumentationBreakdown,
        get_compliance_rating, get_trust_rating
    )
    
    issue_messages = [i.message for i in issues if i.severity == ValidationSeverity.ERROR]
    
    if dimension == "compliance":
        # Create minimal compliance score
        compliance = ComplianceScore(
            total=simple_score,
            rating=get_compliance_rating(simple_score),
            breakdown=ComplianceBreakdown(
                core_fields=CoreFieldsBreakdown(score=simple_score, present=[], missing=[]),
                skills_quality=SkillsQualityBreakdown(score=0),
                format_compliance=FormatComplianceBreakdown(score=0),
                data_quality=DataQualityBreakdown(score=0)
            ),
            issues=issue_messages
        )
        trust = TrustScore(
            total=0,
            raw_score=0,
            confidence_multiplier=0.6,
            rating=get_trust_rating(0),
            breakdown=TrustBreakdown(
                signatures=SignaturesBreakdown(score=0),
                provider=ProviderBreakdown(score=0),
                security=SecurityBreakdown(score=0),
                documentation=DocumentationBreakdown(score=0)
            )
        )
    else:  # trust
        compliance = ComplianceScore(
            total=0,
            rating=get_compliance_rating(0),
            breakdown=ComplianceBreakdown(
                core_fields=CoreFieldsBreakdown(score=0, present=[], missing=[]),
                skills_quality=SkillsQualityBreakdown(score=0),
                format_compliance=FormatComplianceBreakdown(score=0),
                data_quality=DataQualityBreakdown(score=0)
            )
        )
        trust = TrustScore(
            total=simple_score,
            raw_score=simple_score,
            confidence_multiplier=1.0,
            rating=get_trust_rating(simple_score),
            breakdown=TrustBreakdown(
                signatures=SignaturesBreakdown(score=simple_score),
                provider=ProviderBreakdown(score=0),
                security=SecurityBreakdown(score=0),
                documentation=DocumentationBreakdown(score=0)
            ),
            issues=issue_messages
        )
    
    from .scoring import AvailabilityScorer
    availability_scorer = AvailabilityScorer()
    availability = availability_scorer.score_not_tested("Not applicable")
    
    return ValidationResult(
        success=success,
        compliance=compliance,
        trust=trust,
        availability=availability,
        issues=issues
    )


class CacheEntry(BaseModel):
    """Cached validation result with TTL."""

    result: ValidationResult
    cached_at: float  # Unix timestamp
    ttl: int  # Seconds


class RateLimitInfo(BaseModel):
    """Rate limit information."""

    requests_allowed: int
    requests_used: int
    reset_at: float  # Unix timestamp

    @property
    def requests_remaining(self) -> int:
        """Remaining requests."""
        return max(0, self.requests_allowed - self.requests_used)
