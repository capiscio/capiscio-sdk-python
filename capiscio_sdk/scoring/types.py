"""Type definitions for multi-dimensional scoring system.

Defines the three core score types (Compliance, Trust, Availability),
their breakdown structures, rating enums, and helper functions.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


# ============================================================================
# Rating Enums
# ============================================================================


class ComplianceRating(str, Enum):
    """Compliance score rating levels."""
    PERFECT = "Perfect"
    EXCELLENT = "Excellent"
    GOOD = "Good"
    FAIR = "Fair"
    POOR = "Poor"


class TrustRating(str, Enum):
    """Trust score rating levels."""
    HIGHLY_TRUSTED = "Highly Trusted"
    TRUSTED = "Trusted"
    MODERATE_TRUST = "Moderate Trust"
    LOW_TRUST = "Low Trust"
    UNTRUSTED = "Untrusted"


class AvailabilityRating(str, Enum):
    """Availability score rating levels."""
    FULLY_AVAILABLE = "Fully Available"
    AVAILABLE = "Available"
    DEGRADED = "Degraded"
    UNSTABLE = "Unstable"
    UNAVAILABLE = "Unavailable"


# ============================================================================
# Breakdown Structures
# ============================================================================


@dataclass
class CoreFieldsBreakdown:
    """Breakdown for core required fields scoring."""
    score: int
    max_score: int = 60
    present: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)


@dataclass
class SkillsQualityBreakdown:
    """Breakdown for skills quality scoring."""
    score: int
    max_score: int = 20
    skills_present: bool = False
    all_skills_have_required_fields: bool = False
    all_skills_have_tags: bool = False
    issue_count: int = 0


@dataclass
class FormatComplianceBreakdown:
    """Breakdown for format compliance scoring."""
    score: int
    max_score: int = 15
    valid_semver: bool = False
    valid_protocol_version: bool = False
    valid_url: bool = False
    valid_transports: bool = False
    valid_mime_types: bool = False


@dataclass
class DataQualityBreakdown:
    """Breakdown for data quality scoring."""
    score: int
    max_score: int = 5
    no_duplicate_skill_ids: bool = False
    field_lengths_valid: bool = False
    no_ssrf_risks: bool = False


@dataclass
class ComplianceBreakdown:
    """Complete compliance score breakdown (100 points total)."""
    core_fields: CoreFieldsBreakdown
    skills_quality: SkillsQualityBreakdown
    format_compliance: FormatComplianceBreakdown
    data_quality: DataQualityBreakdown


@dataclass
class SignaturesBreakdown:
    """Breakdown for signature validation scoring."""
    score: int
    max_score: int = 40
    tested: bool = False
    has_valid_signature: bool = False
    multiple_signatures: bool = False
    covers_all_fields: bool = False
    is_recent: bool = False
    has_invalid_signature: bool = False
    has_expired_signature: bool = False


@dataclass
class ProviderBreakdown:
    """Breakdown for provider information scoring."""
    score: int
    max_score: int = 25
    tested: bool = False
    has_organization: bool = False
    has_url: bool = False
    url_reachable: Optional[bool] = None


@dataclass
class SecurityBreakdown:
    """Breakdown for security configuration scoring."""
    score: int
    max_score: int = 20
    https_only: bool = False
    has_security_schemes: bool = False
    has_strong_auth: bool = False
    has_http_urls: bool = False


@dataclass
class DocumentationBreakdown:
    """Breakdown for documentation and transparency scoring."""
    score: int
    max_score: int = 15
    has_documentation_url: bool = False
    has_terms_of_service: bool = False
    has_privacy_policy: bool = False


@dataclass
class TrustBreakdown:
    """Complete trust score breakdown (100 points before multiplier)."""
    signatures: SignaturesBreakdown
    provider: ProviderBreakdown
    security: SecurityBreakdown
    documentation: DocumentationBreakdown


@dataclass
class PrimaryEndpointBreakdown:
    """Breakdown for primary endpoint scoring."""
    score: int
    max_score: int = 50
    responds: bool = False
    response_time: Optional[float] = None
    has_cors: Optional[bool] = None
    valid_tls: Optional[bool] = None
    errors: List[str] = field(default_factory=list)


@dataclass
class TransportSupportBreakdown:
    """Breakdown for transport protocol support scoring."""
    score: int
    max_score: int = 30
    preferred_transport_works: bool = False
    additional_interfaces_working: int = 0
    additional_interfaces_failed: int = 0


@dataclass
class ResponseQualityBreakdown:
    """Breakdown for response quality scoring."""
    score: int
    max_score: int = 20
    valid_structure: bool = False
    proper_content_type: bool = False
    proper_error_handling: bool = False


@dataclass
class AvailabilityBreakdown:
    """Complete availability score breakdown (100 points total)."""
    primary_endpoint: PrimaryEndpointBreakdown
    transport_support: TransportSupportBreakdown
    response_quality: ResponseQualityBreakdown


# ============================================================================
# Core Score Types
# ============================================================================


@dataclass
class ComplianceScore:
    """Compliance score (0-100): Measures A2A specification adherence.
    
    Always calculated consistently regardless of validation flags.
    """
    total: int
    rating: ComplianceRating
    breakdown: ComplianceBreakdown
    issues: List[str] = field(default_factory=list)
    
    def __post_init__(self) -> None:
        """Validate score is in range."""
        assert 0 <= self.total <= 100, f"Invalid compliance score: {self.total}"


@dataclass
class TrustScore:
    """Trust score (0-100): Measures security and authenticity signals.
    
    Includes confidence multiplier based on signature presence.
    """
    total: int  # After confidence multiplier
    raw_score: int  # Before multiplier
    confidence_multiplier: float  # 1.0x, 0.6x, or 0.4x
    rating: TrustRating
    breakdown: TrustBreakdown
    issues: List[str] = field(default_factory=list)
    partial_validation: bool = False
    
    def __post_init__(self) -> None:
        """Validate score is in range."""
        assert 0 <= self.total <= 100, f"Invalid trust score: {self.total}"
        assert 0 <= self.raw_score <= 100, f"Invalid raw trust score: {self.raw_score}"
        assert self.confidence_multiplier in (0.4, 0.6, 1.0), \
            f"Invalid confidence multiplier: {self.confidence_multiplier}"


@dataclass
class AvailabilityScore:
    """Availability score (0-100): Measures operational readiness.
    
    Only calculated when network tests are enabled (not schema-only mode).
    """
    total: Optional[int]  # None if not tested
    rating: Optional[AvailabilityRating]
    breakdown: Optional[AvailabilityBreakdown]
    issues: List[str] = field(default_factory=list)
    tested: bool = False
    not_tested_reason: Optional[str] = None
    
    def __post_init__(self) -> None:
        """Validate score is in range if present."""
        if self.total is not None:
            assert 0 <= self.total <= 100, f"Invalid availability score: {self.total}"


# ============================================================================
# Context & Helpers
# ============================================================================


@dataclass
class ScoringContext:
    """Context about what validation was performed."""
    schema_only: bool = False
    skip_signature_verification: bool = False
    test_live: bool = False
    strict_mode: bool = False


# ============================================================================
# Rating Helper Functions
# ============================================================================


def get_compliance_rating(score: int) -> ComplianceRating:
    """Get compliance rating based on score.
    
    Args:
        score: Compliance score (0-100)
        
    Returns:
        ComplianceRating enum value
    """
    if score == 100:
        return ComplianceRating.PERFECT
    if score >= 90:
        return ComplianceRating.EXCELLENT
    if score >= 75:
        return ComplianceRating.GOOD
    if score >= 60:
        return ComplianceRating.FAIR
    return ComplianceRating.POOR


def get_trust_rating(score: int) -> TrustRating:
    """Get trust rating based on score.
    
    Args:
        score: Trust score (0-100, after confidence multiplier)
        
    Returns:
        TrustRating enum value
    """
    if score >= 80:
        return TrustRating.HIGHLY_TRUSTED
    if score >= 60:
        return TrustRating.TRUSTED
    if score >= 40:
        return TrustRating.MODERATE_TRUST
    if score >= 20:
        return TrustRating.LOW_TRUST
    return TrustRating.UNTRUSTED


def get_availability_rating(score: int) -> AvailabilityRating:
    """Get availability rating based on score.
    
    Args:
        score: Availability score (0-100)
        
    Returns:
        AvailabilityRating enum value
    """
    if score >= 95:
        return AvailabilityRating.FULLY_AVAILABLE
    if score >= 80:
        return AvailabilityRating.AVAILABLE
    if score >= 60:
        return AvailabilityRating.DEGRADED
    if score >= 40:
        return AvailabilityRating.UNSTABLE
    return AvailabilityRating.UNAVAILABLE


def get_trust_confidence_multiplier(
    has_valid_signature: bool,
    has_invalid_signature: bool
) -> float:
    """Get trust confidence multiplier based on signature state.
    
    Args:
        has_valid_signature: Whether a valid signature exists
        has_invalid_signature: Whether an invalid signature exists
        
    Returns:
        Confidence multiplier: 1.0x (valid), 0.6x (none), or 0.4x (invalid)
    """
    if has_invalid_signature:
        return 0.4  # Active distrust
    if has_valid_signature:
        return 1.0  # Full confidence
    return 0.6  # Unverified claims
