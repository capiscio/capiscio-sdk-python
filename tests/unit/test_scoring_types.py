"""Unit tests for capiscio_sdk.scoring.types — rating helpers and dataclasses."""

import pytest

from capiscio_sdk.scoring.types import (
    ComplianceRating,
    TrustRating,
    AvailabilityRating,
    ComplianceScore,
    TrustScore,
    AvailabilityScore,
    ComplianceBreakdown,
    CoreFieldsBreakdown,
    SkillsQualityBreakdown,
    FormatComplianceBreakdown,
    DataQualityBreakdown,
    TrustBreakdown,
    SignaturesBreakdown,
    ProviderBreakdown,
    SecurityBreakdown,
    DocumentationBreakdown,
    ScoringContext,
    get_compliance_rating,
    get_trust_rating,
    get_availability_rating,
    get_trust_confidence_multiplier,
)


# ---------------------------------------------------------------------------
# Rating helper functions
# ---------------------------------------------------------------------------


class TestGetComplianceRating:
    """Tests for get_compliance_rating() boundary values."""

    @pytest.mark.parametrize("score, expected", [
        (100, ComplianceRating.PERFECT),
        (99, ComplianceRating.EXCELLENT),
        (90, ComplianceRating.EXCELLENT),
        (89, ComplianceRating.GOOD),
        (75, ComplianceRating.GOOD),
        (74, ComplianceRating.FAIR),
        (60, ComplianceRating.FAIR),
        (59, ComplianceRating.POOR),
        (0, ComplianceRating.POOR),
    ])
    def test_boundary_values(self, score, expected):
        assert get_compliance_rating(score) == expected


class TestGetTrustRating:
    """Tests for get_trust_rating() boundary values."""

    @pytest.mark.parametrize("score, expected", [
        (100, TrustRating.HIGHLY_TRUSTED),
        (80, TrustRating.HIGHLY_TRUSTED),
        (79, TrustRating.TRUSTED),
        (60, TrustRating.TRUSTED),
        (59, TrustRating.MODERATE_TRUST),
        (40, TrustRating.MODERATE_TRUST),
        (39, TrustRating.LOW_TRUST),
        (20, TrustRating.LOW_TRUST),
        (19, TrustRating.UNTRUSTED),
        (0, TrustRating.UNTRUSTED),
    ])
    def test_boundary_values(self, score, expected):
        assert get_trust_rating(score) == expected


class TestGetAvailabilityRating:
    """Tests for get_availability_rating() boundary values."""

    @pytest.mark.parametrize("score, expected", [
        (100, AvailabilityRating.FULLY_AVAILABLE),
        (95, AvailabilityRating.FULLY_AVAILABLE),
        (94, AvailabilityRating.AVAILABLE),
        (80, AvailabilityRating.AVAILABLE),
        (79, AvailabilityRating.DEGRADED),
        (60, AvailabilityRating.DEGRADED),
        (59, AvailabilityRating.UNSTABLE),
        (40, AvailabilityRating.UNSTABLE),
        (39, AvailabilityRating.UNAVAILABLE),
        (0, AvailabilityRating.UNAVAILABLE),
    ])
    def test_boundary_values(self, score, expected):
        assert get_availability_rating(score) == expected


class TestGetTrustConfidenceMultiplier:
    """Tests for get_trust_confidence_multiplier()."""

    def test_valid_signature(self):
        assert get_trust_confidence_multiplier(True, False) == 1.0

    def test_no_signature(self):
        assert get_trust_confidence_multiplier(False, False) == 0.6

    def test_invalid_signature(self):
        assert get_trust_confidence_multiplier(False, True) == 0.4

    def test_invalid_overrides_valid(self):
        """Invalid signature takes precedence even if a valid one exists."""
        assert get_trust_confidence_multiplier(True, True) == 0.4


# ---------------------------------------------------------------------------
# Dataclass post_init validation
# ---------------------------------------------------------------------------


def _make_compliance_breakdown():
    """Helper — minimal valid ComplianceBreakdown."""
    return ComplianceBreakdown(
        core_fields=CoreFieldsBreakdown(score=60),
        skills_quality=SkillsQualityBreakdown(score=20),
        format_compliance=FormatComplianceBreakdown(score=15),
        data_quality=DataQualityBreakdown(score=5),
    )


def _make_trust_breakdown():
    """Helper — minimal valid TrustBreakdown."""
    return TrustBreakdown(
        signatures=SignaturesBreakdown(score=40),
        provider=ProviderBreakdown(score=25),
        security=SecurityBreakdown(score=20),
        documentation=DocumentationBreakdown(score=15),
    )


class TestComplianceScoreValidation:
    def test_valid_range(self):
        cs = ComplianceScore(
            total=85,
            rating=ComplianceRating.GOOD,
            breakdown=_make_compliance_breakdown(),
        )
        assert cs.total == 85

    def test_rejects_above_100(self):
        with pytest.raises(AssertionError):
            ComplianceScore(
                total=101,
                rating=ComplianceRating.PERFECT,
                breakdown=_make_compliance_breakdown(),
            )

    def test_rejects_negative(self):
        with pytest.raises(AssertionError):
            ComplianceScore(
                total=-1,
                rating=ComplianceRating.POOR,
                breakdown=_make_compliance_breakdown(),
            )


class TestTrustScoreValidation:
    def test_valid_range(self):
        ts = TrustScore(
            total=60,
            raw_score=100,
            confidence_multiplier=0.6,
            rating=TrustRating.TRUSTED,
            breakdown=_make_trust_breakdown(),
        )
        assert ts.total == 60

    def test_rejects_bad_multiplier(self):
        with pytest.raises(AssertionError):
            TrustScore(
                total=50,
                raw_score=50,
                confidence_multiplier=0.5,
                rating=TrustRating.MODERATE_TRUST,
                breakdown=_make_trust_breakdown(),
            )


class TestAvailabilityScoreValidation:
    def test_not_tested(self):
        a = AvailabilityScore(total=None, rating=None, breakdown=None, tested=False)
        assert a.tested is False

    def test_rejects_above_100(self):
        with pytest.raises(AssertionError):
            AvailabilityScore(total=101, rating=AvailabilityRating.FULLY_AVAILABLE, breakdown=None)


class TestScoringContext:
    def test_defaults(self):
        ctx = ScoringContext()
        assert ctx.schema_only is False
        assert ctx.skip_signature_verification is False
        assert ctx.test_live is False
        assert ctx.strict_mode is False
