"""Unit tests for capiscio_sdk.scoring.availability — AvailabilityScorer."""

import pytest

from capiscio_sdk.types import ValidationIssue, ValidationSeverity
from capiscio_sdk.scoring.availability import AvailabilityScorer
from capiscio_sdk.scoring.types import AvailabilityRating


def _issue(code: str, msg: str = "test") -> ValidationIssue:
    return ValidationIssue(severity=ValidationSeverity.ERROR, code=code, message=msg)


class TestAvailabilityScorerNotTested:
    """score_not_tested() should return an untested placeholder."""

    def test_defaults(self):
        scorer = AvailabilityScorer()
        result = scorer.score_not_tested()
        assert result.tested is False
        assert result.total is None
        assert result.rating is None
        assert result.breakdown is None
        assert result.not_tested_reason == "Network tests not enabled"

    def test_custom_reason(self):
        scorer = AvailabilityScorer()
        result = scorer.score_not_tested("Behind firewall")
        assert result.not_tested_reason == "Behind firewall"


class TestAvailabilityScorerPerfect:
    """Fully available endpoint: responds fast, TLS valid, CORS present."""

    def test_maximum_score(self):
        scorer = AvailabilityScorer()
        result = scorer.score_endpoint_test(
            endpoint_responded=True,
            response_time=0.5,
            has_cors=True,
            valid_tls=True,
        )
        assert result.tested is True
        assert result.total == 100
        assert result.rating == AvailabilityRating.FULLY_AVAILABLE


class TestAvailabilityScorerPrimaryEndpoint:
    """Primary endpoint subscore (50 points max)."""

    def test_no_response(self):
        scorer = AvailabilityScorer()
        result = scorer.score_endpoint_test(endpoint_responded=False)
        pe = result.breakdown.primary_endpoint
        assert pe.responds is False
        assert pe.score == 0
        assert "Endpoint did not respond" in pe.errors

    def test_fast_response(self):
        scorer = AvailabilityScorer()
        result = scorer.score_endpoint_test(endpoint_responded=True, response_time=1.0)
        pe = result.breakdown.primary_endpoint
        assert pe.score >= 40  # 30 responds + 10 fast

    def test_medium_response(self):
        scorer = AvailabilityScorer()
        result = scorer.score_endpoint_test(endpoint_responded=True, response_time=3.0)
        pe = result.breakdown.primary_endpoint
        # 30 responds + 5 medium speed
        assert pe.score >= 35

    def test_slow_response(self):
        scorer = AvailabilityScorer()
        result = scorer.score_endpoint_test(endpoint_responded=True, response_time=10.0)
        pe = result.breakdown.primary_endpoint
        # 30 responds + 0 speed
        assert pe.score == 30
        assert any("Slow response" in e for e in pe.errors)

    def test_invalid_tls(self):
        scorer = AvailabilityScorer()
        result = scorer.score_endpoint_test(
            endpoint_responded=True, valid_tls=False
        )
        pe = result.breakdown.primary_endpoint
        assert "Invalid TLS certificate" in pe.errors

    def test_missing_cors(self):
        scorer = AvailabilityScorer()
        result = scorer.score_endpoint_test(
            endpoint_responded=True, has_cors=False
        )
        pe = result.breakdown.primary_endpoint
        assert "Missing CORS headers" in pe.errors

    def test_tls_and_cors_none_no_penalty(self):
        """When TLS/CORS weren't checked (None), no errors are added."""
        scorer = AvailabilityScorer()
        result = scorer.score_endpoint_test(
            endpoint_responded=True,
            valid_tls=None,
            has_cors=None,
        )
        pe = result.breakdown.primary_endpoint
        assert pe.errors == []


class TestAvailabilityScorerTransportSupport:
    """Transport support subscore (30 points max)."""

    def test_transport_works(self):
        scorer = AvailabilityScorer()
        result = scorer.score_endpoint_test(endpoint_responded=True)
        ts = result.breakdown.transport_support
        assert ts.preferred_transport_works is True
        assert ts.score == 30

    def test_transport_failed(self):
        scorer = AvailabilityScorer()
        result = scorer.score_endpoint_test(
            endpoint_responded=True,
            issues=[_issue("TRANSPORT_FAILED")]
        )
        ts = result.breakdown.transport_support
        assert ts.preferred_transport_works is False
        assert ts.score == 0

    def test_transport_not_tested_when_down(self):
        scorer = AvailabilityScorer()
        result = scorer.score_endpoint_test(endpoint_responded=False)
        ts = result.breakdown.transport_support
        assert ts.preferred_transport_works is False
        assert ts.score == 0


class TestAvailabilityScorerResponseQuality:
    """Response quality subscore (20 points max)."""

    def test_valid_response(self):
        scorer = AvailabilityScorer()
        result = scorer.score_endpoint_test(endpoint_responded=True)
        rq = result.breakdown.response_quality
        assert rq.valid_structure is True
        assert rq.proper_content_type is True
        assert rq.proper_error_handling is True
        assert rq.score == 20

    def test_malformed_json(self):
        scorer = AvailabilityScorer()
        result = scorer.score_endpoint_test(
            endpoint_responded=True,
            issues=[_issue("MALFORMED_JSON")]
        )
        rq = result.breakdown.response_quality
        assert rq.valid_structure is False
        assert rq.score == 10  # content_type 5 + error_handling 5

    def test_invalid_content_type(self):
        scorer = AvailabilityScorer()
        result = scorer.score_endpoint_test(
            endpoint_responded=True,
            issues=[_issue("INVALID_CONTENT_TYPE")]
        )
        rq = result.breakdown.response_quality
        assert rq.proper_content_type is False

    def test_no_quality_when_down(self):
        scorer = AvailabilityScorer()
        result = scorer.score_endpoint_test(endpoint_responded=False)
        rq = result.breakdown.response_quality
        assert rq.score == 0


class TestAvailabilityScorerIssueFiltering:
    """Only availability-related issues appear in the result."""

    def test_availability_issues_included(self):
        scorer = AvailabilityScorer()
        issues = [
            _issue("ENDPOINT_UNREACHABLE", "endpoint down"),
            _issue("INVALID_SEMVER", "compliance issue"),
        ]
        result = scorer.score_endpoint_test(endpoint_responded=True, issues=issues)
        assert "endpoint down" in result.issues
        assert "compliance issue" not in result.issues
