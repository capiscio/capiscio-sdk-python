"""Unit tests for capiscio_sdk.scoring.trust — TrustScorer."""

from capiscio_sdk.types import ValidationIssue, ValidationSeverity
from capiscio_sdk.scoring.trust import TrustScorer
from capiscio_sdk.scoring.types import TrustRating


def _issue(code: str, msg: str = "test") -> ValidationIssue:
    return ValidationIssue(severity=ValidationSeverity.ERROR, code=code, message=msg)


def _full_card() -> dict:
    """Card with all trust-relevant fields present."""
    return {
        "signatures": [{"sig": "a"}, {"sig": "b"}],
        "provider": {"organization": "Acme", "url": "https://acme.example.com"},
        "capabilities": {
            "securitySchemes": [{"type": "apiKey", "name": "x-api-key"}],
        },
        "documentationUrl": "https://docs.example.com",
        "termsOfService": "https://tos.example.com",
        "privacyPolicy": "https://privacy.example.com",
    }


class TestTrustScorerPerfect:
    """Fully trusted card with valid signatures, full provider, etc."""

    def test_maximum_score(self):
        scorer = TrustScorer()
        result = scorer.score_agent_card(_full_card(), [])

        assert result.raw_score == 100
        assert result.confidence_multiplier == 1.0
        assert result.total == 100
        assert result.rating == TrustRating.HIGHLY_TRUSTED
        assert result.partial_validation is False


class TestTrustScorerSignatures:
    """Signatures subscore (40 points max)."""

    def test_skip_verification(self):
        scorer = TrustScorer()
        result = scorer.score_agent_card(_full_card(), [], skip_signature_verification=True)
        assert result.breakdown.signatures.tested is False
        assert result.breakdown.signatures.score == 0
        assert result.partial_validation is True

    def test_missing_signature(self):
        scorer = TrustScorer()
        result = scorer.score_agent_card(_full_card(), [_issue("MISSING_SIGNATURE")])
        sig = result.breakdown.signatures
        assert sig.has_valid_signature is False
        assert result.confidence_multiplier == 0.6

    def test_invalid_signature(self):
        scorer = TrustScorer()
        result = scorer.score_agent_card(
            _full_card(),
            [_issue("SIGNATURE_VERIFICATION_FAILED")]
        )
        sig = result.breakdown.signatures
        assert sig.has_invalid_signature is True
        assert result.confidence_multiplier == 0.4

    def test_expired_signature(self):
        scorer = TrustScorer()
        result = scorer.score_agent_card(_full_card(), [_issue("SIGNATURE_EXPIRED")])
        sig = result.breakdown.signatures
        assert sig.has_expired_signature is True
        assert sig.is_recent is False

    def test_single_signature_no_multi_bonus(self):
        scorer = TrustScorer()
        card = _full_card()
        card["signatures"] = [{"sig": "only-one"}]
        result = scorer.score_agent_card(card, [])
        assert result.breakdown.signatures.multiple_signatures is False


class TestTrustScorerProvider:
    """Provider subscore (25 points max)."""

    def test_full_provider(self):
        scorer = TrustScorer()
        result = scorer.score_agent_card(_full_card(), [])
        prov = result.breakdown.provider
        assert prov.has_organization is True
        assert prov.has_url is True
        assert prov.url_reachable is True
        assert prov.score == 25

    def test_no_provider(self):
        scorer = TrustScorer()
        card = _full_card()
        card["provider"] = {}
        result = scorer.score_agent_card(card, [])
        assert result.breakdown.provider.score == 0

    def test_provider_url_unreachable(self):
        scorer = TrustScorer()
        result = scorer.score_agent_card(
            _full_card(),
            [_issue("PROVIDER_URL_UNREACHABLE")]
        )
        prov = result.breakdown.provider
        assert prov.url_reachable is False
        assert prov.score == 20  # 10 org + 10 url, no reachable bonus

    def test_non_dict_provider(self):
        scorer = TrustScorer()
        card = _full_card()
        card["provider"] = "invalid"
        result = scorer.score_agent_card(card, [])
        assert result.breakdown.provider.score == 0


class TestTrustScorerSecurity:
    """Security subscore (20 points max)."""

    def test_https_only(self):
        scorer = TrustScorer()
        result = scorer.score_agent_card(_full_card(), [])
        sec = result.breakdown.security
        assert sec.https_only is True
        assert sec.score == 20

    def test_http_url_found(self):
        scorer = TrustScorer()
        result = scorer.score_agent_card(_full_card(), [_issue("HTTP_URL_FOUND")])
        sec = result.breakdown.security
        assert sec.https_only is False
        assert sec.has_http_urls is True

    def test_no_security_schemes(self):
        scorer = TrustScorer()
        card = _full_card()
        card["capabilities"] = {"securitySchemes": []}
        result = scorer.score_agent_card(card, [])
        sec = result.breakdown.security
        assert sec.has_security_schemes is False
        assert sec.has_strong_auth is False
        assert sec.score == 10  # https_only only

    def test_non_dict_capabilities(self):
        scorer = TrustScorer()
        card = _full_card()
        card["capabilities"] = "invalid"
        result = scorer.score_agent_card(card, [])
        sec = result.breakdown.security
        assert sec.has_security_schemes is False


class TestTrustScorerDocumentation:
    """Documentation subscore (15 points max)."""

    def test_full_docs(self):
        scorer = TrustScorer()
        result = scorer.score_agent_card(_full_card(), [])
        doc = result.breakdown.documentation
        assert doc.score == 15

    def test_no_docs(self):
        scorer = TrustScorer()
        card = _full_card()
        del card["documentationUrl"]
        del card["termsOfService"]
        del card["privacyPolicy"]
        result = scorer.score_agent_card(card, [])
        assert result.breakdown.documentation.score == 0


class TestTrustScorerConfidenceMultiplier:
    """End-to-end multiplier application."""

    def test_multiplier_applied_to_total(self):
        scorer = TrustScorer()
        # Missing signature → 0.6x
        result = scorer.score_agent_card(_full_card(), [_issue("MISSING_SIGNATURE")])
        # raw_score still counts other components, total is int(raw * 0.6)
        assert result.total == int(result.raw_score * 0.6)

    def test_issue_filtering(self):
        scorer = TrustScorer()
        issues = [
            _issue("MISSING_SIGNATURE", "trust issue"),
            _issue("INVALID_SEMVER", "compliance issue"),
        ]
        result = scorer.score_agent_card(_full_card(), issues)
        assert "trust issue" in result.issues
        assert "compliance issue" not in result.issues
