"""Unit tests for capiscio_sdk.scoring.compliance — ComplianceScorer."""

import pytest

from capiscio_sdk.types import ValidationIssue, ValidationSeverity
from capiscio_sdk.scoring.compliance import ComplianceScorer
from capiscio_sdk.scoring.types import ComplianceRating


def _issue(code: str, msg: str = "test") -> ValidationIssue:
    """Shorthand for creating a ValidationIssue."""
    return ValidationIssue(severity=ValidationSeverity.ERROR, code=code, message=msg)


def _full_card() -> dict:
    """Agent card with every required field populated."""
    return {
        "name": "TestAgent",
        "description": "A test agent",
        "url": "https://example.com",
        "version": "1.0.0",
        "protocolVersion": "1.0",
        "preferredTransport": "https",
        "capabilities": {"securitySchemes": []},
        "provider": {"organization": "Acme", "url": "https://acme.example.com"},
        "skills": [
            {"id": "s1", "name": "Skill 1", "description": "Does things", "tags": ["general"]},
            {"id": "s2", "name": "Skill 2", "description": "Does more", "tags": ["general"]},
        ],
    }


class TestComplianceScorerPerfect:
    """A fully-populated, issue-free card should score 100 / Perfect."""

    def test_perfect_score(self):
        scorer = ComplianceScorer()
        result = scorer.score_agent_card(_full_card(), [])

        assert result.total == 100
        assert result.rating == ComplianceRating.PERFECT
        assert result.breakdown.core_fields.score == 60
        assert result.breakdown.skills_quality.score == 20
        assert result.breakdown.format_compliance.score == 15
        assert result.breakdown.data_quality.score == 5


class TestComplianceScorerCoreFields:
    """Core fields subscore (60 points)."""

    def test_empty_card_zero_core(self):
        scorer = ComplianceScorer()
        result = scorer.score_agent_card({}, [])
        assert result.breakdown.core_fields.score == 0
        assert set(result.breakdown.core_fields.missing) == set(ComplianceScorer.REQUIRED_FIELDS)

    def test_partial_fields(self):
        scorer = ComplianceScorer()
        card = {"name": "A", "version": "1.0.0"}
        result = scorer.score_agent_card(card, [])
        assert result.breakdown.core_fields.score == int(2 * ComplianceScorer.POINTS_PER_CORE_FIELD)
        assert "name" in result.breakdown.core_fields.present
        assert "version" in result.breakdown.core_fields.present

    def test_falsy_values_count_as_missing(self):
        scorer = ComplianceScorer()
        card = {"name": "", "version": None}
        result = scorer.score_agent_card(card, [])
        assert result.breakdown.core_fields.score == 0


class TestComplianceScorerSkillsQuality:
    """Skills quality subscore (20 points)."""

    def test_no_skills(self):
        scorer = ComplianceScorer()
        result = scorer.score_agent_card({"skills": []}, [])
        assert result.breakdown.skills_quality.score == 0
        assert result.breakdown.skills_quality.skills_present is False

    def test_skills_without_required_fields(self):
        scorer = ComplianceScorer()
        card = {"skills": [{"id": "s1"}]}  # missing name, description
        result = scorer.score_agent_card(card, [])
        bd = result.breakdown.skills_quality
        assert bd.skills_present is True
        assert bd.all_skills_have_required_fields is False
        assert bd.score == 5  # only "skills present" bonus

    def test_skills_without_tags(self):
        scorer = ComplianceScorer()
        card = {"skills": [{"id": "s1", "name": "S", "description": "D"}]}  # no tags
        result = scorer.score_agent_card(card, [])
        bd = result.breakdown.skills_quality
        assert bd.all_skills_have_required_fields is True
        assert bd.all_skills_have_tags is False
        assert bd.score == 15  # 5 present + 10 required fields

    def test_non_dict_skills_handled(self):
        """Skills that aren't dicts should be counted as issues."""
        scorer = ComplianceScorer()
        card = {"skills": ["not-a-dict"]}
        result = scorer.score_agent_card(card, [])
        bd = result.breakdown.skills_quality
        assert bd.all_skills_have_required_fields is False
        assert bd.issue_count >= 1

    def test_non_list_skills_handled(self):
        """skills: 'invalid' should be treated as empty."""
        scorer = ComplianceScorer()
        card = {"skills": "invalid"}
        result = scorer.score_agent_card(card, [])
        assert result.breakdown.skills_quality.skills_present is False


class TestComplianceScorerFormatCompliance:
    """Format compliance subscore (15 points)."""

    def test_all_valid_formats(self):
        scorer = ComplianceScorer()
        result = scorer.score_agent_card({}, [])
        assert result.breakdown.format_compliance.score == 15

    @pytest.mark.parametrize("issue_code, field", [
        ("INVALID_SEMVER", "valid_semver"),
        ("INVALID_PROTOCOL_VERSION", "valid_protocol_version"),
        ("INVALID_TRANSPORT", "valid_transports"),
        ("INVALID_MIME_TYPE", "valid_mime_types"),
    ])
    def test_individual_format_failures(self, issue_code, field):
        scorer = ComplianceScorer()
        result = scorer.score_agent_card({}, [_issue(issue_code)])
        bd = result.breakdown.format_compliance
        assert getattr(bd, field) is False
        assert bd.score == 12  # 15 - 3

    def test_insecure_url_counts(self):
        scorer = ComplianceScorer()
        result = scorer.score_agent_card({}, [_issue("INSECURE_URL")])
        assert result.breakdown.format_compliance.valid_url is False


class TestComplianceScorerDataQuality:
    """Data quality subscore (5 points)."""

    def test_duplicate_skill_ids(self):
        scorer = ComplianceScorer()
        card = {"skills": [
            {"id": "dup", "name": "A", "description": "A"},
            {"id": "dup", "name": "B", "description": "B"},
        ]}
        result = scorer.score_agent_card(card, [])
        assert result.breakdown.data_quality.no_duplicate_skill_ids is False

    def test_field_length_exceeded(self):
        scorer = ComplianceScorer()
        result = scorer.score_agent_card({}, [_issue("FIELD_LENGTH_EXCEEDED")])
        assert result.breakdown.data_quality.field_lengths_valid is False

    def test_ssrf_risk(self):
        scorer = ComplianceScorer()
        result = scorer.score_agent_card({}, [_issue("SSRF_RISK")])
        assert result.breakdown.data_quality.no_ssrf_risks is False


class TestComplianceScorerIssueFiltering:
    """Only compliance-related issues appear in the result."""

    def test_compliance_issues_included(self):
        scorer = ComplianceScorer()
        issues = [
            _issue("MISSING_REQUIRED_FIELD", "name is required"),
            _issue("SIGNATURE_VERIFICATION_FAILED", "trust issue"),  # not compliance
        ]
        result = scorer.score_agent_card({}, issues)
        assert "name is required" in result.issues
        assert "trust issue" not in result.issues

    def test_total_clamped_to_0_100(self):
        scorer = ComplianceScorer()
        result = scorer.score_agent_card({}, [])
        assert 0 <= result.total <= 100
