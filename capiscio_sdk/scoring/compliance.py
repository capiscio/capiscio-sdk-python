"""Compliance scorer for A2A protocol specification adherence.

Calculates compliance score (0-100) based on:
- Core required fields (60 points)
- Skills quality (20 points)
- Format compliance (15 points)
- Data quality (5 points)
"""

from typing import Any, Dict, List
from ..types import ValidationIssue
from .types import (
    ComplianceScore,
    ComplianceBreakdown,
    CoreFieldsBreakdown,
    SkillsQualityBreakdown,
    FormatComplianceBreakdown,
    DataQualityBreakdown,
    get_compliance_rating,
)


class ComplianceScorer:
    """Calculates compliance scores for A2A protocol adherence."""
    
    # Required fields per A2A specification
    REQUIRED_FIELDS = [
        "name",
        "description",
        "url",
        "version",
        "protocolVersion",
        "preferredTransport",
        "capabilities",
        "provider",
        "skills"
    ]
    
    POINTS_PER_CORE_FIELD = 60 / len(REQUIRED_FIELDS)  # ~6.67 points each
    
    def score_agent_card(
        self,
        card_data: Dict[str, Any],
        issues: List[ValidationIssue]
    ) -> ComplianceScore:
        """Calculate compliance score for an agent card.
        
        Args:
            card_data: Agent card data dictionary
            issues: List of validation issues found
            
        Returns:
            ComplianceScore with detailed breakdown
        """
        # Calculate each component
        core_fields = self._score_core_fields(card_data)
        skills_quality = self._score_skills_quality(card_data)
        format_compliance = self._score_format_compliance(card_data, issues)
        data_quality = self._score_data_quality(card_data, issues)
        
        # Calculate total
        total = (
            core_fields.score +
            skills_quality.score +
            format_compliance.score +
            data_quality.score
        )
        total = max(0, min(100, total))  # Clamp to 0-100
        
        # Create breakdown
        breakdown = ComplianceBreakdown(
            core_fields=core_fields,
            skills_quality=skills_quality,
            format_compliance=format_compliance,
            data_quality=data_quality
        )
        
        # Extract issue messages
        issue_messages = [
            issue.message for issue in issues
            if self._is_compliance_issue(issue)
        ]
        
        return ComplianceScore(
            total=total,
            rating=get_compliance_rating(total),
            breakdown=breakdown,
            issues=issue_messages
        )
    
    def _score_core_fields(self, card_data: Dict[str, Any]) -> CoreFieldsBreakdown:
        """Score core required fields (60 points).
        
        Args:
            card_data: Agent card data
            
        Returns:
            CoreFieldsBreakdown with present/missing fields
        """
        present = []
        missing = []
        
        for field in self.REQUIRED_FIELDS:
            if field in card_data and card_data[field]:
                present.append(field)
            else:
                missing.append(field)
        
        score = int(len(present) * self.POINTS_PER_CORE_FIELD)
        
        return CoreFieldsBreakdown(
            score=score,
            max_score=60,
            present=present,
            missing=missing
        )
    
    def _score_skills_quality(self, card_data: Dict[str, Any]) -> SkillsQualityBreakdown:
        """Score skills quality (20 points).
        
        Args:
            card_data: Agent card data
            
        Returns:
            SkillsQualityBreakdown with quality metrics
        """
        skills = card_data.get("skills", [])
        score = 0
        issue_count = 0
        
        # Ensure skills is a list (defensive coding for validation errors)
        if not isinstance(skills, list):
            skills = []
        
        skills_present = bool(skills)
        all_have_required = True
        all_have_tags = True
        
        if skills_present:
            score += 5  # Skills array present
            
            # Check all skills have required fields
            required_skill_fields = ["id", "name", "description"]
            for skill in skills:
                # Defensive: ensure skill is a dict
                if not isinstance(skill, dict):
                    all_have_required = False
                    issue_count += 1
                    continue
                    
                if not all(field in skill for field in required_skill_fields):
                    all_have_required = False
                    issue_count += 1
            
            if all_have_required:
                score += 10
            
            # Check all skills have tags
            for skill in skills:
                # Defensive: ensure skill is a dict
                if not isinstance(skill, dict):
                    all_have_tags = False
                    issue_count += 1
                    continue
                    
                if not skill.get("tags"):
                    all_have_tags = False
                    issue_count += 1
            
            if all_have_tags:
                score += 5
        else:
            all_have_required = False
            all_have_tags = False
        
        return SkillsQualityBreakdown(
            score=score,
            max_score=20,
            skills_present=skills_present,
            all_skills_have_required_fields=all_have_required,
            all_skills_have_tags=all_have_tags,
            issue_count=issue_count
        )
    
    def _score_format_compliance(
        self,
        card_data: Dict[str, Any],
        issues: List[ValidationIssue]
    ) -> FormatComplianceBreakdown:
        """Score format compliance (15 points).
        
        Args:
            card_data: Agent card data
            issues: Validation issues to check
            
        Returns:
            FormatComplianceBreakdown with format checks
        """
        score = 0
        
        # Check for format-related issues (3 points each)
        valid_semver = not self._has_issue_code(issues, "INVALID_SEMVER")
        if valid_semver:
            score += 3
        
        valid_protocol_version = not self._has_issue_code(issues, "INVALID_PROTOCOL_VERSION")
        if valid_protocol_version:
            score += 3
        
        valid_url = not self._has_issue_code(issues, ["INVALID_URL", "INSECURE_URL"])
        if valid_url:
            score += 3
        
        valid_transports = not self._has_issue_code(issues, "INVALID_TRANSPORT")
        if valid_transports:
            score += 3
        
        valid_mime_types = not self._has_issue_code(issues, "INVALID_MIME_TYPE")
        if valid_mime_types:
            score += 3
        
        return FormatComplianceBreakdown(
            score=score,
            max_score=15,
            valid_semver=valid_semver,
            valid_protocol_version=valid_protocol_version,
            valid_url=valid_url,
            valid_transports=valid_transports,
            valid_mime_types=valid_mime_types
        )
    
    def _score_data_quality(
        self,
        card_data: Dict[str, Any],
        issues: List[ValidationIssue]
    ) -> DataQualityBreakdown:
        """Score data quality (5 points).
        
        Args:
            card_data: Agent card data
            issues: Validation issues to check
            
        Returns:
            DataQualityBreakdown with quality checks
        """
        score = 0
        
        # Check for duplicate skill IDs (2 points)
        skills = card_data.get("skills", [])
        # Ensure skills is a list (defensive coding)
        if not isinstance(skills, list):
            skills = []
        # Ensure each skill is a dict
        skill_ids = [s.get("id") for s in skills if isinstance(s, dict) and s.get("id")]
        no_duplicates = len(skill_ids) == len(set(skill_ids))
        if no_duplicates:
            score += 2
        
        # Check field lengths (2 points)
        field_lengths_valid = not self._has_issue_code(issues, "FIELD_LENGTH_EXCEEDED")
        if field_lengths_valid:
            score += 2
        
        # Check for SSRF risks (1 point)
        no_ssrf_risks = not self._has_issue_code(issues, ["SSRF_RISK", "PRIVATE_IP"])
        if no_ssrf_risks:
            score += 1
        
        return DataQualityBreakdown(
            score=score,
            max_score=5,
            no_duplicate_skill_ids=no_duplicates,
            field_lengths_valid=field_lengths_valid,
            no_ssrf_risks=no_ssrf_risks
        )
    
    def _is_compliance_issue(self, issue: ValidationIssue) -> bool:
        """Check if issue is compliance-related.
        
        Args:
            issue: Validation issue to check
            
        Returns:
            True if compliance-related
        """
        compliance_codes = {
            "MISSING_REQUIRED_FIELD",
            "INVALID_SEMVER",
            "INVALID_PROTOCOL_VERSION",
            "INVALID_TRANSPORT",
            "INVALID_MIME_TYPE",
            "FIELD_LENGTH_EXCEEDED",
            "DUPLICATE_SKILL_ID",
        }
        return issue.code in compliance_codes
    
    def _has_issue_code(
        self,
        issues: List[ValidationIssue],
        codes: str | List[str]
    ) -> bool:
        """Check if any issue has given code(s).
        
        Args:
            issues: List of validation issues
            codes: Single code or list of codes to check
            
        Returns:
            True if any issue matches
        """
        if isinstance(codes, str):
            codes = [codes]
        code_set = set(codes)
        return any(issue.code in code_set for issue in issues)
