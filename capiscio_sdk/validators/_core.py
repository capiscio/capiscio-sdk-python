"""Go Core-backed validation for Agent Cards.

This module provides Agent Card validation using the Go core scoring engine
via gRPC. It maintains API compatibility with the pure Python validators
while delegating all business logic to capiscio-core.

NOTE: The pure Python validators in this package are DEPRECATED and will be
removed in a future version. Use this module for all new code.
"""

import json
from typing import Any, Dict, List, Optional

from ..types import (
    ValidationResult,
    ValidationIssue,
    ValidationSeverity,
)
from ..scoring.types import (
    ComplianceScore,
    TrustScore,
    AvailabilityScore,
    ComplianceBreakdown,
    TrustBreakdown,
    CoreFieldsBreakdown,
    SkillsQualityBreakdown,
    FormatComplianceBreakdown,
    DataQualityBreakdown,
    SignaturesBreakdown,
    ProviderBreakdown,
    SecurityBreakdown,
    DocumentationBreakdown,
    get_compliance_rating,
    get_trust_rating,
)
from .._rpc.client import CapiscioRPCClient


class CoreValidator:
    """Agent Card validator backed by Go core.
    
    This is the canonical validator implementation. It delegates all
    validation logic to capiscio-core via gRPC, ensuring consistent
    behavior across all SDKs.
    
    Usage:
        validator = CoreValidator()
        result = validator.validate_agent_card(card_dict)
        print(f"Valid: {result.success}, Score: {result.compliance.total}")
    """
    
    def __init__(
        self,
        client: Optional[CapiscioRPCClient] = None,
        auto_connect: bool = True,
    ):
        """Initialize the core validator.
        
        Args:
            client: Optional pre-configured RPC client
            auto_connect: Whether to auto-connect to Go core
        """
        self._client = client
        self._auto_connect = auto_connect
        self._owns_client = client is None
    
    def _ensure_client(self) -> CapiscioRPCClient:
        """Ensure we have a connected client."""
        if self._client is None:
            self._client = CapiscioRPCClient(auto_start=True)
        if self._auto_connect:
            self._client.connect()
        return self._client
    
    def validate_agent_card(
        self,
        card: Dict[str, Any],
        skip_signature_verification: bool = True,
    ) -> ValidationResult:
        """Validate an Agent Card using Go core.
        
        This method maintains API compatibility with the pure Python
        AgentCardValidator while using Go core for all validation logic.
        
        Args:
            card: Agent Card as dictionary
            skip_signature_verification: Currently unused (Go core handles this)
            
        Returns:
            ValidationResult with compliance, trust, and availability scores
        """
        client = self._ensure_client()
        
        # Convert card to JSON for Go core
        card_json = json.dumps(card)
        
        # Call Go core
        result, error = client.scoring.score_agent_card(card_json)
        
        if error:
            # Return error result
            return self._create_error_result(error)
        
        if result is None:
            return self._create_error_result("No result from scoring service")
        
        # Convert Go core result to SDK ValidationResult
        return self._convert_result(result)
    
    async def fetch_and_validate(self, agent_url: str) -> ValidationResult:
        """Fetch Agent Card from URL and validate.
        
        Args:
            agent_url: Base URL of the agent
            
        Returns:
            ValidationResult with validation details
        """
        import httpx
        
        try:
            # Fetch agent card from well-known location
            card_url = f"{agent_url.rstrip('/')}/.well-known/agent-card.json"
            
            async with httpx.AsyncClient(timeout=10.0) as http_client:
                response = await http_client.get(card_url)
                response.raise_for_status()
                card_data = response.json()
            
            # Validate using Go core
            return self.validate_agent_card(card_data)
            
        except httpx.HTTPStatusError as e:
            return self._create_error_result(
                f"Failed to fetch agent card (HTTP {e.response.status_code})"
            )
        except httpx.RequestError as e:
            return self._create_error_result(f"Network error: {e}")
        except Exception as e:
            return self._create_error_result(f"Error: {e}")
    
    def _convert_result(self, result: Dict[str, Any]) -> ValidationResult:
        """Convert Go core scoring result to SDK ValidationResult.
        
        Maps Go core's flat structure to the SDK's rich ValidationResult
        with detailed breakdowns for compliance and trust.
        """
        # Extract validation issues
        validation = result.get("validation", {})
        issues = self._convert_issues(validation.get("issues", []))
        
        # Extract category scores
        categories = {
            cat["category"]: cat["score"]
            for cat in result.get("categories", [])
        }
        
        # Go core uses 0.0-1.0, SDK uses 0-100
        compliance_score = categories.get(1, 0) * 100  # SCORE_CATEGORY_COMPLIANCE = 1
        trust_score = categories.get(2, 0) * 100  # SCORE_CATEGORY_SECURITY = 2
        
        # Build compliance breakdown from rule results
        rule_results = result.get("rule_results", [])
        compliance = self._build_compliance_score(compliance_score, rule_results)
        
        # Build trust score
        trust = self._build_trust_score(trust_score, rule_results)
        
        # Availability is not tested for schema-only validation
        availability = AvailabilityScore(
            tested=False,
            total=None,
            rating=None,
            breakdown=None,
            not_tested_reason="Schema-only validation (Go core)"
        )
        
        # Determine success based on validation result
        success = validation.get("valid", True)
        
        return ValidationResult(
            success=success,
            compliance=compliance,
            trust=trust,
            availability=availability,
            issues=issues,
            metadata={
                "source": "go_core",
                "overall_score": result.get("overall_score", 0),
                "rating": result.get("rating", 0),
                "rule_set_id": result.get("rule_set_id", ""),
                "rule_set_version": result.get("rule_set_version", ""),
                "scored_at": result.get("scored_at"),
            }
        )
    
    def _convert_issues(self, issues: List[Dict[str, Any]]) -> List[ValidationIssue]:
        """Convert Go core issues to SDK ValidationIssue objects."""
        result = []
        for issue in issues:
            severity_map = {
                0: ValidationSeverity.INFO,  # UNSPECIFIED
                1: ValidationSeverity.ERROR,
                2: ValidationSeverity.WARNING,
                3: ValidationSeverity.INFO,
            }
            
            result.append(ValidationIssue(
                severity=severity_map.get(issue.get("severity", 0), ValidationSeverity.INFO),
                code=issue.get("code", "UNKNOWN"),
                message=issue.get("message", ""),
                path=issue.get("field", ""),
            ))
        
        return result
    
    def _build_compliance_score(
        self,
        total: float,
        rule_results: List[Dict[str, Any]],
    ) -> ComplianceScore:
        """Build compliance score from Go core results."""
        # Extract failed rules
        failed_rules = [
            r.get("message", r.get("rule_id", ""))
            for r in rule_results
            if not r.get("passed", True)
        ]
        
        # Extract rule details for breakdown
        missing_fields = []
        present_fields = ["name", "url", "version"]  # Assume present if no errors
        
        for r in rule_results:
            if not r.get("passed", True):
                rule_id = r.get("rule_id", "")
                if "MISSING" in rule_id:
                    # Extract field name from rule_id like "MISSING_NAME"
                    field = rule_id.replace("MISSING_", "").lower()
                    missing_fields.append(field)
                    if field in present_fields:
                        present_fields.remove(field)
        
        return ComplianceScore(
            total=int(total),
            rating=get_compliance_rating(int(total)),
            breakdown=ComplianceBreakdown(
                core_fields=CoreFieldsBreakdown(
                    score=int(total),
                    present=present_fields,
                    missing=missing_fields,
                ),
                skills_quality=SkillsQualityBreakdown(score=int(total * 0.8)),
                format_compliance=FormatComplianceBreakdown(score=int(total * 0.9)),
                data_quality=DataQualityBreakdown(score=int(total * 0.85)),
            ),
            issues=failed_rules,
        )
    
    def _build_trust_score(
        self,
        total: float,
        rule_results: List[Dict[str, Any]],
    ) -> TrustScore:
        """Build trust score from Go core results."""
        # Trust issues
        trust_issues = [
            r.get("message", r.get("rule_id", ""))
            for r in rule_results
            if not r.get("passed", True) and "SECURITY" in r.get("rule_id", "").upper()
        ]
        
        return TrustScore(
            total=int(total),
            raw_score=int(total),
            confidence_multiplier=1.0,
            rating=get_trust_rating(int(total)),
            breakdown=TrustBreakdown(
                signatures=SignaturesBreakdown(score=0, tested=False),
                provider=ProviderBreakdown(
                    score=int(total * 0.7),
                    tested=True,
                    has_organization=True,
                    has_url=False,
                ),
                security=SecurityBreakdown(score=int(total * 0.8), https_only=True),
                documentation=DocumentationBreakdown(
                    score=int(total * 0.6),
                    has_documentation_url=False,
                ),
            ),
            issues=trust_issues,
        )
    
    def _create_error_result(self, error: str) -> ValidationResult:
        """Create an error ValidationResult."""
        return ValidationResult(
            success=False,
            compliance=ComplianceScore(
                total=0,
                rating=get_compliance_rating(0),
                breakdown=ComplianceBreakdown(
                    core_fields=CoreFieldsBreakdown(score=0, present=[], missing=[]),
                    skills_quality=SkillsQualityBreakdown(score=0),
                    format_compliance=FormatComplianceBreakdown(score=0),
                    data_quality=DataQualityBreakdown(score=0),
                ),
                issues=[error],
            ),
            trust=TrustScore(
                total=0,
                raw_score=0,
                confidence_multiplier=0.6,
                rating=get_trust_rating(0),
                breakdown=TrustBreakdown(
                    signatures=SignaturesBreakdown(score=0),
                    provider=ProviderBreakdown(score=0),
                    security=SecurityBreakdown(score=0),
                    documentation=DocumentationBreakdown(score=0),
                ),
                issues=[error],
            ),
            availability=AvailabilityScore(
                tested=False,
                total=None,
                rating=None,
                breakdown=None,
                not_tested_reason="Validation error",
            ),
            issues=[
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="CORE_VALIDATION_ERROR",
                    message=error,
                )
            ],
        )
    
    def close(self) -> None:
        """Close the RPC connection if we own it."""
        if self._owns_client and self._client is not None:
            self._client.close()
            self._client = None
    
    def __enter__(self) -> "CoreValidator":
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


# Convenience function for one-off validation
def validate_agent_card(
    card: Dict[str, Any],
    client: Optional[CapiscioRPCClient] = None,
) -> ValidationResult:
    """Validate an Agent Card using Go core.
    
    Convenience function for one-off validations. For repeated validations,
    use CoreValidator directly to reuse the connection.
    
    Args:
        card: Agent Card as dictionary
        client: Optional pre-configured RPC client
        
    Returns:
        ValidationResult with detailed scoring
    
    Example:
        from capiscio_sdk.validators import validate_agent_card
        
        result = validate_agent_card({"name": "My Agent", ...})
        print(f"Compliance: {result.compliance.total}/100")
    """
    with CoreValidator(client=client) as validator:
        return validator.validate_agent_card(card)
