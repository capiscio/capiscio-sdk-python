"""Trust scorer for security and authenticity signals.

Calculates trust score (0-100) based on:
- Cryptographic signatures (40 points)
- Provider information (25 points)
- Security configuration (20 points)
- Documentation and transparency (15 points)

Applies confidence multiplier based on signature state:
- Valid signature: 1.0x (full confidence)
- No signature: 0.6x (unverified claims)
- Invalid signature: 0.4x (active distrust)
"""

from typing import Any, Dict, List
from ..types import ValidationIssue
from .types import (
    TrustScore,
    TrustBreakdown,
    SignaturesBreakdown,
    ProviderBreakdown,
    SecurityBreakdown,
    DocumentationBreakdown,
    get_trust_rating,
    get_trust_confidence_multiplier,
)


class TrustScorer:
    """Calculates trust scores for security and authenticity signals."""
    
    def score_agent_card(
        self,
        card_data: Dict[str, Any],
        issues: List[ValidationIssue],
        skip_signature_verification: bool = False
    ) -> TrustScore:
        """Calculate trust score for an agent card.
        
        Args:
            card_data: Agent card data dictionary
            issues: List of validation issues found
            skip_signature_verification: Whether signature verification was skipped
            
        Returns:
            TrustScore with detailed breakdown
        """
        # Calculate each component
        signatures = self._score_signatures(card_data, issues, skip_signature_verification)
        provider = self._score_provider(card_data, issues)
        security = self._score_security(card_data, issues)
        documentation = self._score_documentation(card_data)
        
        # Calculate raw score
        raw_score = (
            signatures.score +
            provider.score +
            security.score +
            documentation.score
        )
        raw_score = max(0, min(100, raw_score))
        
        # Apply confidence multiplier
        confidence_multiplier = get_trust_confidence_multiplier(
            has_valid_signature=signatures.has_valid_signature,
            has_invalid_signature=signatures.has_invalid_signature
        )
        total = int(raw_score * confidence_multiplier)
        
        # Create breakdown
        breakdown = TrustBreakdown(
            signatures=signatures,
            provider=provider,
            security=security,
            documentation=documentation
        )
        
        # Extract issue messages
        issue_messages = [
            issue.message for issue in issues
            if self._is_trust_issue(issue)
        ]
        
        return TrustScore(
            total=total,
            raw_score=raw_score,
            confidence_multiplier=confidence_multiplier,
            rating=get_trust_rating(total),
            breakdown=breakdown,
            issues=issue_messages,
            partial_validation=skip_signature_verification
        )
    
    def _score_signatures(
        self,
        card_data: Dict[str, Any],
        issues: List[ValidationIssue],
        skip_verification: bool
    ) -> SignaturesBreakdown:
        """Score cryptographic signatures (40 points).
        
        Args:
            card_data: Agent card data
            issues: Validation issues
            skip_verification: Whether verification was skipped
            
        Returns:
            SignaturesBreakdown with signature metrics
        """
        score = 0
        tested = not skip_verification
        
        has_valid = False
        multiple_sigs = False
        covers_all = False
        is_recent = False
        has_invalid = False
        has_expired = False
        
        if tested:
            # Check for valid signature (25 points)
            has_valid = not self._has_issue_code(issues, [
                "SIGNATURE_VERIFICATION_FAILED",
                "MISSING_SIGNATURE"
            ])
            if has_valid:
                score += 25
            
            # Check for invalid signature
            has_invalid = self._has_issue_code(issues, "SIGNATURE_VERIFICATION_FAILED")
            
            # Check for expired signature
            has_expired = self._has_issue_code(issues, "SIGNATURE_EXPIRED")
            
            # Check for multiple signatures (5 points)
            signatures = card_data.get("signatures", [])
            if isinstance(signatures, list) and len(signatures) > 1:
                multiple_sigs = True
                score += 5
            
            # Check if signature covers all fields (5 points)
            # In practice, this would verify the JWS payload includes all card fields
            if has_valid and not self._has_issue_code(issues, "INCOMPLETE_SIGNATURE_COVERAGE"):
                covers_all = True
                score += 5
            
            # Check if signature is recent (5 points)
            # Signatures less than 90 days old
            if has_valid and not has_expired:
                is_recent = True
                score += 5
        
        return SignaturesBreakdown(
            score=score,
            max_score=40,
            tested=tested,
            has_valid_signature=has_valid,
            multiple_signatures=multiple_sigs,
            covers_all_fields=covers_all,
            is_recent=is_recent,
            has_invalid_signature=has_invalid,
            has_expired_signature=has_expired
        )
    
    def _score_provider(
        self,
        card_data: Dict[str, Any],
        issues: List[ValidationIssue]
    ) -> ProviderBreakdown:
        """Score provider information (25 points).
        
        Args:
            card_data: Agent card data
            issues: Validation issues
            
        Returns:
            ProviderBreakdown with provider metrics
        """
        score = 0
        provider = card_data.get("provider", {})
        
        # Ensure provider is a dict (defensive coding for validation errors)
        if not isinstance(provider, dict):
            provider = {}
        
        # Check for organization (10 points)
        has_org = bool(provider.get("organization"))
        if has_org:
            score += 10
        
        # Check for provider URL (10 points)
        has_url = bool(provider.get("url"))
        if has_url:
            score += 10
        
        # Check if URL is reachable (5 points)
        # This would require network test, so we check if no related errors
        url_reachable = None
        if has_url and not self._has_issue_code(issues, ["PROVIDER_URL_UNREACHABLE"]):
            url_reachable = True
            score += 5
        elif has_url:
            url_reachable = False
        
        return ProviderBreakdown(
            score=score,
            max_score=25,
            tested=True,
            has_organization=has_org,
            has_url=has_url,
            url_reachable=url_reachable
        )
    
    def _score_security(
        self,
        card_data: Dict[str, Any],
        issues: List[ValidationIssue]
    ) -> SecurityBreakdown:
        """Score security configuration (20 points).
        
        Args:
            card_data: Agent card data
            issues: Validation issues
            
        Returns:
            SecurityBreakdown with security metrics
        """
        score = 0
        
        # Check HTTPS only (10 points)
        has_http = self._has_issue_code(issues, ["INSECURE_URL", "HTTP_URL_FOUND"])
        https_only = not has_http
        if https_only:
            score += 10
        
        # Check for security schemes (5 points)
        capabilities = card_data.get("capabilities", {})
        # Ensure capabilities is a dict (defensive coding for validation errors)
        if not isinstance(capabilities, dict):
            capabilities = {}
        security_schemes = capabilities.get("securitySchemes", [])
        has_security_schemes = bool(security_schemes)
        if has_security_schemes:
            score += 5
        
        # Check for strong auth (5 points)
        # OAuth2, API Key, or other authentication
        has_strong_auth = False
        if has_security_schemes:
            for scheme in security_schemes:
                scheme_type = scheme.get("type", "").lower()
                if scheme_type in ["oauth2", "apikey", "http"]:
                    has_strong_auth = True
                    break
        if has_strong_auth:
            score += 5
        
        return SecurityBreakdown(
            score=score,
            max_score=20,
            https_only=https_only,
            has_security_schemes=has_security_schemes,
            has_strong_auth=has_strong_auth,
            has_http_urls=has_http
        )
    
    def _score_documentation(self, card_data: Dict[str, Any]) -> DocumentationBreakdown:
        """Score documentation and transparency (15 points).
        
        Args:
            card_data: Agent card data
            
        Returns:
            DocumentationBreakdown with documentation metrics
        """
        score = 0
        
        # Check for documentation URL (5 points)
        has_docs = bool(card_data.get("documentationUrl"))
        if has_docs:
            score += 5
        
        # Check for terms of service (5 points)
        has_tos = bool(card_data.get("termsOfService"))
        if has_tos:
            score += 5
        
        # Check for privacy policy (5 points)
        has_privacy = bool(card_data.get("privacyPolicy"))
        if has_privacy:
            score += 5
        
        return DocumentationBreakdown(
            score=score,
            max_score=15,
            has_documentation_url=has_docs,
            has_terms_of_service=has_tos,
            has_privacy_policy=has_privacy
        )
    
    def _is_trust_issue(self, issue: ValidationIssue) -> bool:
        """Check if issue is trust-related.
        
        Args:
            issue: Validation issue to check
            
        Returns:
            True if trust-related
        """
        trust_codes = {
            "SIGNATURE_VERIFICATION_FAILED",
            "MISSING_SIGNATURE",
            "SIGNATURE_EXPIRED",
            "INCOMPLETE_SIGNATURE_COVERAGE",
            "INSECURE_URL",
            "HTTP_URL_FOUND",
            "PROVIDER_URL_UNREACHABLE",
            "SSRF_RISK",
            "PRIVATE_IP",
        }
        return issue.code in trust_codes
    
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
