"""Availability scorer for operational readiness.

Calculates availability score (0-100) based on:
- Primary endpoint (50 points)
- Transport protocol support (30 points)
- Response quality (20 points)

Only calculated when network tests are enabled.
"""

from typing import List, Optional
from ..types import ValidationIssue
from .types import (
    AvailabilityScore,
    AvailabilityBreakdown,
    PrimaryEndpointBreakdown,
    TransportSupportBreakdown,
    ResponseQualityBreakdown,
    get_availability_rating,
)


class AvailabilityScorer:
    """Calculates availability scores for operational readiness."""
    
    def score_not_tested(self, reason: str = "Network tests not enabled") -> AvailabilityScore:
        """Create availability score for when testing was skipped.
        
        Args:
            reason: Why availability wasn't tested
            
        Returns:
            AvailabilityScore with tested=False
        """
        return AvailabilityScore(
            total=None,
            rating=None,
            breakdown=None,
            issues=[],
            tested=False,
            not_tested_reason=reason
        )
    
    def score_endpoint_test(
        self,
        endpoint_responded: bool,
        response_time: Optional[float] = None,
        has_cors: Optional[bool] = None,
        valid_tls: Optional[bool] = None,
        issues: Optional[List[ValidationIssue]] = None
    ) -> AvailabilityScore:
        """Calculate availability score based on endpoint test results.
        
        Args:
            endpoint_responded: Whether primary endpoint responded
            response_time: Response time in seconds (if responded)
            has_cors: Whether CORS headers present
            valid_tls: Whether TLS certificate is valid
            issues: List of validation issues found
            
        Returns:
            AvailabilityScore with detailed breakdown
        """
        if issues is None:
            issues = []
        
        # Score primary endpoint (50 points)
        primary = self._score_primary_endpoint(
            endpoint_responded,
            response_time,
            has_cors,
            valid_tls,
            issues
        )
        
        # Score transport support (30 points)
        # For now, basic scoring - can be enhanced with actual transport tests
        transport = self._score_transport_support(endpoint_responded, issues)
        
        # Score response quality (20 points)
        response_quality = self._score_response_quality(endpoint_responded, issues)
        
        # Calculate total
        total = primary.score + transport.score + response_quality.score
        total = max(0, min(100, total))
        
        # Create breakdown
        breakdown = AvailabilityBreakdown(
            primary_endpoint=primary,
            transport_support=transport,
            response_quality=response_quality
        )
        
        # Extract issue messages
        issue_messages = [
            issue.message for issue in issues
            if self._is_availability_issue(issue)
        ]
        
        return AvailabilityScore(
            total=total,
            rating=get_availability_rating(total),
            breakdown=breakdown,
            issues=issue_messages,
            tested=True
        )
    
    def _score_primary_endpoint(
        self,
        responded: bool,
        response_time: Optional[float],
        has_cors: Optional[bool],
        valid_tls: Optional[bool],
        issues: List[ValidationIssue]
    ) -> PrimaryEndpointBreakdown:
        """Score primary endpoint (50 points).
        
        Args:
            responded: Whether endpoint responded
            response_time: Response time in seconds
            has_cors: Whether CORS present
            valid_tls: Whether TLS valid
            issues: Validation issues
            
        Returns:
            PrimaryEndpointBreakdown
        """
        score = 0
        errors = []
        
        # Responds (30 points)
        if responded:
            score += 30
        else:
            errors.append("Endpoint did not respond")
        
        # Response time (10 points)
        if response_time is not None:
            if response_time < 2.0:  # Under 2 seconds
                score += 10
            elif response_time < 5.0:  # Under 5 seconds
                score += 5
            else:
                errors.append(f"Slow response time: {response_time:.2f}s")
        
        # Valid TLS (5 points)
        if valid_tls:
            score += 5
        elif valid_tls is False:
            errors.append("Invalid TLS certificate")
        
        # CORS support (5 points)
        if has_cors:
            score += 5
        elif has_cors is False:
            errors.append("Missing CORS headers")
        
        return PrimaryEndpointBreakdown(
            score=score,
            max_score=50,
            responds=responded,
            response_time=response_time,
            has_cors=has_cors,
            valid_tls=valid_tls,
            errors=errors
        )
    
    def _score_transport_support(
        self,
        endpoint_responded: bool,
        issues: List[ValidationIssue]
    ) -> TransportSupportBreakdown:
        """Score transport protocol support (30 points).
        
        Args:
            endpoint_responded: Whether primary endpoint worked
            issues: Validation issues
            
        Returns:
            TransportSupportBreakdown
        """
        score = 0
        
        # Preferred transport works (20 points)
        preferred_works = endpoint_responded and not self._has_issue_code(
            issues,
            "TRANSPORT_FAILED"
        )
        if preferred_works:
            score += 20
        
        # Additional interfaces (10 points)
        # This would require testing multiple transports
        # For now, give partial credit if primary works
        if preferred_works:
            score += 10
            additional_working = 1
            additional_failed = 0
        else:
            additional_working = 0
            additional_failed = 0
        
        return TransportSupportBreakdown(
            score=score,
            max_score=30,
            preferred_transport_works=preferred_works,
            additional_interfaces_working=additional_working,
            additional_interfaces_failed=additional_failed
        )
    
    def _score_response_quality(
        self,
        endpoint_responded: bool,
        issues: List[ValidationIssue]
    ) -> ResponseQualityBreakdown:
        """Score response quality (20 points).
        
        Args:
            endpoint_responded: Whether endpoint responded
            issues: Validation issues
            
        Returns:
            ResponseQualityBreakdown
        """
        score = 0
        
        # Valid structure (10 points)
        valid_structure = endpoint_responded and not self._has_issue_code(
            issues,
            ["INVALID_RESPONSE_STRUCTURE", "MALFORMED_JSON"]
        )
        if valid_structure:
            score += 10
        
        # Proper content type (5 points)
        proper_content_type = endpoint_responded and not self._has_issue_code(
            issues,
            "INVALID_CONTENT_TYPE"
        )
        if proper_content_type:
            score += 5
        
        # Proper error handling (5 points)
        # Check that errors are properly formatted
        proper_errors = endpoint_responded and not self._has_issue_code(
            issues,
            "IMPROPER_ERROR_FORMAT"
        )
        if proper_errors:
            score += 5
        
        return ResponseQualityBreakdown(
            score=score,
            max_score=20,
            valid_structure=valid_structure,
            proper_content_type=proper_content_type,
            proper_error_handling=proper_errors
        )
    
    def _is_availability_issue(self, issue: ValidationIssue) -> bool:
        """Check if issue is availability-related.
        
        Args:
            issue: Validation issue to check
            
        Returns:
            True if availability-related
        """
        availability_codes = {
            "ENDPOINT_UNREACHABLE",
            "TRANSPORT_FAILED",
            "TIMEOUT",
            "INVALID_RESPONSE_STRUCTURE",
            "MALFORMED_JSON",
            "INVALID_CONTENT_TYPE",
            "IMPROPER_ERROR_FORMAT",
            "TLS_ERROR",
            "CORS_ERROR",
        }
        return issue.code in availability_codes
    
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
