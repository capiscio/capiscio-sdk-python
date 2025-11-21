"""URL security validation for A2A protocol."""
import re
from typing import TYPE_CHECKING, Any, List, Optional
from urllib.parse import urlparse

from ..types import ValidationResult, ValidationIssue, ValidationSeverity, create_simple_validation_result

if TYPE_CHECKING:
    from .certificate import CertificateValidator


class URLSecurityValidator:
    """Validates URL security requirements per A2A specification."""

    # Private IPv4 ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    # Link-local: 169.254.0.0/16
    PRIVATE_IPV4_PATTERN = re.compile(
        r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.)'
    )
    
    # Private IPv6 ranges: fc00::/7, fe80::/10
    PRIVATE_IPV6_PATTERN = re.compile(r'^(fc|fd|fe[89ab])', re.IGNORECASE)
    
    LOCALHOST_NAMES = {'localhost', '127.0.0.1', '::1', '0.0.0.0', '::'}  # nosec B104 - validation constants, not binding

    def __init__(self, certificate_validator: Optional['CertificateValidator'] = None):
        """Initialize URL security validator.
        
        Args:
            certificate_validator: Optional certificate validator for TLS validation
        """
        self._certificate_validator = certificate_validator

    def validate_url(
        self,
        url: str,
        field_name: str = "url",
        require_https: bool = True
    ) -> ValidationResult:
        """
        Validate URL for security compliance (synchronous version).

        Args:
            url: URL to validate
            field_name: Name of the field being validated (for error messages)
            require_https: Whether HTTPS is required (default: True per A2A spec)

        Returns:
            ValidationResult with security validation results
        """
        issues: List[ValidationIssue] = []
        score = 100

        # Parse URL
        try:
            parsed = urlparse(url)
        except Exception as e:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="INVALID_URL_FORMAT",
                    message=f"{field_name}: Invalid URL format - {str(e)}",
                    path=field_name,
                )
            )
            return create_simple_validation_result(
                success=False,
                issues=issues,
                simple_score=0,
                dimension="trust"
            )

        # Continue with existing validation logic...
        return self._validate_url_internal(parsed, url, field_name, require_https, issues, score)

    async def validate_url_with_certificate(
        self,
        url: str,
        field_name: str = "url",
        require_https: bool = True
    ) -> ValidationResult:
        """
        Validate URL for security compliance including certificate validation (async version).

        Args:
            url: URL to validate
            field_name: Name of the field being validated (for error messages)
            require_https: Whether HTTPS is required (default: True per A2A spec)

        Returns:
            ValidationResult with security and certificate validation results
        """
        issues: List[ValidationIssue] = []
        score = 100

        # Parse URL
        try:
            parsed = urlparse(url)
        except Exception as e:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="INVALID_URL_FORMAT",
                    message=f"{field_name}: Invalid URL format - {str(e)}",
                    path=field_name,
                )
            )
            return create_simple_validation_result(
                success=False,
                issues=issues,
                simple_score=0,
                dimension="trust"
            )

        # First do standard URL validation
        result = self._validate_url_internal(parsed, url, field_name, require_https, issues, score)
        
        # Then optionally verify TLS certificate
        if self._certificate_validator and parsed.scheme == "https":
            cert_result = await self._certificate_validator.validate_url_certificate(url)
            result.issues.extend(cert_result.issues)
            # Reduce trust score based on certificate issues
            if not cert_result.success and cert_result.trust:
                # Merge certificate trust issues into result
                if result.trust and result.trust.total:
                    # Certificate issues reduce trust score
                    min(result.trust.total, cert_result.trust.total or 0)
                    # Update success based on combined issues
                    result.success = not any(i.severity == ValidationSeverity.ERROR for i in result.issues)
        
        return result

    def _validate_url_internal(
        self,
        parsed: Any,
        url: str,
        field_name: str,
        require_https: bool,
        issues: List[ValidationIssue],
        score: int
    ) -> ValidationResult:
        """Internal URL validation logic."""
        
        # Check scheme
        if not parsed.scheme:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="MISSING_URL_SCHEME",
                    message=f"{field_name}: URL must include scheme (https://)",
                    path=field_name,
                )
            )
            score -= 30

        # HTTPS enforcement (A2A specification §5.3)
        elif require_https and parsed.scheme != 'https':
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="HTTPS_REQUIRED",
                    message=f"{field_name}: Must use HTTPS (HTTP not allowed per A2A specification)",
                    path=field_name,
                )
            )
            score -= 40

        # Check for hostname
        if not parsed.hostname:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="MISSING_HOSTNAME",
                    message=f"{field_name}: URL must include hostname",
                    path=field_name,
                )
            )
            score -= 30
            
        else:
            # SSRF Protection: Check for localhost
            if parsed.hostname.lower() in self.LOCALHOST_NAMES:
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        code="LOCALHOST_NOT_ALLOWED",
                        message=f"{field_name}: Localhost addresses not allowed (SSRF protection)",
                        path=field_name,
                        details={"hostname": parsed.hostname},
                    )
                )
                score -= 50

            # SSRF Protection: Check for private IP addresses
            elif self._is_private_ip(parsed.hostname):
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        code="PRIVATE_IP_NOT_ALLOWED",
                        message=f"{field_name}: Private IP addresses not allowed (SSRF protection)",
                        path=field_name,
                        details={"hostname": parsed.hostname},
                    )
                )
                score -= 50

            # Check for IP address in hostname (warning)
            elif self._is_ip_address(parsed.hostname):
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        code="IP_ADDRESS_HOSTNAME",
                        message=f"{field_name}: Using IP address instead of domain name",
                        path=field_name,
                        details={"hostname": parsed.hostname},
                    )
                )
                score -= 10

        # Check for suspicious ports (if specified)
        if parsed.port:
            # Allow common HTTPS ports
            allowed_ports = {443, 8443}
            if require_https and parsed.port not in allowed_ports:
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        code="NON_STANDARD_PORT",
                        message=f"{field_name}: Non-standard HTTPS port {parsed.port}",
                        path=field_name,
                        details={"port": parsed.port},
                    )
                )
                score -= 5

        # Ensure score doesn't go negative
        score = max(0, score)

        return create_simple_validation_result(
            success=score >= 60 and not any(i.severity == ValidationSeverity.ERROR for i in issues),
            issues=issues,
            simple_score=score,
            dimension="trust"
        )

    def _is_private_ip(self, hostname: str) -> bool:
        """Check if hostname is a private IP address."""
        # IPv4 private ranges
        if self.PRIVATE_IPV4_PATTERN.match(hostname):
            return True
        
        # IPv6 private ranges
        if self.PRIVATE_IPV6_PATTERN.match(hostname):
            return True
        
        return False

    def _is_ip_address(self, hostname: str) -> bool:
        """Check if hostname is an IP address (IPv4 or IPv6)."""
        # IPv4 pattern
        ipv4_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        if ipv4_pattern.match(hostname):
            return True
        
        # IPv6 pattern (simplified)
        if ':' in hostname:
            return True
        
        return False
