"""Certificate validation for TLS/SSL connections.

This module provides validation for TLS/SSL certificates used in agent
communication. It checks certificate validity, expiry, hostname matching,
and certificate chain integrity.

Validates:
- Certificate validity and expiry
- Hostname verification
- Certificate chain integrity
- Self-signed certificate detection
- Certificate trust
"""

from typing import Optional, List
from datetime import datetime
import ssl
import socket
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import httpx

from ..types import ValidationResult, ValidationIssue, ValidationSeverity, create_simple_validation_result


class CertificateValidator:
    """Validates TLS/SSL certificates for secure agent communication.
    
    Performs certificate validation including expiry checks, hostname
    verification, and chain validation to ensure secure connections.
    """
    
    # Warning threshold for certificate expiry (days)
    EXPIRY_WARNING_DAYS = 30
    
    def __init__(self, http_client: Optional[httpx.AsyncClient] = None):
        """Initialize certificate validator.
        
        Args:
            http_client: Optional HTTP client with certificate verification
        """
        self.http_client = http_client or httpx.AsyncClient(
            timeout=10.0,
            verify=True  # Enable certificate verification
        )
    
    async def validate_url_certificate(
        self,
        url: str,
        verify_hostname: bool = True
    ) -> ValidationResult:
        """Validate certificate for a given URL.
        
        Args:
            url: URL to validate certificate for
            verify_hostname: Whether to verify hostname matches certificate
            
        Returns:
            ValidationResult with certificate validation issues
        """
        issues: List[ValidationIssue] = []
        
        try:
            parsed = urlparse(url)
            
            # Only validate HTTPS URLs
            if parsed.scheme != "https":
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="NON_HTTPS_URL",
                    message="Certificate validation only applies to HTTPS URLs",
                    path="certificate"
                ))
                return create_simple_validation_result(
                    success=True,
                    issues=issues,
                    simple_score=80,
                    dimension="trust"
                )
            
            hostname = parsed.hostname
            port = parsed.port or 443
            
            if not hostname:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="INVALID_HOSTNAME",
                    message="Cannot extract hostname from URL",
                    path="certificate"
                ))
                return create_simple_validation_result(
                    success=False,
                    issues=issues,
                    simple_score=0,
                    dimension="trust"
                )
            
            # Get certificate from server
            cert_pem = self._get_certificate(hostname, port)
            if not cert_pem:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="CERTIFICATE_FETCH_FAILED",
                    message=f"Failed to fetch certificate from {hostname}:{port}",
                    path="certificate"
                ))
                return create_simple_validation_result(
                    success=False,
                    issues=issues,
                    simple_score=0,
                    dimension="trust"
                )
            
            # Parse certificate
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            
            # Validate certificate
            issues.extend(self._validate_certificate_expiry(cert))
            
            if verify_hostname:
                issues.extend(self._validate_hostname(cert, hostname))
            
            issues.extend(self._check_self_signed(cert))
            
            # Calculate score
            error_count = sum(1 for i in issues if i.severity == ValidationSeverity.ERROR)
            warning_count = sum(1 for i in issues if i.severity == ValidationSeverity.WARNING)
            score = max(0, 100 - (error_count * 25) - (warning_count * 10))
            
            return create_simple_validation_result(
                success=error_count == 0,
                issues=issues,
                simple_score=score,
                dimension="trust"
            )
            
        except Exception as e:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                code="CERTIFICATE_VALIDATION_ERROR",
                message=f"Certificate validation error: {str(e)}",
                path="certificate"
            ))
            return create_simple_validation_result(
                success=False,
                issues=issues,
                simple_score=0,
                dimension="trust"
            )
    
    def _get_certificate(self, hostname: str, port: int) -> Optional[str]:
        """Retrieve certificate from server.
        
        Args:
            hostname: Server hostname
            port: Server port
            
        Returns:
            PEM-encoded certificate or None if failed
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    if cert_der:
                        cert = x509.load_der_x509_certificate(cert_der, default_backend())
                        return cert.public_bytes(encoding=x509.Encoding.PEM).decode()  # type: ignore[attr-defined]
            return None
        except Exception:
            return None
    
    def _validate_certificate_expiry(self, cert: x509.Certificate) -> List[ValidationIssue]:
        """Validate certificate expiry dates.
        
        Args:
            cert: Certificate to validate
            
        Returns:
            List of validation issues
        """
        issues: List[ValidationIssue] = []
        now = datetime.utcnow()
        
        # Check if certificate has expired
        if cert.not_valid_after < now:
            days_expired = (now - cert.not_valid_after).days
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                code="CERTIFICATE_EXPIRED",
                message=f"Certificate expired {days_expired} days ago (expired: {cert.not_valid_after.isoformat()})",
                path="certificate.expiry"
            ))
        # Check if certificate is not yet valid
        elif cert.not_valid_before > now:
            days_early = (cert.not_valid_before - now).days
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                code="CERTIFICATE_NOT_YET_VALID",
                message=f"Certificate not valid for {days_early} more days (valid from: {cert.not_valid_before.isoformat()})",
                path="certificate.validity"
            ))
        # Check if certificate expires soon
        else:
            days_until_expiry = (cert.not_valid_after - now).days
            if days_until_expiry <= self.EXPIRY_WARNING_DAYS:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="CERTIFICATE_EXPIRING_SOON",
                    message=f"Certificate expires in {days_until_expiry} days (expires: {cert.not_valid_after.isoformat()})",
                    path="certificate.expiry"
                ))
        
        return issues
    
    def _validate_hostname(self, cert: x509.Certificate, hostname: str) -> List[ValidationIssue]:
        """Validate certificate hostname matches.
        
        Args:
            cert: Certificate to validate
            hostname: Expected hostname
            
        Returns:
            List of validation issues
        """
        issues: List[ValidationIssue] = []
        
        try:
            # Get subject common name
            subject = cert.subject
            common_names = [
                attr.value for attr in subject
                if attr.oid == NameOID.COMMON_NAME
            ]
            
            # Get subject alternative names
            san_names: List[str] = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                san_names = [
                    str(name.value) for name in san_ext.value  # type: ignore[attr-defined]
                    if isinstance(name, x509.DNSName)
                ]
            except x509.ExtensionNotFound:
                pass
            
            # Check if hostname matches
            all_names = common_names + san_names
            if not any(self._matches_hostname(name, hostname) for name in all_names):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="HOSTNAME_MISMATCH",
                    message=f"Certificate hostname mismatch. Expected: {hostname}, Certificate names: {', '.join(all_names) if all_names else 'none'}",
                    path="certificate.hostname"
                ))
        
        except Exception as e:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                code="HOSTNAME_VALIDATION_ERROR",
                message=f"Failed to validate hostname: {str(e)}",
                path="certificate.hostname"
            ))
        
        return issues
    
    def _matches_hostname(self, cert_name: str, hostname: str) -> bool:
        """Check if certificate name matches hostname.
        
        Supports wildcard certificates (*.example.com).
        
        Args:
            cert_name: Name from certificate
            hostname: Hostname to match
            
        Returns:
            True if matches, False otherwise
        """
        # Exact match
        if cert_name.lower() == hostname.lower():
            return True
        
        # Wildcard match (*.example.com matches foo.example.com)
        if cert_name.startswith("*."):
            cert_domain = cert_name[2:].lower()
            if "." in hostname:
                _, host_domain = hostname.split(".", 1)
                if host_domain.lower() == cert_domain:
                    return True
        
        return False
    
    def _check_self_signed(self, cert: x509.Certificate) -> List[ValidationIssue]:
        """Check if certificate is self-signed.
        
        Args:
            cert: Certificate to check
            
        Returns:
            List of validation issues
        """
        issues: List[ValidationIssue] = []
        
        try:
            # A certificate is self-signed if issuer == subject
            if cert.issuer == cert.subject:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="SELF_SIGNED_CERTIFICATE",
                    message="Certificate is self-signed (not issued by trusted CA)",
                    path="certificate.issuer"
                ))
        except Exception:
            pass
        
        return issues
    
    def validate_certificate_chain(
        self,
        cert: x509.Certificate,
        chain: List[x509.Certificate]
    ) -> ValidationResult:
        """Validate certificate chain integrity.
        
        Args:
            cert: End-entity certificate
            chain: Certificate chain (intermediate + root)
            
        Returns:
            ValidationResult with chain validation issues
        """
        issues: List[ValidationIssue] = []
        
        try:
            # Basic chain validation
            if not chain:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="NO_CERTIFICATE_CHAIN",
                    message="No certificate chain provided",
                    path="certificate.chain"
                ))
            else:
                # Verify each certificate in chain is issued by the next
                current = cert
                for idx, issuer_cert in enumerate(chain):
                    if current.issuer != issuer_cert.subject:
                        issues.append(ValidationIssue(
                            severity=ValidationSeverity.ERROR,
                            code="CHAIN_BROKEN",
                            message=f"Certificate chain broken at position {idx}",
                            path=f"certificate.chain[{idx}]"
                        ))
                        break
                    current = issuer_cert
            
            error_count = sum(1 for i in issues if i.severity == ValidationSeverity.ERROR)
            warning_count = sum(1 for i in issues if i.severity == ValidationSeverity.WARNING)
            score = max(0, 100 - (error_count * 25) - (warning_count * 10))
            
            return create_simple_validation_result(
                success=error_count == 0,
                issues=issues,
                simple_score=score,
                dimension="trust"
            )
        
        except Exception as e:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                code="CHAIN_VALIDATION_ERROR",
                message=f"Certificate chain validation error: {str(e)}",
                path="certificate.chain"
            ))
            return create_simple_validation_result(
                success=False,
                issues=issues,
                simple_score=0,
                dimension="trust"
            )
