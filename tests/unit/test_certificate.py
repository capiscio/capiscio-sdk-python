"""Tests for Certificate validator."""

import pytest
from unittest.mock import patch
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from capiscio_sdk.validators.certificate import CertificateValidator
from capiscio_sdk.types import ValidationSeverity


@pytest.fixture
def validator():
    """Create certificate validator instance."""
    return CertificateValidator()


def create_test_certificate(
    hostname: str = "example.com",
    days_until_expiry: int = 90,
    self_signed: bool = False
) -> x509.Certificate:
    """Create a test certificate for testing.
    
    Args:
        hostname: Hostname for certificate
        days_until_expiry: Days until certificate expires
        self_signed: Whether to create a self-signed certificate
        
    Returns:
        Test certificate
    """
    # Generate key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])
    
    # Create issuer (same as subject if self-signed)
    issuer = subject if self_signed else x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
    ])
    
    # Create certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=days_until_expiry))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )
    
    return cert


@pytest.mark.asyncio
async def test_validate_url_certificate_non_https(validator):
    """Test that non-HTTPS URLs get a warning."""
    result = await validator.validate_url_certificate("http://example.com", verify_hostname=True)
    
    warning_codes = [i.code for i in result.issues if i.severity == ValidationSeverity.WARNING]
    assert "NON_HTTPS_URL" in warning_codes


def test_validate_certificate_expiry_valid(validator):
    """Test validation of valid (not expired) certificate."""
    cert = create_test_certificate(days_until_expiry=90)
    issues = validator._validate_certificate_expiry(cert)
    
    # Should have no errors
    error_issues = [i for i in issues if i.severity == ValidationSeverity.ERROR]
    assert len(error_issues) == 0


def test_validate_certificate_expiry_expired(validator):
    """Test validation of expired certificate."""
    # Create certificate with valid range but then manipulate to make it expired
    from datetime import datetime, timedelta
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    
    # Create certificate that expired 10 days ago
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=100))
        .not_valid_after(datetime.utcnow() - timedelta(days=10))  # Expired 10 days ago
        .sign(key, hashes.SHA256(), default_backend())
    )
    
    issues = validator._validate_certificate_expiry(cert)
    
    error_codes = [i.code for i in issues if i.severity == ValidationSeverity.ERROR]
    assert "CERTIFICATE_EXPIRED" in error_codes


def test_validate_certificate_expiring_soon(validator):
    """Test warning for certificate expiring soon."""
    cert = create_test_certificate(days_until_expiry=15)  # Expires in 15 days
    issues = validator._validate_certificate_expiry(cert)
    
    warning_codes = [i.code for i in issues if i.severity == ValidationSeverity.WARNING]
    assert "CERTIFICATE_EXPIRING_SOON" in warning_codes


def test_validate_certificate_not_yet_valid(validator):
    """Test validation of certificate that is not yet valid."""
    # Create certificate that's valid starting 10 days from now
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() + timedelta(days=10))  # Not yet valid
        .not_valid_after(datetime.utcnow() + timedelta(days=100))
        .sign(key, hashes.SHA256(), default_backend())
    )
    
    issues = validator._validate_certificate_expiry(cert)
    
    error_codes = [i.code for i in issues if i.severity == ValidationSeverity.ERROR]
    assert "CERTIFICATE_NOT_YET_VALID" in error_codes


def test_validate_hostname_exact_match(validator):
    """Test hostname validation with exact match."""
    cert = create_test_certificate(hostname="example.com")
    issues = validator._validate_hostname(cert, "example.com")
    
    # Should have no errors
    error_issues = [i for i in issues if i.severity == ValidationSeverity.ERROR]
    assert len(error_issues) == 0


def test_validate_hostname_mismatch(validator):
    """Test hostname validation with mismatch."""
    cert = create_test_certificate(hostname="example.com")
    issues = validator._validate_hostname(cert, "different.com")
    
    error_codes = [i.code for i in issues if i.severity == ValidationSeverity.ERROR]
    assert "HOSTNAME_MISMATCH" in error_codes


def test_validate_hostname_wildcard_match(validator):
    """Test hostname validation with wildcard certificate."""
    # Create certificate with wildcard
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "*.example.com")])
    
    (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("*.example.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )
    
    # Test wildcard matching
    assert validator._matches_hostname("*.example.com", "foo.example.com")
    assert validator._matches_hostname("*.example.com", "bar.example.com")
    assert not validator._matches_hostname("*.example.com", "example.com")  # Wildcard doesn't match base domain
    assert not validator._matches_hostname("*.example.com", "foo.bar.example.com")  # Only one level


def test_matches_hostname_exact(validator):
    """Test exact hostname matching."""
    assert validator._matches_hostname("example.com", "example.com")
    assert validator._matches_hostname("example.com", "EXAMPLE.COM")  # Case insensitive
    assert not validator._matches_hostname("example.com", "different.com")


def test_check_self_signed(validator):
    """Test detection of self-signed certificates."""
    cert = create_test_certificate(self_signed=True)
    issues = validator._check_self_signed(cert)
    
    warning_codes = [i.code for i in issues if i.severity == ValidationSeverity.WARNING]
    assert "SELF_SIGNED_CERTIFICATE" in warning_codes


def test_check_not_self_signed(validator):
    """Test non-self-signed certificate detection."""
    cert = create_test_certificate(self_signed=False)
    issues = validator._check_self_signed(cert)
    
    # Should have no self-signed warnings
    warning_codes = [i.code for i in issues if i.severity == ValidationSeverity.WARNING]
    assert "SELF_SIGNED_CERTIFICATE" not in warning_codes


def test_validate_certificate_chain_valid(validator):
    """Test validation of valid certificate chain."""
    # Create a simple 2-certificate chain
    cert = create_test_certificate()
    issuer_cert = create_test_certificate(hostname="Test CA", self_signed=True)
    
    result = validator.validate_certificate_chain(cert, [issuer_cert])
    
    # Basic chain validation - may not be perfect but should not error on structure
    # Certificate validation is trust-related
    assert result.trust.total > 0


def test_validate_certificate_chain_empty(validator):
    """Test validation with empty certificate chain."""
    cert = create_test_certificate()
    
    result = validator.validate_certificate_chain(cert, [])
    
    warning_codes = [i.code for i in result.issues if i.severity == ValidationSeverity.WARNING]
    assert "NO_CERTIFICATE_CHAIN" in warning_codes


@pytest.mark.asyncio
async def test_validate_url_certificate_invalid_hostname(validator):
    """Test validation with invalid hostname in URL."""
    result = await validator.validate_url_certificate("https://", verify_hostname=True)
    
    assert not result.success
    error_codes = [i.code for i in result.issues if i.severity == ValidationSeverity.ERROR]
    assert "INVALID_HOSTNAME" in error_codes


@pytest.mark.asyncio
async def test_validate_url_certificate_fetch_failure(validator):
    """Test handling of certificate fetch failure."""
    with patch.object(validator, '_get_certificate', return_value=None):
        result = await validator.validate_url_certificate("https://example.com")
        
        assert not result.success
        error_codes = [i.code for i in result.issues if i.severity == ValidationSeverity.ERROR]
        assert "CERTIFICATE_FETCH_FAILED" in error_codes


def test_get_certificate_failure(validator):
    """Test handling of certificate retrieval failure."""
    # This will fail because we're not mocking the socket
    cert_pem = validator._get_certificate("invalid-hostname-that-does-not-exist.com", 443)
    assert cert_pem is None
