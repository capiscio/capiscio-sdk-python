"""Tests for URL security validator."""
import pytest
from capiscio_sdk.validators.url_security import URLSecurityValidator


@pytest.fixture
def validator():
    """Create URL security validator instance."""
    return URLSecurityValidator()


def test_validate_valid_https_url(validator):
    """Test validation of valid HTTPS URL."""
    result = validator.validate_url("https://example.com")
    assert result.success
    assert result.trust.total == 100
    assert len(result.errors) == 0


def test_validate_http_not_allowed(validator):
    """Test that HTTP is rejected."""
    result = validator.validate_url("http://example.com")
    assert not result.success
    assert any(i.code == "HTTPS_REQUIRED" for i in result.errors)


def test_validate_localhost_not_allowed(validator):
    """Test that localhost is rejected."""
    result = validator.validate_url("https://localhost")
    assert not result.success
    assert any(i.code == "LOCALHOST_NOT_ALLOWED" for i in result.errors)


def test_validate_127_0_0_1_not_allowed(validator):
    """Test that 127.0.0.1 is rejected."""
    result = validator.validate_url("https://127.0.0.1")
    assert not result.success
    assert any(i.code == "LOCALHOST_NOT_ALLOWED" for i in result.errors)


def test_validate_private_ip_10_x(validator):
    """Test that private IP 10.x is rejected."""
    result = validator.validate_url("https://10.0.0.1")
    assert not result.success
    assert any(i.code == "PRIVATE_IP_NOT_ALLOWED" for i in result.errors)


def test_validate_private_ip_192_168(validator):
    """Test that private IP 192.168.x is rejected."""
    result = validator.validate_url("https://192.168.1.1")
    assert not result.success
    assert any(i.code == "PRIVATE_IP_NOT_ALLOWED" for i in result.errors)


def test_validate_private_ip_172_16(validator):
    """Test that private IP 172.16-31.x is rejected."""
    result = validator.validate_url("https://172.16.0.1")
    assert not result.success
    assert any(i.code == "PRIVATE_IP_NOT_ALLOWED" for i in result.errors)


def test_validate_link_local_169_254(validator):
    """Test that link-local 169.254.x is rejected."""
    result = validator.validate_url("https://169.254.1.1")
    assert not result.success
    assert any(i.code == "PRIVATE_IP_NOT_ALLOWED" for i in result.errors)


def test_validate_public_ip_address_warning(validator):
    """Test that public IP address gets warning."""
    result = validator.validate_url("https://8.8.8.8")
    assert result.success
    assert any(i.code == "IP_ADDRESS_HOSTNAME" for i in result.warnings)


def test_validate_non_standard_port_warning(validator):
    """Test that non-standard HTTPS port gets warning."""
    result = validator.validate_url("https://example.com:8080")
    assert result.success
    assert any(i.code == "NON_STANDARD_PORT" for i in result.warnings)


def test_validate_standard_port_ok(validator):
    """Test that standard HTTPS port 443 is OK."""
    result = validator.validate_url("https://example.com:443")
    assert result.success
    assert result.trust.total == 100


def test_validate_missing_scheme(validator):
    """Test that URL without scheme is rejected."""
    result = validator.validate_url("example.com")
    assert not result.success
    assert any(i.code == "MISSING_URL_SCHEME" for i in result.errors)


def test_validate_invalid_url_format(validator):
    """Test that invalid URL format is rejected."""
    result = validator.validate_url("not a url at all")
    assert not result.success
    # Missing scheme error or invalid URL format
    assert any(i.code in ["INVALID_URL_FORMAT", "MISSING_URL_SCHEME"] for i in result.errors)


def test_validate_ipv6_localhost(validator):
    """Test that IPv6 localhost is rejected."""
    result = validator.validate_url("https://[::1]")
    assert not result.success
    assert any(i.code == "LOCALHOST_NOT_ALLOWED" for i in result.errors)


def test_validate_http_allowed_when_not_required(validator):
    """Test that HTTP is allowed when HTTPS is not required."""
    result = validator.validate_url("http://example.com", require_https=False)
    assert result.success
    assert result.trust.total >= 80
