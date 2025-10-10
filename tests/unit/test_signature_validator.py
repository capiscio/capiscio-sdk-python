"""Tests for signature validator."""
import pytest
from capiscio_a2a_security.validators.signature import SignatureValidator


@pytest.fixture
def validator():
    """Create signature validator instance."""
    return SignatureValidator()


def test_validate_signature_format(validator):
    """Test signature format validation."""
    # Valid JWS format (3 parts)
    signature = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    result = validator.validate_signature({}, signature)
    
    # If PyJWT is not installed, trust score will be 0 (with warning)
    # If installed, trust score should be > 0
    if not validator._crypto_available:
        assert result.trust.total == 0
        assert any(i.code == "CRYPTO_NOT_AVAILABLE" for i in result.warnings)
    else:
        assert result.trust.total > 0


def test_validate_invalid_signature_format(validator):
    """Test invalid signature format."""
    result = validator.validate_signature({}, "not.a.valid.signature.format")
    assert not result.success
    # If PyJWT not available, will show crypto warning instead
    if validator._crypto_available:
        assert any(i.code == "INVALID_JWS_FORMAT" for i in result.errors)
    else:
        assert any(i.code == "CRYPTO_NOT_AVAILABLE" for i in result.warnings)


def test_validate_empty_signature(validator):
    """Test empty signature."""
    result = validator.validate_signature({}, "")
    assert not result.success
    # Should catch empty signature before checking crypto availability
    assert any(i.code == "INVALID_SIGNATURE_FORMAT" for i in result.errors)


def test_validate_no_signatures(validator):
    """Test validation with no signatures."""
    result = validator.validate_signatures({}, [])
    assert not result.success
    assert any(i.code == "NO_SIGNATURES" for i in result.warnings)


def test_validate_multiple_signatures(validator):
    """Test validation of multiple signatures."""
    signatures = [
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature2",
    ]
    result = validator.validate_signatures({}, signatures)
    
    # Should process both signatures
    assert result.metadata["total_signatures"] == 2


def test_crypto_availability_check(validator):
    """Test that crypto availability is checked."""
    # This will depend on whether PyJWT is installed
    # Just verify the check runs without error
    assert hasattr(validator, '_crypto_available')
