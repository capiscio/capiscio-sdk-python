"""Integration tests for DV SDK high-level API."""

import os

import pytest

from capiscio_sdk.dv import create_dv_order, finalize_dv_order, get_dv_order


# Test configuration
TEST_SERVER_URL = os.getenv("CAPISCIO_TEST_SERVER", "http://localhost:8080")


@pytest.fixture
def test_jwk():
    """Generate a test JWK."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    import base64
    
    # Generate Ed25519 key
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Get raw bytes
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    # Create JWK
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(public_bytes).decode().rstrip("="),
        "d": base64.urlsafe_b64encode(private_bytes).decode().rstrip("="),
        "use": "sig",
        "alg": "EdDSA"
    }
    
    return jwk


class TestDVSDK:
    """Test DV SDK high-level API."""
    
    def test_create_dv_order_http01(self, test_jwk):
        """Test creating an HTTP-01 DV order using SDK."""
        order = create_dv_order(
            domain="test-sdk.example.com",
            challenge_type="http-01",
            jwk=test_jwk,
            ca_url=TEST_SERVER_URL
        )
        
        # Verify order structure
        assert order.order_id is not None
        assert order.domain == "test-sdk.example.com"
        assert order.challenge_type == "http-01"
        assert order.challenge_token is not None
        assert order.status == "pending"
        assert order.validation_url is not None
        assert "test-sdk.example.com" in order.validation_url
        assert ".well-known/capiscio-challenge" in order.validation_url
        assert order.expires_at is not None
        
    def test_create_dv_order_dns01(self, test_jwk):
        """Test creating a DNS-01 DV order using SDK."""
        order = create_dv_order(
            domain="test-sdk-dns.example.com",
            challenge_type="dns-01",
            jwk=test_jwk,
            ca_url=TEST_SERVER_URL
        )
        
        # Verify order structure
        assert order.order_id is not None
        assert order.domain == "test-sdk-dns.example.com"
        assert order.challenge_type == "dns-01"
        assert order.challenge_token is not None
        assert order.status == "pending"
        assert order.dns_record is not None
        assert order.expires_at is not None
        
    def test_get_dv_order_status(self, test_jwk):
        """Test getting order status using SDK."""
        # Create order first
        created_order = create_dv_order(
            domain="test-status.example.com",
            challenge_type="http-01",
            jwk=test_jwk,
            ca_url=TEST_SERVER_URL
        )
        
        # Get order status
        order = get_dv_order(
            order_id=created_order.order_id,
            ca_url=TEST_SERVER_URL
        )
        
        # Verify order matches
        assert order.order_id == created_order.order_id
        assert order.domain == "test-status.example.com"
        assert order.challenge_type == "http-01"
        assert order.status == "pending"
        
    def test_get_nonexistent_order(self):
        """Test getting a non-existent order returns error."""
        fake_order_id = "00000000-0000-0000-0000-000000000000"
        
        with pytest.raises(ValueError) as exc_info:
            get_dv_order(
                order_id=fake_order_id,
                ca_url=TEST_SERVER_URL
            )
        
        # Should contain error message about not finding the order
        assert "Failed to get DV order" in str(exc_info.value) or "not found" in str(exc_info.value).lower()
        
    def test_finalize_order_without_validation_fails(self, test_jwk):
        """Test finalizing order without domain validation fails."""
        # Create order
        order = create_dv_order(
            domain="test-finalize-fail.example.com",
            challenge_type="http-01",
            jwk=test_jwk,
            ca_url=TEST_SERVER_URL
        )
        
        # Try to finalize without provisioning challenge (should fail)
        with pytest.raises(ValueError) as exc_info:
            finalize_dv_order(
                order_id=order.order_id,
                ca_url=TEST_SERVER_URL
            )
        
        # Should contain error message about validation failure
        assert "Failed to finalize DV order" in str(exc_info.value)
        
    def test_invalid_challenge_type(self, test_jwk):
        """Test creating order with invalid challenge type."""
        with pytest.raises(ValueError) as exc_info:
            create_dv_order(
                domain="test.example.com",
                challenge_type="invalid-challenge",
                jwk=test_jwk,
                ca_url=TEST_SERVER_URL
            )
        
        assert "Invalid challenge_type" in str(exc_info.value)
        assert "invalid-challenge" in str(exc_info.value)
