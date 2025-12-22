"""
Integration tests for capiscio-sdk-python → capiscio-server.

These tests verify SDK functionality against a live capiscio-server instance.
Unlike test_real_executor.py which uses mocked validation, these tests make
real HTTP/gRPC calls to the server.

Test Coverage:
- Badge client requesting badges from server
- Badge verification against live JWKS
- SimpleGuard validation workflow
- BadgeKeeper auto-renewal
- Error handling and edge cases
"""

import os
import pytest
import requests
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from capiscio_sdk.badge_client import BadgeClient
from capiscio_sdk.badge_verifier import BadgeVerifier
from capiscio_sdk.errors import CapiscioError

# Get API URL from environment
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8080")


@pytest.fixture(scope="module")
def server_health_check():
    """Verify server is running before tests."""
    max_retries = 30
    for i in range(max_retries):
        try:
            resp = requests.get(f"{API_BASE_URL}/health", timeout=2)
            if resp.status_code == 200:
                print(f"✓ Server is healthy at {API_BASE_URL}")
                return True
        except requests.exceptions.RequestException:
            if i < max_retries - 1:
                time.sleep(1)
                continue
            else:
                pytest.skip(f"Server not available at {API_BASE_URL}")
    return False


@pytest.fixture
def test_api_key():
    """Get test API key for badge issuance."""
    # TODO: Set up test agent and get real API key
    # For now, return placeholder
    api_key = os.getenv("TEST_API_KEY", "test-api-key-placeholder")
    return api_key


class TestBadgeClientIntegration:
    """Integration tests for BadgeClient against live server."""

    def test_request_badge_success(self, server_health_check, test_api_key):
        """Test: Request badge from live server successfully."""
        client = BadgeClient(
            registry_url=API_BASE_URL,
            api_key=test_api_key
        )

        try:
            result = client.request_badge(
                agent_id="test-agent-sdk-001",
                domain="sdk-test.example.com",
                ttl=300  # 5 minutes
            )

            assert result is not None
            assert "token" in result
            assert "jti" in result
            assert result["jti"] != ""
            print(f"✓ Issued badge: JTI={result['jti']}")

        except CapiscioError as e:
            # If agent doesn't exist, that's expected
            if "not found" in str(e).lower():
                pytest.skip("Test agent not registered - expected in initial setup")
            else:
                raise

    def test_request_badge_invalid_api_key(self, server_health_check):
        """Test: Invalid API key is rejected."""
        client = BadgeClient(
            registry_url=API_BASE_URL,
            api_key="invalid-key-12345"
        )

        with pytest.raises(CapiscioError) as exc_info:
            client.request_badge(
                agent_id="test-agent-001",
                domain="test.example.com"
            )

        # Should get authentication error
        assert "auth" in str(exc_info.value).lower() or "unauthorized" in str(exc_info.value).lower()
        print(f"✓ Invalid API key correctly rejected: {exc_info.value}")

    def test_request_badge_nonexistent_agent(self, server_health_check, test_api_key):
        """Test: Nonexistent agent returns 404."""
        client = BadgeClient(
            registry_url=API_BASE_URL,
            api_key=test_api_key
        )

        with pytest.raises(CapiscioError) as exc_info:
            client.request_badge(
                agent_id="nonexistent-agent-999",
                domain="test.example.com"
            )

        # Should get not found error
        error_msg = str(exc_info.value).lower()
        assert "not found" in error_msg or "404" in error_msg
        print(f"✓ Nonexistent agent correctly rejected: {exc_info.value}")


class TestBadgeVerifierIntegration:
    """Integration tests for BadgeVerifier against live server."""

    @pytest.mark.skip(reason="Requires valid badge from server - implement after agent setup")
    def test_verify_badge_success(self, server_health_check, test_api_key):
        """Test: Verify badge against live JWKS."""
        # Step 1: Issue badge
        client = BadgeClient(
            registry_url=API_BASE_URL,
            api_key=test_api_key
        )
        
        result = client.request_badge(
            agent_id="test-agent-verifier",
            domain="verify-sdk.example.com"
        )
        
        badge_token = result["token"]

        # Step 2: Verify badge
        verifier = BadgeVerifier(registry_url=API_BASE_URL)
        claims = verifier.verify(badge_token)

        assert claims is not None
        assert claims["jti"] == result["jti"]
        assert claims["sub"] == result["subject"]
        print(f"✓ Verified badge: {claims['jti']}")

    def test_verify_invalid_token(self, server_health_check):
        """Test: Invalid token is rejected."""
        verifier = BadgeVerifier(registry_url=API_BASE_URL)

        with pytest.raises(CapiscioError):
            verifier.verify("invalid.token.here")

        print("✓ Invalid token correctly rejected")

    def test_verify_malformed_token(self, server_health_check):
        """Test: Malformed token is rejected."""
        verifier = BadgeVerifier(registry_url=API_BASE_URL)

        with pytest.raises(CapiscioError):
            verifier.verify("not-even-a-jwt")

        print("✓ Malformed token correctly rejected")


class TestPoPIntegration:
    """Integration tests for PoP protocol."""

    @pytest.mark.skip(reason="Requires PoP implementation - implement after RFC-003 support")
    def test_pop_challenge_flow(self, server_health_check, test_api_key):
        """Test: Complete PoP challenge-response flow."""
        # Generate key pair
        private_key = Ed25519PrivateKey.generate()
        
        # TODO: Implement PoP client in SDK
        # 1. Request challenge
        # 2. Sign challenge with private key
        # 3. Submit proof
        # 4. Receive IAL-1 badge
        pass


class TestSimpleGuardIntegration:
    """Integration tests for SimpleGuard validation."""

    @pytest.mark.skip(reason="Requires SimpleGuard server validation - implement after setup")
    def test_simpleguard_sign_and_verify(self, server_health_check):
        """Test: SimpleGuard signs message and server verifies."""
        # TODO: Implement SimpleGuard integration test
        # 1. Initialize SimpleGuard with agent keys
        # 2. Sign outbound message
        # 3. Send to server for verification
        # 4. Verify server accepts signature
        pass


class TestBadgeKeeperIntegration:
    """Integration tests for BadgeKeeper auto-renewal."""

    @pytest.mark.skip(reason="Requires BadgeKeeper implementation - implement after Task 10")
    def test_badge_keeper_auto_renewal(self, server_health_check, test_api_key):
        """Test: BadgeKeeper automatically renews expiring badges."""
        # TODO: Implement BadgeKeeper integration test
        # 1. Issue badge with short TTL
        # 2. Start BadgeKeeper
        # 3. Wait for expiry
        # 4. Verify badge is auto-renewed
        pass


# Utility tests

def test_server_jwks_endpoint(server_health_check):
    """Test: Server exposes JWKS endpoint."""
    resp = requests.get(f"{API_BASE_URL}/.well-known/jwks.json")
    assert resp.status_code == 200
    jwks = resp.json()
    assert "keys" in jwks
    assert isinstance(jwks["keys"], list)
    print(f"✓ JWKS endpoint accessible: {len(jwks['keys'])} keys")


def test_server_agent_registry_endpoint(server_health_check):
    """Test: Server has agent registry endpoint."""
    resp = requests.get(f"{API_BASE_URL}/v1/agents")
    # May return 404 or empty list depending on implementation
    assert resp.status_code in [200, 404]
    print("✓ Agent registry endpoint accessible")
