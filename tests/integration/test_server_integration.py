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
from capiscio_sdk.badge import verify_badge, parse_badge
from capiscio_sdk.badge_keeper import BadgeKeeper
from capiscio_sdk.errors import CapiscioSecurityError

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
    api_key = os.getenv("TEST_API_KEY")
    if not api_key:
        pytest.skip("TEST_API_KEY environment variable required")
    return api_key


@pytest.fixture
def register_test_agent():
    """Register a test agent via the SDK endpoint.
    
    Returns a function that can be called to register an agent with a given DID.
    """
    def _register(did: str, name: str = "Test Agent", public_key: str = None):
        """Register agent via SDK endpoint.
        
        Args:
            did: Agent DID identifier
            name: Agent name
            public_key: Base64-encoded public key (optional, required for did:web PoP)
        """
        api_key = os.getenv("TEST_API_KEY")
        if not api_key:
            pytest.skip("TEST_API_KEY environment variable required")
        
        agent_data = {
            "name": name,
            "did": did
        }
        
        # Add public key if provided (needed for did:web DID Document)
        if public_key:
            agent_data["publicKey"] = public_key
        
        resp = requests.post(
            f"{API_BASE_URL}/v1/sdk/agents",
            headers={
                "X-Capiscio-Registry-Key": api_key,
                "Content-Type": "application/json"
            },
            json=agent_data
        )
        
        if resp.status_code == 200:
            return resp.json()["data"]
        else:
            # Agent might already exist - that's ok
            print(f"Agent registration returned {resp.status_code}: {resp.text}")
            return None
    
    return _register


@pytest.mark.skip(reason="BadgeClient class not exported - tests need refactor to use DV flow")
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


@pytest.mark.skip(reason="BadgeVerifier class not exported - tests need refactor to use verify_badge()")
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
    """Integration tests for PoP protocol (RFC-003)."""

    def test_pop_challenge_flow(self, server_health_check, test_api_key, register_test_agent):
        """Test: Complete PoP challenge-response flow with real server."""
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from capiscio_sdk.badge import request_pop_badge_sync
        import json
        
        # Generate Ed25519 key pair
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        # Convert to JWK format
        from cryptography.hazmat.primitives import serialization
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        import base64
        private_key_jwk = json.dumps({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64.urlsafe_b64encode(public_bytes).decode().rstrip("="),
            "d": base64.urlsafe_b64encode(private_bytes).decode().rstrip("=")
        })
        
        # Define agent DID - use localhost:8080 for local testing
        # Format: did:web:localhost%3A8080:agents:{uuid}
        # Note: Port must be percent-encoded per W3C did:web spec
        import uuid as uuid_module
        agent_uuid = str(uuid_module.uuid4())
        agent_did = f"did:web:localhost%3A8080:agents:{agent_uuid}"
        
        # Encode public key for agent registration (DID Document needs this)
        public_key_b64 = base64.b64encode(public_bytes).decode()
        
        # Register agent with public key before requesting badge
        register_test_agent(agent_did, "PoP Flow Test Agent", public_key=public_key_b64)
        
        # Request PoP badge
        token = request_pop_badge_sync(
            agent_did=agent_did,
            private_key_jwk=private_key_jwk,
            ca_url=os.environ.get("CAPISCIO_CA_URL", "http://localhost:8080"),
            api_key=test_api_key,
        )
        
        # Verify badge structure
        assert token
        assert len(token.split('.')) == 3
        
        # Parse and verify claims
        from capiscio_sdk.badge import parse_badge
        claims = parse_badge(token)
        
        # Verify IAL-1 badge characteristics
        # Note: IAL-1 badges have cnf claim with key binding
        assert claims.subject == agent_did
        
        print("✓ PoP badge request successful with IAL-1 assurance")

    def test_pop_badge_did_key(self, server_health_check, test_api_key, register_test_agent):
        """Test: PoP badge request with did:key identifier."""
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from capiscio_sdk.badge import request_pop_badge_sync
        import json
        import base64
        
        # Generate Ed25519 key pair
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        # Create did:key from public key
        from cryptography.hazmat.primitives import serialization
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Multicodec prefix for Ed25519 (0xed01) + public key
        multicodec_key = b'\xed\x01' + public_bytes
        
        # Base58btc encode
        import base58
        did_key = "did:key:z" + base58.b58encode(multicodec_key).decode()
        
        # Register agent with did:key
        register_test_agent(did_key, "did:key Test Agent")
        
        # Convert private key to JWK
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        private_key_jwk = json.dumps({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64.urlsafe_b64encode(public_bytes).decode().rstrip("="),
            "d": base64.urlsafe_b64encode(private_bytes).decode().rstrip("=")
        })
        
        # Request PoP badge with did:key
        token = request_pop_badge_sync(
            agent_did=did_key,
            private_key_jwk=private_key_jwk,
            ca_url=os.environ.get("CAPISCIO_CA_URL", "http://localhost:8080"),
            api_key=test_api_key,
        )
        
        # Verify badge
        assert token
        from capiscio_sdk.badge import parse_badge
        claims = parse_badge(token)
        assert claims.subject == did_key
        
        print("✓ PoP badge with did:key successful")

    def test_pop_badge_error_handling(self, server_health_check, test_api_key):
        """Test: PoP badge error handling for various failure cases."""
        from capiscio_sdk.badge import request_pop_badge_sync
        import json
        
        # Invalid JWK format
        with pytest.raises(ValueError):
            request_pop_badge_sync(
                agent_did="did:web:registry.capisc.io:agents:test-agent",
                private_key_jwk="not-a-jwk",
                api_key=test_api_key,
            )
        
        # Invalid DID format
        valid_jwk = json.dumps({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
        })
        
        with pytest.raises(ValueError):
            request_pop_badge_sync(
                agent_did="not-a-did",
                private_key_jwk=valid_jwk,
                api_key=test_api_key,
            )
        
        print("✓ PoP error handling works correctly")


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
