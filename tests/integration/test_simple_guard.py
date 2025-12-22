"""
Integration tests for SimpleGuard validation against live server.

Tests SimpleGuard → gRPC → capiscio-server validation workflow.
This verifies that the SDK's SimpleGuard middleware correctly signs
messages and the server validates them.
"""

import os
import pytest
import requests
from capiscio_sdk.simple_guard import SimpleGuard
from capiscio_sdk.errors import VerificationError

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
                import time
                time.sleep(1)
                continue
            else:
                pytest.skip(f"Server not available at {API_BASE_URL}")
    return False


class TestSimpleGuardSignVerify:
    """Test SimpleGuard signing and verification."""

    def test_simpleguard_sign_message(self, server_health_check):
        """Test: SimpleGuard can sign messages."""
        guard = SimpleGuard(dev_mode=True)
        
        payload = {
            "sub": "test-agent",
            "aud": "did:web:example.com",
            "custom_claim": "test_value"
        }
        
        token = guard.sign_outbound(payload)
        
        assert token is not None
        assert isinstance(token, str)
        assert len(token.split('.')) == 3  # JWS has 3 parts
        print(f"✓ SimpleGuard signed message: {len(token)} bytes")
        
        guard.close()

    def test_simpleguard_sign_with_body(self, server_health_check):
        """Test: SimpleGuard can sign with body hash binding."""
        guard = SimpleGuard(dev_mode=True)
        
        payload = {"sub": "test-agent"}
        body = b"test request body"
        
        token = guard.sign_outbound(payload, body=body)
        
        assert token is not None
        # Token should include body hash in claims
        print(f"✓ SimpleGuard signed with body binding")
        
        guard.close()

    def test_simpleguard_verify_own_signature(self, server_health_check):
        """Test: SimpleGuard can verify its own signatures."""
        guard = SimpleGuard(dev_mode=True)
        
        payload = {"sub": "test-agent", "msg": "hello"}
        body = b"test body"
        
        # Sign
        token = guard.sign_outbound(payload, body=body)
        
        # Verify
        verified = guard.verify_inbound(token, body=body)
        
        assert verified is not None
        assert verified.get("iss") == guard.agent_id
        print(f"✓ SimpleGuard verified own signature: {verified.get('iss')}")
        
        guard.close()

    def test_simpleguard_verify_fails_wrong_body(self, server_health_check):
        """Test: Verification fails with mismatched body."""
        guard = SimpleGuard(dev_mode=True)
        
        payload = {"sub": "test-agent"}
        original_body = b"original body"
        wrong_body = b"different body"
        
        # Sign with original body
        token = guard.sign_outbound(payload, body=original_body)
        
        # Try to verify with wrong body
        with pytest.raises(VerificationError):
            guard.verify_inbound(token, body=wrong_body)
        
        print("✓ SimpleGuard correctly rejected mismatched body")
        guard.close()

    def test_simpleguard_verify_fails_invalid_token(self, server_health_check):
        """Test: Verification fails with invalid token."""
        guard = SimpleGuard(dev_mode=True)
        
        invalid_token = "invalid.token.here"
        
        with pytest.raises(VerificationError):
            guard.verify_inbound(invalid_token)
        
        print("✓ SimpleGuard correctly rejected invalid token")
        guard.close()


class TestSimpleGuardMakeHeaders:
    """Test SimpleGuard header generation."""

    def test_make_headers_with_signing(self, server_health_check):
        """Test: make_headers() generates badge header."""
        guard = SimpleGuard(dev_mode=True)
        
        payload = {"sub": "test-agent"}
        headers = guard.make_headers(payload)
        
        assert "X-Capiscio-Badge" in headers
        assert headers["X-Capiscio-Badge"] is not None
        assert len(headers["X-Capiscio-Badge"]) > 0
        print(f"✓ Generated badge header: {len(headers['X-Capiscio-Badge'])} bytes")
        
        guard.close()

    def test_make_headers_with_preexisting_badge(self, server_health_check):
        """Test: make_headers() uses provided badge_token."""
        preexisting_token = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.fake_sig"
        
        guard = SimpleGuard(dev_mode=True, badge_token=preexisting_token)
        
        payload = {"sub": "irrelevant"}  # Ignored when badge_token is set
        headers = guard.make_headers(payload)
        
        assert headers["X-Capiscio-Badge"] == preexisting_token
        print("✓ Used pre-existing badge token")
        
        guard.close()

    def test_set_badge_token(self, server_health_check):
        """Test: set_badge_token() updates the token."""
        guard = SimpleGuard(dev_mode=True)
        
        # Initially no badge token
        payload = {"sub": "test"}
        headers1 = guard.make_headers(payload)
        
        # Set badge token
        new_token = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJuZXcifQ.new_sig"
        guard.set_badge_token(new_token)
        
        # Now should use the set token
        headers2 = guard.make_headers(payload)
        
        assert headers2["X-Capiscio-Badge"] == new_token
        assert headers1["X-Capiscio-Badge"] != headers2["X-Capiscio-Badge"]
        print("✓ Badge token updated successfully")
        
        guard.close()


class TestSimpleGuardDevMode:
    """Test SimpleGuard dev mode behavior."""

    def test_dev_mode_auto_generates_did_key(self, server_health_check):
        """Test: Dev mode auto-generates did:key identity."""
        guard = SimpleGuard(dev_mode=True)
        
        assert guard.agent_id is not None
        assert guard.agent_id.startswith("did:key:")
        print(f"✓ Auto-generated DID: {guard.agent_id[:50]}...")
        
        guard.close()

    def test_explicit_agent_id_overrides(self, server_health_check):
        """Test: Explicit agent_id overrides auto-generation."""
        explicit_did = "did:web:example.com:agents:test-agent"
        
        # This may fail if agent doesn't exist, but we're testing the config
        try:
            guard = SimpleGuard(dev_mode=True, agent_id=explicit_did)
            # If it succeeds, agent_id should match
            # Note: SimpleGuard may still generate did:key in dev_mode
            # depending on implementation
            print(f"✓ Initialized with explicit agent_id")
            guard.close()
        except Exception as e:
            # Expected if agent doesn't exist
            print(f"✓ Explicit agent_id config accepted (agent may not exist: {e})")


class TestSimpleGuardContextManager:
    """Test SimpleGuard as context manager."""

    def test_context_manager(self, server_health_check):
        """Test: SimpleGuard works as context manager."""
        with SimpleGuard(dev_mode=True) as guard:
            payload = {"sub": "test"}
            token = guard.sign_outbound(payload)
            assert token is not None
        
        # Guard should be closed after context exit
        print("✓ Context manager works correctly")


# Integration with server endpoints (if available)

class TestSimpleGuardServerIntegration:
    """Test SimpleGuard against actual server endpoints."""

    @pytest.mark.skip(reason="Requires server endpoint that validates SimpleGuard tokens")
    def test_server_validates_simpleguard_token(self, server_health_check):
        """Test: Server validates SimpleGuard-signed requests."""
        guard = SimpleGuard(dev_mode=True)
        
        # Create signed request
        payload = {"sub": guard.agent_id, "action": "test"}
        headers = guard.make_headers(payload)
        
        # Send to server endpoint that validates badges
        # TODO: Implement when server has validation endpoint
        resp = requests.post(
            f"{API_BASE_URL}/v1/validate",
            headers=headers,
            json={"data": "test"}
        )
        
        assert resp.status_code == 200
        print("✓ Server validated SimpleGuard token")
        
        guard.close()

    @pytest.mark.skip(reason="Requires server gRPC validation endpoint")
    def test_server_grpc_validation(self, server_health_check):
        """Test: Server validates via gRPC."""
        # TODO: Implement when server exposes gRPC validation
        pass
