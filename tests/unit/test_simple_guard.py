"""Tests for SimpleGuard.

These tests verify the public API of SimpleGuard, which delegates
all cryptographic operations to the Go core via gRPC.
"""

import os
import json
import pytest
from unittest.mock import patch, MagicMock

from capiscio_sdk.simple_guard import SimpleGuard
from capiscio_sdk.errors import VerificationError, ConfigurationError


@pytest.fixture
def temp_workspace(tmp_path):
    """Create a temporary workspace for SimpleGuard."""
    cwd = os.getcwd()
    os.chdir(tmp_path)
    yield tmp_path
    os.chdir(cwd)


@pytest.fixture
def mock_rpc_client():
    """Create a mock RPC client for testing without requiring Go core."""
    with patch("capiscio_sdk.simple_guard.CapiscioRPCClient") as MockClient:
        mock_instance = MagicMock()
        MockClient.return_value = mock_instance
        
        # Setup simpleguard service mock
        mock_instance.simpleguard = MagicMock()
        mock_instance.simpleguard.load_key.return_value = ({"key_id": "test-key"}, None)
        mock_instance.simpleguard.generate_key_pair.return_value = ({
            "key_id": "test-key",
            "private_key_pem": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
            "public_key_pem": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
        }, None)
        mock_instance.simpleguard.sign_attached.return_value = ("mock.jws.token", None)
        mock_instance.simpleguard.verify_attached.return_value = (
            True, 
            b'{"sub": "test", "iss": "local-dev-agent"}',
            "test-key",
            None
        )
        
        yield mock_instance


class TestSimpleGuardInitialization:
    """Tests for SimpleGuard initialization."""

    def test_dev_mode_creates_directories(self, temp_workspace, mock_rpc_client):
        """Test that dev_mode creates necessary directories."""
        guard = SimpleGuard(dev_mode=True)
        
        assert (temp_workspace / "capiscio_keys").exists()
        assert (temp_workspace / "capiscio_keys" / "trusted").exists()
        
        guard.close()

    def test_dev_mode_generates_keys_without_agent_card(self, temp_workspace, mock_rpc_client):
        """Test that dev_mode generates keys but does NOT create agent-card.json."""
        guard = SimpleGuard(dev_mode=True)
        
        # Keys are generated via gRPC
        mock_rpc_client.simpleguard.generate_key_pair.assert_called_once()
        
        # agent-card.json should NOT be created (eliminated as dead weight)
        assert not (temp_workspace / "agent-card.json").exists()
        
        guard.close()

    def test_production_mode_requires_config(self, temp_workspace, mock_rpc_client):
        """Test that production mode fails without existing config."""
        with pytest.raises(ConfigurationError, match="No agent identity configured"):
            SimpleGuard(dev_mode=False)

    def test_explicit_agent_id_and_signing_kid(self, temp_workspace, mock_rpc_client):
        """Test that explicit agent_id + signing_kid skips agent-card.json entirely."""
        keys_dir = temp_workspace / "capiscio_keys"
        keys_dir.mkdir()
        (keys_dir / "private.pem").write_text("mock key")
        
        guard = SimpleGuard(
            agent_id="did:web:example.com:agents:test",
            signing_kid="key-1",
            dev_mode=False,
        )
        assert guard.agent_id == "did:web:example.com:agents:test"
        assert guard.signing_kid == "test-key"  # Updated by load_key
        
        # No agent-card.json needed
        assert not (temp_workspace / "agent-card.json").exists()
        
        guard.close()

    def test_legacy_agent_card_with_deprecation_warning(self, temp_workspace, mock_rpc_client, caplog):
        """Test that loading from agent-card.json works but logs deprecation warning."""
        import logging
        
        # Create legacy agent-card.json
        card = {
            "agent_id": "my-agent",
            "public_keys": [{"kid": "my-key", "kty": "OKP", "crv": "Ed25519"}],
        }
        (temp_workspace / "agent-card.json").write_text(json.dumps(card))
        
        # Create keys directory
        keys_dir = temp_workspace / "capiscio_keys"
        keys_dir.mkdir()
        (keys_dir / "private.pem").write_text("mock key")
        
        with caplog.at_level(logging.WARNING):
            guard = SimpleGuard(dev_mode=False)
        
        assert guard.agent_id == "my-agent"
        assert "deprecated" in caplog.text.lower()
        
        guard.close()


class TestSimpleGuardDidKeyRecovery:
    """Tests for dev mode did:key persistence and recovery."""

    def test_dev_mode_persists_did_key_on_generate(self, temp_workspace, mock_rpc_client):
        """Test that dev_mode persists did:key to sidecar file on first generation."""
        mock_rpc_client.simpleguard.generate_key_pair.return_value = ({
            "key_id": "test-key",
            "did_key": "did:key:z6MkTestGeneratedKey",
            "private_key_pem": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
            "public_key_pem": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
        }, None)

        guard = SimpleGuard(dev_mode=True)

        assert guard.agent_id == "did:key:z6MkTestGeneratedKey"
        did_key_path = temp_workspace / "capiscio_keys" / "did_key.txt"
        assert did_key_path.exists()
        assert did_key_path.read_text() == "did:key:z6MkTestGeneratedKey"

        guard.close()

    def test_dev_mode_recovers_did_key_on_load(self, temp_workspace, mock_rpc_client):
        """Test that dev_mode recovers did:key from sidecar file when key exists."""
        keys_dir = temp_workspace / "capiscio_keys"
        keys_dir.mkdir(parents=True)
        (keys_dir / "trusted").mkdir()
        (keys_dir / "private.pem").write_text("mock key")
        (keys_dir / "public.pem").write_text("mock pub")
        (keys_dir / "did_key.txt").write_text("did:key:z6MkRecoveredKey")

        guard = SimpleGuard(dev_mode=True)

        assert guard.agent_id == "did:key:z6MkRecoveredKey"
        mock_rpc_client.simpleguard.generate_key_pair.assert_not_called()

        guard.close()

    def test_dev_mode_explicit_agent_id_ignores_sidecar(self, temp_workspace, mock_rpc_client):
        """Test that explicit agent_id is not overridden by sidecar did_key.txt."""
        keys_dir = temp_workspace / "capiscio_keys"
        keys_dir.mkdir(parents=True)
        (keys_dir / "trusted").mkdir()
        (keys_dir / "private.pem").write_text("mock key")
        (keys_dir / "did_key.txt").write_text("did:key:z6MkShouldBeIgnored")

        guard = SimpleGuard(dev_mode=True, agent_id="did:web:example.com:myagent")

        assert guard.agent_id == "did:web:example.com:myagent"

        guard.close()


class TestSimpleGuardSigning:
    """Tests for SimpleGuard signing operations."""

    def test_sign_outbound_returns_token(self, temp_workspace, mock_rpc_client):
        """Test that sign_outbound returns a JWS token."""
        guard = SimpleGuard(dev_mode=True)
        
        payload = {"sub": "test-agent", "msg": "hello"}
        token = guard.sign_outbound(payload)
        
        assert token == "mock.jws.token"
        mock_rpc_client.simpleguard.sign_attached.assert_called_once()
        
        guard.close()

    def test_sign_outbound_injects_issuer(self, temp_workspace, mock_rpc_client):
        """Test that sign_outbound injects issuer if missing."""
        guard = SimpleGuard(dev_mode=True)
        
        payload = {"msg": "hello"}  # No iss
        _ = guard.sign_outbound(payload)
        
        # Should have called sign_attached with issuer in headers
        call_kwargs = mock_rpc_client.simpleguard.sign_attached.call_args
        assert "iss" in call_kwargs.kwargs.get("headers", {})
        
        guard.close()

    def test_make_headers_returns_dict(self, temp_workspace, mock_rpc_client):
        """Test that make_headers returns proper header dict (RFC-002 §9.1)."""
        guard = SimpleGuard(dev_mode=True)
        
        headers = guard.make_headers({"sub": "test"})
        
        assert "X-Capiscio-Badge" in headers
        assert headers["X-Capiscio-Badge"] == "mock.jws.token"
        
        guard.close()


class TestSimpleGuardVerification:
    """Tests for SimpleGuard verification operations."""

    def test_verify_inbound_returns_payload(self, temp_workspace, mock_rpc_client):
        """Test that verify_inbound returns the payload on success."""
        guard = SimpleGuard(dev_mode=True)
        
        result = guard.verify_inbound("some.jws.token")
        
        assert result["sub"] == "test"
        assert result["iss"] == "local-dev-agent"
        
        guard.close()

    def test_verify_inbound_raises_on_error(self, temp_workspace, mock_rpc_client):
        """Test that verify_inbound raises VerificationError on failure."""
        mock_rpc_client.simpleguard.verify_attached.return_value = (
            False, None, None, "Signature invalid"
        )
        
        guard = SimpleGuard(dev_mode=True)
        
        with pytest.raises(VerificationError, match="Signature invalid"):
            guard.verify_inbound("bad.token")
        
        guard.close()

    def test_verify_inbound_with_body(self, temp_workspace, mock_rpc_client):
        """Test that verify_inbound passes body for integrity check."""
        guard = SimpleGuard(dev_mode=True)
        
        body = b'{"data": "test"}'
        guard.verify_inbound("token", body=body)
        
        # Verify body was passed to RPC
        call_kwargs = mock_rpc_client.simpleguard.verify_attached.call_args
        assert call_kwargs.kwargs.get("body") == body
        
        guard.close()


class TestSimpleGuardContextManager:
    """Tests for SimpleGuard context manager protocol."""

    def test_context_manager_closes_connection(self, temp_workspace, mock_rpc_client):
        """Test that context manager properly closes connection."""
        with SimpleGuard(dev_mode=True) as guard:
            assert guard is not None
        
        mock_rpc_client.close.assert_called_once()


class TestSimpleGuardProductionSafety:
    """Tests for production safety checks."""

    def test_dev_mode_warning_in_production(self, temp_workspace, mock_rpc_client, caplog):
        """Test that dev_mode=True in production environment logs critical warning."""
        with patch.dict(os.environ, {"CAPISCIO_ENV": "prod"}):
            import logging
            with caplog.at_level(logging.CRITICAL):
                guard = SimpleGuard(dev_mode=True)
                
                assert "CRITICAL" in caplog.text or "dev_mode=True" in caplog.text
                
                guard.close()
