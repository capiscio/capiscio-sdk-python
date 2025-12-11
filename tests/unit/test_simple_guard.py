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

    def test_dev_mode_creates_agent_card(self, temp_workspace, mock_rpc_client):
        """Test that dev_mode creates agent-card.json."""
        guard = SimpleGuard(dev_mode=True)
        
        assert (temp_workspace / "agent-card.json").exists()
        
        card = json.loads((temp_workspace / "agent-card.json").read_text())
        assert "agent_id" in card
        assert "public_keys" in card
        
        guard.close()

    def test_production_mode_requires_config(self, temp_workspace, mock_rpc_client):
        """Test that production mode fails without existing config."""
        with pytest.raises(ConfigurationError):
            SimpleGuard(dev_mode=False)

    def test_production_mode_with_existing_card(self, temp_workspace, mock_rpc_client):
        """Test that production mode works with existing config."""
        # Create agent-card.json
        card = {
            "agent_id": "my-agent",
            "public_keys": [{"kid": "my-key", "kty": "OKP", "crv": "Ed25519"}],
        }
        (temp_workspace / "agent-card.json").write_text(json.dumps(card))
        
        # Create keys directory
        keys_dir = temp_workspace / "capiscio_keys"
        keys_dir.mkdir()
        (keys_dir / "private.pem").write_text("mock key")
        
        guard = SimpleGuard(dev_mode=False)
        assert guard.agent_id == "my-agent"
        
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
