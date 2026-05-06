"""Tests for SimpleGuard envelope operations (RFC-008).

These tests verify the envelope creation, derivation, and transport header
generation methods that delegate to the Go core via gRPC.
"""

import json
import os
import pytest
from unittest.mock import patch, MagicMock

from capiscio_sdk.simple_guard import SimpleGuard
from capiscio_sdk.errors import ConfigurationError


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
            None,
        )

        # Envelope operation mocks
        mock_instance.simpleguard.create_envelope.return_value = (
            "eyJhbGciOiJFZERTQSJ9.root-payload.root-sig",
            "env-001",
            "did:key:z6Mk_issuer",
            None,
        )
        mock_instance.simpleguard.derive_envelope.return_value = (
            "eyJhbGciOiJFZERTQSJ9.child-payload.child-sig",
            "env-002",
            "sha256:abc123",
            None,
        )
        mock_instance.simpleguard.build_transport_headers.return_value = (
            "eyJhbGciOiJFZERTQSJ9.child-payload.child-sig",
            "base64url-encoded-chain",
            "base64url-encoded-badge-map",
            None,
        )

        yield mock_instance


@pytest.fixture
def guard(temp_workspace, mock_rpc_client):
    """Create a SimpleGuard instance in dev_mode for testing."""
    g = SimpleGuard(dev_mode=True)
    yield g
    g.close()


class TestCreateEnvelope:
    """Tests for SimpleGuard.create_envelope()."""

    def test_basic_creation(self, guard, mock_rpc_client):
        """Test basic envelope creation with required params."""
        jws = guard.create_envelope(
            subject_did="did:key:z6Mk_subject",
            capability_class="tools.database.read",
            delegation_depth_remaining=2,
            issuer_badge_jti="badge-jti-001",
        )

        assert jws == "eyJhbGciOiJFZERTQSJ9.root-payload.root-sig"
        mock_rpc_client.simpleguard.create_envelope.assert_called_once()
        call_kwargs = mock_rpc_client.simpleguard.create_envelope.call_args[1]
        assert call_kwargs["subject_did"] == "did:key:z6Mk_subject"
        assert call_kwargs["capability_class"] == "tools.database.read"
        assert call_kwargs["delegation_depth_remaining"] == 2
        assert call_kwargs["issuer_badge_jti"] == "badge-jti-001"
        assert call_kwargs["key_id"] == "local-dev-key"

    def test_with_constraints(self, guard, mock_rpc_client):
        """Test envelope creation with constraints JSON."""
        constraints = {"max_tokens": 1000, "allowed_models": ["gpt-4"]}
        jws = guard.create_envelope(
            subject_did="did:key:z6Mk_subject",
            capability_class="tools.llm.invoke",
            constraints=constraints,
        )

        assert jws == "eyJhbGciOiJFZERTQSJ9.root-payload.root-sig"
        call_kwargs = mock_rpc_client.simpleguard.create_envelope.call_args[1]
        assert json.loads(call_kwargs["constraints_json"]) == constraints

    def test_with_enforcement_mode_min(self, guard, mock_rpc_client):
        """Test envelope creation with enforcement_mode_min field."""
        jws = guard.create_envelope(
            subject_did="did:key:z6Mk_subject",
            capability_class="tools.database.write",
            enforcement_mode_min="EM-AUDIT",
        )

        assert jws is not None
        call_kwargs = mock_rpc_client.simpleguard.create_envelope.call_args[1]
        assert call_kwargs["enforcement_mode_min"] == "EM-AUDIT"

    def test_without_constraints_sends_empty_string(self, guard, mock_rpc_client):
        """Test that no constraints results in empty string (not 'null')."""
        guard.create_envelope(
            subject_did="did:key:z6Mk_subject",
            capability_class="tools.database.read",
        )

        call_kwargs = mock_rpc_client.simpleguard.create_envelope.call_args[1]
        assert call_kwargs["constraints_json"] == ""

    def test_error_raises_configuration_error(self, guard, mock_rpc_client):
        """Test that gRPC errors are raised as ConfigurationError."""
        mock_rpc_client.simpleguard.create_envelope.return_value = (
            "", "", "", "key not found: test-key"
        )

        with pytest.raises(ConfigurationError, match="key not found"):
            guard.create_envelope(
                subject_did="did:key:z6Mk_subject",
                capability_class="tools.database.read",
            )

    def test_custom_expiry(self, guard, mock_rpc_client):
        """Test custom expiry time."""
        guard.create_envelope(
            subject_did="did:key:z6Mk_subject",
            capability_class="tools.database.read",
            expires_in_seconds=7200,
        )

        call_kwargs = mock_rpc_client.simpleguard.create_envelope.call_args[1]
        assert call_kwargs["expires_in_seconds"] == 7200


class TestDeriveEnvelope:
    """Tests for SimpleGuard.derive_envelope()."""

    def test_basic_derivation(self, guard, mock_rpc_client):
        """Test basic child envelope derivation."""
        parent_jws = "eyJhbGciOiJFZERTQSJ9.parent-payload.parent-sig"
        jws = guard.derive_envelope(
            parent_envelope_jws=parent_jws,
            subject_did="did:key:z6Mk_grandchild",
            capability_class="tools.database.read",
            delegation_depth_remaining=0,
            issuer_badge_jti="child-badge-jti",
        )

        assert jws == "eyJhbGciOiJFZERTQSJ9.child-payload.child-sig"
        call_kwargs = mock_rpc_client.simpleguard.derive_envelope.call_args[1]
        assert call_kwargs["parent_envelope_jws"] == parent_jws
        assert call_kwargs["subject_did"] == "did:key:z6Mk_grandchild"
        assert call_kwargs["delegation_depth_remaining"] == 0
        assert call_kwargs["key_id"] == "local-dev-key"

    def test_narrowing_violation_error(self, guard, mock_rpc_client):
        """Test that narrowing violations from gRPC are propagated."""
        mock_rpc_client.simpleguard.derive_envelope.return_value = (
            "", "", "", "ENVELOPE_NARROWING_VIOLATION: capability tools.admin exceeds parent"
        )

        with pytest.raises(ConfigurationError, match="NARROWING_VIOLATION"):
            guard.derive_envelope(
                parent_envelope_jws="eyJ.parent.sig",
                subject_did="did:key:z6Mk_sub",
                capability_class="tools.admin",
            )

    def test_with_constraints(self, guard, mock_rpc_client):
        """Test derivation with constraints (must be narrower than parent)."""
        constraints = {"region": "eu-west-1"}
        guard.derive_envelope(
            parent_envelope_jws="eyJ.parent.sig",
            subject_did="did:key:z6Mk_sub",
            capability_class="tools.database.read",
            constraints=constraints,
        )

        call_kwargs = mock_rpc_client.simpleguard.derive_envelope.call_args[1]
        assert json.loads(call_kwargs["constraints_json"]) == constraints

    def test_enforcement_mode_inheritance(self, guard, mock_rpc_client):
        """Test enforcement_mode_min passes through for inheritance check."""
        guard.derive_envelope(
            parent_envelope_jws="eyJ.parent.sig",
            subject_did="did:key:z6Mk_sub",
            capability_class="tools.database.read",
            enforcement_mode_min="EM-ENFORCE",
        )

        call_kwargs = mock_rpc_client.simpleguard.derive_envelope.call_args[1]
        assert call_kwargs["enforcement_mode_min"] == "EM-ENFORCE"


class TestMakeDelegationHeaders:
    """Tests for SimpleGuard.make_delegation_headers()."""

    def test_basic_headers(self, guard, mock_rpc_client):
        """Test delegation header generation with single envelope chain."""
        chain = ["eyJ.root.sig"]
        headers = guard.make_delegation_headers(chain=chain)

        assert "X-Capiscio-Authority" in headers
        assert "X-Capiscio-Authority-Chain" in headers
        assert "X-Capiscio-Badge" in headers  # from make_headers()
        mock_rpc_client.simpleguard.build_transport_headers.assert_called_once()

    def test_with_badge_map(self, guard, mock_rpc_client):
        """Test delegation headers with badge map for intermediaries."""
        chain = ["eyJ.root.sig", "eyJ.child.sig"]
        badge_map = {"did:key:z6Mk_intermediary": "eyJ.badge.sig"}
        headers = guard.make_delegation_headers(chain=chain, badge_map=badge_map)

        assert "X-Capiscio-Badge-Map" in headers
        call_args = mock_rpc_client.simpleguard.build_transport_headers.call_args
        assert call_args[0][0] == chain  # positional arg 0
        assert call_args[0][1] == badge_map  # positional arg 1

    def test_error_raises_configuration_error(self, guard, mock_rpc_client):
        """Test that transport header errors are propagated."""
        mock_rpc_client.simpleguard.build_transport_headers.return_value = (
            "", "", "", "chain is empty"
        )

        with pytest.raises(ConfigurationError, match="chain is empty"):
            guard.make_delegation_headers(chain=[])

    def test_empty_badge_map_omits_header(self, guard, mock_rpc_client):
        """Test that empty badge_map_header omits X-Capiscio-Badge-Map."""
        mock_rpc_client.simpleguard.build_transport_headers.return_value = (
            "eyJ.leaf.sig",
            "base64url-chain",
            "",  # empty badge map header
            None,
        )

        headers = guard.make_delegation_headers(chain=["eyJ.root.sig"])

        # Empty badge_map_header means the header is not added (truthy check)
        assert "X-Capiscio-Badge-Map" not in headers
