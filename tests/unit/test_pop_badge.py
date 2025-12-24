"""Unit tests for PoP badge request functionality (RFC-003)."""

import json
import pytest
from unittest.mock import patch, MagicMock

from capiscio_sdk.badge import request_pop_badge_sync, request_pop_badge


class TestRequestPoPBadge:
    """Test suite for RFC-003 PoP badge request."""

    @pytest.fixture
    def mock_private_key_jwk(self):
        """Create a mock private key in JWK format."""
        return json.dumps({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
        })

    @pytest.fixture
    def mock_rpc_client(self):
        """Create a mock RPC client."""
        with patch('capiscio_sdk.badge._get_client') as mock_get_client:
            mock_client = MagicMock()
            mock_badge_service = MagicMock()
            mock_client.badge = mock_badge_service
            mock_get_client.return_value = mock_client
            yield mock_badge_service

    def test_request_pop_badge_sync_success(self, mock_rpc_client, mock_private_key_jwk):
        """Test successful PoP badge request."""
        # Setup mock response
        mock_rpc_client.request_pop_badge.return_value = (
            True,
            {
                "token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
                "jti": "550e8400-e29b-41d4-a716-446655440000",
                "subject": "did:web:registry.capisc.io:agents:test-agent",
                "trust_level": "2",
                "assurance_level": "IAL-1",
                "expires_at": 1735000000,
                "cnf": {"kid": "did:web:registry.capisc.io:agents:test-agent#key-1"}
            },
            None
        )

        # Execute
        token = request_pop_badge_sync(
            agent_did="did:web:registry.capisc.io:agents:test-agent",
            private_key_jwk=mock_private_key_jwk,
            api_key="sk_test_abc123",
        )

        # Verify
        assert token == "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9..."
        mock_rpc_client.request_pop_badge.assert_called_once_with(
            agent_did="did:web:registry.capisc.io:agents:test-agent",
            private_key_jwk=mock_private_key_jwk,
            api_key="sk_test_abc123",
            ca_url="https://registry.capisc.io",
            ttl_seconds=300,
            audience=None,
        )

    def test_request_pop_badge_sync_with_custom_params(self, mock_rpc_client, mock_private_key_jwk):
        """Test PoP badge request with custom parameters."""
        mock_rpc_client.request_pop_badge.return_value = (
            True,
            {
                "token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
                "jti": "550e8400-e29b-41d4-a716-446655440000",
                "subject": "did:web:registry.capisc.io:agents:test-agent",
                "trust_level": "2",
                "assurance_level": "IAL-1",
                "expires_at": 1735000600,
                "cnf": {"kid": "did:web:registry.capisc.io:agents:test-agent#key-1"}
            },
            None
        )

        # Execute with custom parameters
        token = request_pop_badge_sync(
            agent_did="did:web:registry.capisc.io:agents:test-agent",
            private_key_jwk=mock_private_key_jwk,
            ca_url="https://staging.capisc.io",
            api_key="sk_test_xyz789",
            ttl_seconds=600,
            audience=["https://api.example.com"],
        )

        # Verify
        assert token == "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9..."
        mock_rpc_client.request_pop_badge.assert_called_once_with(
            agent_did="did:web:registry.capisc.io:agents:test-agent",
            private_key_jwk=mock_private_key_jwk,
            api_key="sk_test_xyz789",
            ca_url="https://staging.capisc.io",
            ttl_seconds=600,
            audience=["https://api.example.com"],
        )

    def test_request_pop_badge_sync_failure(self, mock_rpc_client, mock_private_key_jwk):
        """Test PoP badge request failure handling."""
        # Setup mock error response
        mock_rpc_client.request_pop_badge.return_value = (
            False,
            None,
            "CHALLENGE_EXPIRED: Challenge has expired"
        )

        # Execute and verify error
        with pytest.raises(ValueError, match="PoP badge request failed: CHALLENGE_EXPIRED"):
            request_pop_badge_sync(
                agent_did="did:web:registry.capisc.io:agents:test-agent",
                private_key_jwk=mock_private_key_jwk,
                api_key="sk_test_abc123",
            )

    def test_request_pop_badge_sync_missing_token(self, mock_rpc_client, mock_private_key_jwk):
        """Test PoP badge request with missing token in response."""
        # Setup mock response without token
        mock_rpc_client.request_pop_badge.return_value = (
            True,
            {
                "jti": "550e8400-e29b-41d4-a716-446655440000",
                "subject": "did:web:registry.capisc.io:agents:test-agent",
            },
            None
        )

        # Execute and verify error
        with pytest.raises(ValueError, match="CA response missing token"):
            request_pop_badge_sync(
                agent_did="did:web:registry.capisc.io:agents:test-agent",
                private_key_jwk=mock_private_key_jwk,
                api_key="sk_test_abc123",
            )

    def test_request_pop_badge_sync_did_key(self, mock_rpc_client, mock_private_key_jwk):
        """Test PoP badge request with did:key identifier."""
        mock_rpc_client.request_pop_badge.return_value = (
            True,
            {
                "token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
                "jti": "550e8400-e29b-41d4-a716-446655440000",
                "subject": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                "trust_level": "0",
                "assurance_level": "IAL-1",
                "expires_at": 1735000000,
                "cnf": {
                    "kid": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
                }
            },
            None
        )

        # Execute with did:key
        token = request_pop_badge_sync(
            agent_did="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            private_key_jwk=mock_private_key_jwk,
            api_key="sk_test_abc123",
        )

        # Verify
        assert token == "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9..."
        call_args = mock_rpc_client.request_pop_badge.call_args
        assert "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" in call_args[1].values()

    @pytest.mark.asyncio
    async def test_request_pop_badge_async(self, mock_rpc_client, mock_private_key_jwk):
        """Test async wrapper for PoP badge request."""
        mock_rpc_client.request_pop_badge.return_value = (
            True,
            {
                "token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
                "jti": "550e8400-e29b-41d4-a716-446655440000",
                "subject": "did:web:registry.capisc.io:agents:test-agent",
                "trust_level": "2",
                "assurance_level": "IAL-1",
                "expires_at": 1735000000,
                "cnf": {"kid": "did:web:registry.capisc.io:agents:test-agent#key-1"}
            },
            None
        )

        # Execute async version
        token = await request_pop_badge(
            agent_did="did:web:registry.capisc.io:agents:test-agent",
            private_key_jwk=mock_private_key_jwk,
            api_key="sk_test_abc123",
        )

        # Verify
        assert token == "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9..."

    def test_request_pop_badge_error_codes(self, mock_rpc_client, mock_private_key_jwk):
        """Test various RFC-003 error codes."""
        error_cases = [
            ("INVALID_PROOF", "Proof signature verification failed"),
            ("PROOF_EXPIRED", "Proof has expired"),
            ("CHALLENGE_NOT_FOUND", "Challenge does not exist"),
            ("CHALLENGE_USED", "Challenge already used"),
            ("DID_RESOLUTION_FAILED", "Failed to resolve DID document"),
        ]

        for error_code, error_message in error_cases:
            mock_rpc_client.request_pop_badge.return_value = (
                False,
                None,
                f"{error_code}: {error_message}"
            )

            with pytest.raises(ValueError, match=error_code):
                request_pop_badge_sync(
                    agent_did="did:web:registry.capisc.io:agents:test-agent",
                    private_key_jwk=mock_private_key_jwk,
                    api_key="sk_test_abc123",
                )


class TestPoPBadgeIntegration:
    """Integration-style tests for PoP badge functionality."""

    @pytest.fixture
    def mock_private_key_jwk(self):
        """Mock Ed25519 private key in JWK format."""
        return json.dumps({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
        })

    def test_pop_badge_response_structure(self, mock_private_key_jwk):
        """Verify the structure of a successful PoP badge response."""
        with patch('capiscio_sdk.badge._get_client') as mock_get_client:
            mock_client = MagicMock()
            mock_badge_service = MagicMock()
            mock_client.badge = mock_badge_service
            mock_get_client.return_value = mock_client

            # Full response with all RFC-003 fields
            mock_badge_service.request_pop_badge.return_value = (
                True,
                {
                    "token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJpc3MiOiJodHRwczovL3JlZ2lzdHJ5LmNhcGlzYy5pbyIsInN1YiI6ImRpZDp3ZWI6cmVnaXN0cnkuY2FwaXNjLmlvOmFnZW50czp0ZXN0LWFnZW50IiwiaWF0IjoxNzM1MDAwMDAwLCJleHAiOjE3MzUwMDAzMDAsImlhbCI6IjEiLCJjbmYiOnsia2lkIjoiZGlkOndlYjpyZWdpc3RyeS5jYXBpc2MuaW86YWdlbnRzOnRlc3QtYWdlbnQja2V5LTEifSwidmMiOnsiY3JlZGVudGlhbFN1YmplY3QiOnsiZG9tYWluIjoidGVzdC1hZ2VudC5leGFtcGxlLmNvbSIsImxldmVsIjoiMiJ9fX0.signature",
                    "jti": "550e8400-e29b-41d4-a716-446655440000",
                    "subject": "did:web:registry.capisc.io:agents:test-agent",
                    "trust_level": "2",
                    "assurance_level": "IAL-1",
                    "expires_at": 1735000300,
                    "cnf": {
                        "kid": "did:web:registry.capisc.io:agents:test-agent#key-1"
                    }
                },
                None
            )

            token = request_pop_badge_sync(
                agent_did="did:web:registry.capisc.io:agents:test-agent",
                private_key_jwk=mock_private_key_jwk,
                api_key="sk_test_abc123",
            )

            # Verify token is returned and appears valid (3 parts)
            assert token
            assert len(token.split('.')) == 3

    def test_pop_badge_idempotency(self, mock_private_key_jwk):
        """Test that multiple PoP badge requests can be made."""
        with patch('capiscio_sdk.badge._get_client') as mock_get_client:
            mock_client = MagicMock()
            mock_badge_service = MagicMock()
            mock_client.badge = mock_badge_service
            mock_get_client.return_value = mock_client

            # Mock different JTIs for each request
            mock_badge_service.request_pop_badge.side_effect = [
                (True, {"token": "token1", "jti": "jti1", "subject": "did:web:...", "trust_level": "2", "assurance_level": "IAL-1", "expires_at": 1735000000, "cnf": {}}, None),
                (True, {"token": "token2", "jti": "jti2", "subject": "did:web:...", "trust_level": "2", "assurance_level": "IAL-1", "expires_at": 1735000000, "cnf": {}}, None),
            ]

            # Make two requests
            token1 = request_pop_badge_sync(
                agent_did="did:web:registry.capisc.io:agents:test-agent",
                private_key_jwk=mock_private_key_jwk,
                api_key="sk_test_abc123",
            )

            token2 = request_pop_badge_sync(
                agent_did="did:web:registry.capisc.io:agents:test-agent",
                private_key_jwk=mock_private_key_jwk,
                api_key="sk_test_abc123",
            )

            # Each request should get a unique token
            assert token1 == "token1"
            assert token2 == "token2"
            assert mock_badge_service.request_pop_badge.call_count == 2
