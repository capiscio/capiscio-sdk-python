"""Tests for the Trust Badge API."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from capiscio_sdk.badge import (
    BadgeClaims,
    TrustLevel,
    VerifyMode,
    VerifyOptions,
    VerifyResult,
    parse_badge,
    verify_badge,
)


def utc_now() -> datetime:
    """Get current UTC time as naive datetime for testing."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class TestTrustLevel:
    """Tests for TrustLevel enum."""

    def test_from_string_valid(self):
        """Test parsing valid trust levels."""
        assert TrustLevel.from_string("1") == TrustLevel.LEVEL_1
        assert TrustLevel.from_string("2") == TrustLevel.LEVEL_2
        assert TrustLevel.from_string("3") == TrustLevel.LEVEL_3

    def test_from_string_invalid(self):
        """Test parsing invalid trust level raises error."""
        with pytest.raises(ValueError, match="Unknown trust level"):
            TrustLevel.from_string("4")

    def test_value_property(self):
        """Test value property returns string."""
        assert TrustLevel.LEVEL_1.value == "1"
        assert TrustLevel.LEVEL_2.value == "2"
        assert TrustLevel.LEVEL_3.value == "3"


class TestVerifyMode:
    """Tests for VerifyMode enum."""

    def test_modes_exist(self):
        """Test all verification modes exist."""
        assert VerifyMode.ONLINE.value == "online"
        assert VerifyMode.OFFLINE.value == "offline"
        assert VerifyMode.HYBRID.value == "hybrid"


class TestBadgeClaims:
    """Tests for BadgeClaims dataclass."""

    def test_from_dict(self):
        """Test creating claims from dictionary."""
        data = {
            "jti": "badge-123",
            "iss": "https://registry.capisc.io",
            "sub": "did:web:registry.capisc.io:agents:my-agent",
            "iat": 1704067200,  # 2024-01-01 00:00:00 UTC
            "exp": 1735689600,  # 2025-01-01 00:00:00 UTC
            "trust_level": "2",
            "domain": "example.com",
            "agent_name": "My Agent",
            "aud": ["https://service.example.com"],
        }
        claims = BadgeClaims.from_dict(data)

        assert claims.jti == "badge-123"
        assert claims.issuer == "https://registry.capisc.io"
        assert claims.subject == "did:web:registry.capisc.io:agents:my-agent"
        assert claims.trust_level == TrustLevel.LEVEL_2
        assert claims.domain == "example.com"
        assert claims.agent_name == "My Agent"
        assert claims.audience == ["https://service.example.com"]

    def test_agent_id_extraction(self):
        """Test agent_id property extracts from DID."""
        claims = BadgeClaims(
            jti="test",
            issuer="https://registry.capisc.io",
            subject="did:web:registry.capisc.io:agents:my-agent",
            issued_at=utc_now(),
            expires_at=utc_now() + timedelta(days=365),
            trust_level=TrustLevel.LEVEL_1,
            domain="example.com",
        )
        assert claims.agent_id == "my-agent"

    def test_agent_id_invalid_format(self):
        """Test agent_id returns empty for invalid DIDs."""
        claims = BadgeClaims(
            jti="test",
            issuer="https://registry.capisc.io",
            subject="invalid-did",
            issued_at=utc_now(),
            expires_at=utc_now() + timedelta(days=365),
            trust_level=TrustLevel.LEVEL_1,
            domain="example.com",
        )
        assert claims.agent_id == ""

    def test_is_expired(self):
        """Test is_expired property."""
        # Expired badge
        expired_claims = BadgeClaims(
            jti="test",
            issuer="https://registry.capisc.io",
            subject="did:web:registry.capisc.io:agents:test",
            issued_at=utc_now() - timedelta(days=366),
            expires_at=utc_now() - timedelta(days=1),
            trust_level=TrustLevel.LEVEL_1,
            domain="example.com",
        )
        assert expired_claims.is_expired

        # Valid badge
        valid_claims = BadgeClaims(
            jti="test",
            issuer="https://registry.capisc.io",
            subject="did:web:registry.capisc.io:agents:test",
            issued_at=utc_now() - timedelta(days=1),
            expires_at=utc_now() + timedelta(days=365),
            trust_level=TrustLevel.LEVEL_1,
            domain="example.com",
        )
        assert not valid_claims.is_expired

    def test_is_not_yet_valid(self):
        """Test is_not_yet_valid property."""
        future_claims = BadgeClaims(
            jti="test",
            issuer="https://registry.capisc.io",
            subject="did:web:registry.capisc.io:agents:test",
            issued_at=utc_now() + timedelta(days=1),
            expires_at=utc_now() + timedelta(days=366),
            trust_level=TrustLevel.LEVEL_1,
            domain="example.com",
        )
        assert future_claims.is_not_yet_valid

    def test_to_dict(self):
        """Test converting claims to dictionary."""
        now = utc_now()
        later = now + timedelta(days=365)
        claims = BadgeClaims(
            jti="test-jti",
            issuer="https://registry.capisc.io",
            subject="did:web:registry.capisc.io:agents:test",
            issued_at=now,
            expires_at=later,
            trust_level=TrustLevel.LEVEL_2,
            domain="example.com",
            agent_name="Test Agent",
            audience=["https://service.example.com"],
        )
        data = claims.to_dict()

        assert data["jti"] == "test-jti"
        assert data["iss"] == "https://registry.capisc.io"
        assert data["sub"] == "did:web:registry.capisc.io:agents:test"
        assert data["trust_level"] == "2"
        assert data["domain"] == "example.com"
        assert data["agent_name"] == "Test Agent"
        assert data["aud"] == ["https://service.example.com"]


class TestVerifyOptions:
    """Tests for VerifyOptions dataclass."""

    def test_default_values(self):
        """Test default options."""
        options = VerifyOptions()
        assert options.mode == VerifyMode.ONLINE
        assert options.trusted_issuers == []
        assert options.audience is None
        assert options.skip_revocation_check is False
        assert options.skip_agent_status_check is False
        # RFC-002 v1.3 §7.5: Staleness fail-closed defaults
        assert options.fail_open is False
        assert options.stale_threshold_seconds == 300

    def test_custom_values(self):
        """Test custom options."""
        options = VerifyOptions(
            mode=VerifyMode.OFFLINE,
            trusted_issuers=["https://registry.capisc.io"],
            audience="https://my-service.example.com",
            skip_revocation_check=True,
        )
        assert options.mode == VerifyMode.OFFLINE
        assert options.trusted_issuers == ["https://registry.capisc.io"]
        assert options.audience == "https://my-service.example.com"
        assert options.skip_revocation_check is True

    def test_staleness_options(self):
        """Test RFC-002 v1.3 §7.5 staleness fail-closed options."""
        # Test fail_open mode
        options = VerifyOptions(fail_open=True)
        assert options.fail_open is True

        # Test custom stale threshold
        options = VerifyOptions(stale_threshold_seconds=60)
        assert options.stale_threshold_seconds == 60

        # Test combined staleness options
        options = VerifyOptions(
            fail_open=True,
            stale_threshold_seconds=120,
        )
        assert options.fail_open is True
        assert options.stale_threshold_seconds == 120


class TestVerifyResult:
    """Tests for VerifyResult dataclass."""

    def test_successful_result(self):
        """Test successful verification result."""
        claims = BadgeClaims(
            jti="test",
            issuer="https://registry.capisc.io",
            subject="did:web:registry.capisc.io:agents:test",
            issued_at=utc_now(),
            expires_at=utc_now() + timedelta(days=365),
            trust_level=TrustLevel.LEVEL_1,
            domain="example.com",
        )
        result = VerifyResult(valid=True, claims=claims)
        assert result.valid
        assert result.claims == claims
        assert result.error is None

    def test_failed_result(self):
        """Test failed verification result."""
        result = VerifyResult(
            valid=False,
            error="Signature invalid",
            error_code="BADGE_SIGNATURE_INVALID",
        )
        assert not result.valid
        assert result.error == "Signature invalid"
        assert result.error_code == "BADGE_SIGNATURE_INVALID"


class TestVerifyBadge:
    """Tests for verify_badge function."""

    @patch("capiscio_sdk.badge._get_client")
    def test_verify_badge_success(self, mock_get_client):
        """Test successful badge verification."""
        mock_client = MagicMock()
        # verify_badge now uses verify_badge_with_options for RFC-002 v1.3 staleness support
        mock_client.badge.verify_badge_with_options.return_value = (
            True,
            {
                "jti": "badge-123",
                "iss": "https://registry.capisc.io",
                "sub": "did:web:registry.capisc.io:agents:test",
                "iat": int(utc_now().timestamp()),
                "exp": int((utc_now() + timedelta(days=365)).timestamp()),
                "trust_level": "1",
                "domain": "example.com",
                "agent_name": "Test Agent",
                "aud": [],
            },
            [],  # warnings
            None,  # error
        )
        mock_get_client.return_value = mock_client

        result = verify_badge("test.token.here")

        assert result.valid
        assert result.claims is not None
        assert result.claims.jti == "badge-123"
        assert result.claims.agent_id == "test"

    @patch("capiscio_sdk.badge._get_client")
    def test_verify_badge_invalid_signature(self, mock_get_client):
        """Test badge verification with invalid signature."""
        mock_client = MagicMock()
        # verify_badge now uses verify_badge_with_options for RFC-002 v1.3 staleness support
        mock_client.badge.verify_badge_with_options.return_value = (
            False,
            None,
            [],  # warnings
            "BADGE_SIGNATURE_INVALID: signature verification failed",
        )
        mock_get_client.return_value = mock_client

        result = verify_badge("bad.token.here")

        assert not result.valid
        assert "BADGE_SIGNATURE_INVALID" in result.error
        assert result.error_code == "BADGE_SIGNATURE_INVALID"

    @patch("capiscio_sdk.badge._get_client")
    def test_verify_badge_untrusted_issuer(self, mock_get_client):
        """Test badge from untrusted issuer is rejected."""
        mock_client = MagicMock()
        # verify_badge now uses verify_badge_with_options for RFC-002 v1.3 staleness support
        mock_client.badge.verify_badge_with_options.return_value = (
            True,
            {
                "jti": "badge-123",
                "iss": "https://evil.example.com",  # Untrusted issuer
                "sub": "did:web:evil.example.com:agents:test",
                "iat": int(utc_now().timestamp()),
                "exp": int((utc_now() + timedelta(days=365)).timestamp()),
                "trust_level": "1",
                "domain": "evil.example.com",
                "agent_name": "Evil Agent",
                "aud": [],
            },
            [],  # warnings
            None,  # error
        )
        mock_get_client.return_value = mock_client

        result = verify_badge(
            "test.token.here",
            trusted_issuers=["https://registry.capisc.io"],  # Only trust this issuer
        )

        assert not result.valid
        assert result.error_code == "BADGE_ISSUER_UNTRUSTED"
        assert "evil.example.com" in result.error

    @patch("capiscio_sdk.badge._get_client")
    def test_verify_badge_audience_mismatch(self, mock_get_client):
        """Test badge with wrong audience is rejected."""
        mock_client = MagicMock()
        # verify_badge now uses verify_badge_with_options for RFC-002 v1.3 staleness support
        mock_client.badge.verify_badge_with_options.return_value = (
            True,
            {
                "jti": "badge-123",
                "iss": "https://registry.capisc.io",
                "sub": "did:web:registry.capisc.io:agents:test",
                "iat": int(utc_now().timestamp()),
                "exp": int((utc_now() + timedelta(days=365)).timestamp()),
                "trust_level": "1",
                "domain": "example.com",
                "agent_name": "Test Agent",
                "aud": ["https://other-service.example.com"],
            },
            [],  # warnings
            None,  # error
        )
        mock_get_client.return_value = mock_client

        result = verify_badge(
            "test.token.here",
            audience="https://my-service.example.com",
        )

        assert not result.valid
        assert result.error_code == "BADGE_AUDIENCE_MISMATCH"

    @patch("capiscio_sdk.badge._get_client")
    def test_verify_badge_connection_error(self, mock_get_client):
        """Test graceful handling of connection errors."""
        mock_get_client.side_effect = Exception("Connection refused")

        result = verify_badge("test.token.here")

        assert not result.valid
        assert "Connection refused" in result.error

    def test_verify_badge_with_options_object(self):
        """Test verify_badge accepts VerifyOptions object."""
        with patch("capiscio_sdk.badge._get_client") as mock_get_client:
            mock_client = MagicMock()
            # verify_badge now uses verify_badge_with_options for RFC-002 v1.3 staleness support
            mock_client.badge.verify_badge_with_options.return_value = (
                True,
                {
                    "jti": "badge-123",
                    "iss": "https://registry.capisc.io",
                    "sub": "did:web:registry.capisc.io:agents:test",
                    "iat": int(utc_now().timestamp()),
                    "exp": int((utc_now() + timedelta(days=365)).timestamp()),
                    "trust_level": "1",
                    "domain": "example.com",
                    "agent_name": "Test Agent",
                    "aud": [],
                },
                [],  # warnings
                None,  # error
            )
            mock_get_client.return_value = mock_client

            options = VerifyOptions(
                mode=VerifyMode.OFFLINE,
                trusted_issuers=["https://registry.capisc.io"],
            )
            result = verify_badge("test.token.here", options=options)

            assert result.valid


class TestParseBadge:
    """Tests for parse_badge function."""

    @patch("capiscio_sdk.badge._get_client")
    def test_parse_badge_success(self, mock_get_client):
        """Test successful badge parsing."""
        mock_client = MagicMock()
        mock_client.badge.parse_badge.return_value = (
            {
                "jti": "badge-123",
                "iss": "https://registry.capisc.io",
                "sub": "did:web:registry.capisc.io:agents:my-agent",
                "iat": int(utc_now().timestamp()),
                "exp": int((utc_now() + timedelta(days=365)).timestamp()),
                "trust_level": "2",
                "domain": "example.com",
                "agent_name": "My Agent",
                "aud": [],
            },
            None,
        )
        mock_get_client.return_value = mock_client

        claims = parse_badge("test.token.here")

        assert claims.jti == "badge-123"
        assert claims.agent_id == "my-agent"
        assert claims.trust_level == TrustLevel.LEVEL_2

    @patch("capiscio_sdk.badge._get_client")
    def test_parse_badge_malformed(self, mock_get_client):
        """Test parsing malformed token raises error."""
        mock_client = MagicMock()
        mock_client.badge.parse_badge.return_value = (
            None,
            "BADGE_MALFORMED: invalid token format",
        )
        mock_get_client.return_value = mock_client

        with pytest.raises(ValueError, match="BADGE_MALFORMED"):
            parse_badge("not-a-valid-token")

    @patch("capiscio_sdk.badge._get_client")
    def test_parse_badge_empty_claims(self, mock_get_client):
        """Test parsing returns empty claims raises error."""
        mock_client = MagicMock()
        mock_client.badge.parse_badge.return_value = (None, None)
        mock_get_client.return_value = mock_client

        with pytest.raises(ValueError, match="No claims returned"):
            parse_badge("test.token.here")
