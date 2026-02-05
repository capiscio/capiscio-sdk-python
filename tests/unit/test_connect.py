"""Unit tests for capiscio_sdk.connect module."""

import os
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from capiscio_sdk.connect import (
    AgentIdentity,
    CapiscIO,
    _Connector,
    ConfigurationError,
    DEFAULT_CONFIG_DIR,
    DEFAULT_KEYS_DIR,
    PROD_REGISTRY,
)


class TestAgentIdentity:
    """Tests for AgentIdentity dataclass."""

    def test_init_basic(self):
        """Test basic initialization."""
        identity = AgentIdentity(
            agent_id="test-agent-123",
            did="did:key:z6MkTest",
            name="Test Agent",
            api_key="sk_test_abc",
            server_url="https://registry.capisc.io",
            keys_dir=Path("/tmp/keys"),
        )
        
        assert identity.agent_id == "test-agent-123"
        assert identity.did == "did:key:z6MkTest"
        assert identity.name == "Test Agent"
        assert identity.api_key == "sk_test_abc"
        assert identity.server_url == "https://registry.capisc.io"
        assert identity.keys_dir == Path("/tmp/keys")
        assert identity.badge is None
        assert identity.badge_expires_at is None

    def test_init_with_badge(self):
        """Test initialization with badge."""
        identity = AgentIdentity(
            agent_id="test-agent-123",
            did="did:key:z6MkTest",
            name="Test Agent",
            api_key="sk_test_abc",
            server_url="https://registry.capisc.io",
            keys_dir=Path("/tmp/keys"),
            badge="eyJhbGciOiJFZERTQSJ9...",
            badge_expires_at="2026-02-06T12:00:00Z",
        )
        
        assert identity.badge == "eyJhbGciOiJFZERTQSJ9..."
        assert identity.badge_expires_at == "2026-02-06T12:00:00Z"

    def test_emit_creates_emitter(self):
        """Test that emit creates EventEmitter on first call."""
        identity = AgentIdentity(
            agent_id="test-agent-123",
            did="did:key:z6MkTest",
            name="Test Agent",
            api_key="sk_test_abc",
            server_url="https://registry.capisc.io",
            keys_dir=Path("/tmp/keys"),
        )
        
        assert identity._emitter is None
        
        with patch("capiscio_sdk.events.EventEmitter") as MockEmitter:
            mock_instance = MagicMock()
            mock_instance.emit.return_value = True
            MockEmitter.return_value = mock_instance
            
            result = identity.emit("test_event", {"key": "value"})
            
            MockEmitter.assert_called_once_with(
                server_url="https://registry.capisc.io",
                api_key="sk_test_abc",
                agent_id="test-agent-123",
            )
            mock_instance.emit.assert_called_once_with("test_event", {"key": "value"})
            assert result is True

    def test_emit_reuses_emitter(self):
        """Test that emit reuses existing EventEmitter."""
        identity = AgentIdentity(
            agent_id="test-agent-123",
            did="did:key:z6MkTest",
            name="Test Agent",
            api_key="sk_test_abc",
            server_url="https://registry.capisc.io",
            keys_dir=Path("/tmp/keys"),
        )
        
        mock_emitter = MagicMock()
        mock_emitter.emit.return_value = True
        identity._emitter = mock_emitter
        
        identity.emit("event1", {})
        identity.emit("event2", {})
        
        assert mock_emitter.emit.call_count == 2

    def test_get_badge_with_keeper(self):
        """Test get_badge delegates to keeper."""
        identity = AgentIdentity(
            agent_id="test-agent-123",
            did="did:key:z6MkTest",
            name="Test Agent",
            api_key="sk_test_abc",
            server_url="https://registry.capisc.io",
            keys_dir=Path("/tmp/keys"),
            badge="old-badge",
        )
        
        mock_keeper = MagicMock()
        mock_keeper.get_current_badge.return_value = "new-badge-from-keeper"
        identity._keeper = mock_keeper
        
        result = identity.get_badge()
        
        mock_keeper.get_current_badge.assert_called_once()
        assert result == "new-badge-from-keeper"

    def test_get_badge_without_keeper(self):
        """Test get_badge returns stored badge when no keeper."""
        identity = AgentIdentity(
            agent_id="test-agent-123",
            did="did:key:z6MkTest",
            name="Test Agent",
            api_key="sk_test_abc",
            server_url="https://registry.capisc.io",
            keys_dir=Path("/tmp/keys"),
            badge="stored-badge",
        )
        
        result = identity.get_badge()
        
        assert result == "stored-badge"

    def test_status(self):
        """Test status returns correct dict."""
        identity = AgentIdentity(
            agent_id="test-agent-123",
            did="did:key:z6MkTest",
            name="Test Agent",
            api_key="sk_test_abc",
            server_url="https://registry.capisc.io",
            keys_dir=Path("/tmp/keys"),
            badge="test-badge",
            badge_expires_at="2026-02-06T12:00:00Z",
        )
        
        status = identity.status()
        
        assert status == {
            "agent_id": "test-agent-123",
            "did": "did:key:z6MkTest",
            "name": "Test Agent",
            "server": "https://registry.capisc.io",
            "badge_valid": True,
            "badge_expires_at": "2026-02-06T12:00:00Z",
        }

    def test_status_no_badge(self):
        """Test status with no badge."""
        identity = AgentIdentity(
            agent_id="test-agent-123",
            did="did:key:z6MkTest",
            name="Test Agent",
            api_key="sk_test_abc",
            server_url="https://registry.capisc.io",
            keys_dir=Path("/tmp/keys"),
        )
        
        status = identity.status()
        
        assert status["badge_valid"] is False
        assert status["badge_expires_at"] is None


class TestCapiscIOConnect:
    """Tests for CapiscIO.connect() class method."""

    def test_connect_calls_connector(self):
        """Test that connect creates and runs _Connector."""
        # Patch the _Connector class where it's defined in the module
        with patch.object(_Connector, "__init__", return_value=None) as mock_init:
            with patch.object(_Connector, "connect") as mock_connect:
                mock_identity = AgentIdentity(
                    agent_id="test-123",
                    did="did:key:z6MkTest",
                    name="Test",
                    api_key="sk_test_abc",
                    server_url=PROD_REGISTRY,
                    keys_dir=Path("/tmp/keys"),
                )
                mock_connect.return_value = mock_identity
                
                result = CapiscIO.connect(
                    api_key="sk_test_abc",
                    name="Test Agent",
                    server_url="https://custom.server.com",
                )
                
                mock_init.assert_called_once_with(
                    api_key="sk_test_abc",
                    name="Test Agent",
                    agent_id=None,
                    server_url="https://custom.server.com",
                    keys_dir=None,
                    auto_badge=True,
                    dev_mode=False,
                )
                mock_connect.assert_called_once()
                assert result == mock_identity


class TestCapiscIOFromEnv:
    """Tests for CapiscIO.from_env() class method."""

    def test_from_env_requires_api_key(self):
        """Test that from_env raises without CAPISCIO_API_KEY."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove the key if it exists
            os.environ.pop("CAPISCIO_API_KEY", None)
            
            with pytest.raises(ValueError, match="CAPISCIO_API_KEY environment variable is required"):
                CapiscIO.from_env()

    def test_from_env_reads_env_vars(self):
        """Test that from_env reads all environment variables."""
        env_vars = {
            "CAPISCIO_API_KEY": "sk_test_env",
            "CAPISCIO_AGENT_ID": "env-agent-id",
            "CAPISCIO_AGENT_NAME": "Env Agent",
            "CAPISCIO_SERVER_URL": "https://env.server.com",
            "CAPISCIO_DEV_MODE": "true",
        }
        
        with patch.dict(os.environ, env_vars, clear=False):
            with patch.object(CapiscIO, "connect") as mock_connect:
                mock_connect.return_value = MagicMock()
                
                CapiscIO.from_env()
                
                mock_connect.assert_called_once_with(
                    api_key="sk_test_env",
                    agent_id="env-agent-id",
                    name="Env Agent",
                    server_url="https://env.server.com",
                    dev_mode=True,
                )

    def test_from_env_defaults(self):
        """Test from_env uses defaults for missing optional vars."""
        with patch.dict(os.environ, {"CAPISCIO_API_KEY": "sk_test_only"}, clear=False):
            # Clear optional vars
            for var in ["CAPISCIO_AGENT_ID", "CAPISCIO_AGENT_NAME", "CAPISCIO_SERVER_URL", "CAPISCIO_DEV_MODE"]:
                os.environ.pop(var, None)
            
            with patch.object(CapiscIO, "connect") as mock_connect:
                mock_connect.return_value = MagicMock()
                
                CapiscIO.from_env()
                
                mock_connect.assert_called_once_with(
                    api_key="sk_test_only",
                    agent_id=None,
                    name=None,
                    server_url=PROD_REGISTRY,
                    dev_mode=False,
                )

    @pytest.mark.parametrize("dev_mode_value,expected", [
        ("true", True),
        ("True", True),
        ("TRUE", True),
        ("1", True),
        ("yes", True),
        ("Yes", True),
        ("false", False),
        ("0", False),
        ("no", False),
        ("", False),
    ])
    def test_from_env_dev_mode_parsing(self, dev_mode_value, expected):
        """Test dev_mode parsing from various string values."""
        with patch.dict(os.environ, {
            "CAPISCIO_API_KEY": "sk_test",
            "CAPISCIO_DEV_MODE": dev_mode_value,
        }, clear=False):
            with patch.object(CapiscIO, "connect") as mock_connect:
                mock_connect.return_value = MagicMock()
                
                CapiscIO.from_env()
                
                call_kwargs = mock_connect.call_args[1]
                assert call_kwargs["dev_mode"] == expected


class TestConnector:
    """Tests for _Connector internal class."""

    def test_init(self):
        """Test _Connector initialization."""
        connector = _Connector(
            api_key="sk_test_abc",
            name="Test Agent",
            agent_id="test-123",
            server_url="https://test.server.com",
            keys_dir=Path("/custom/keys"),
            auto_badge=True,
            dev_mode=False,
        )
        
        assert connector.api_key == "sk_test_abc"
        assert connector.name == "Test Agent"
        assert connector.agent_id == "test-123"
        assert connector.server_url == "https://test.server.com"
        assert connector.keys_dir == Path("/custom/keys")
        assert connector.auto_badge is True
        assert connector.dev_mode is False

    def test_init_strips_trailing_slash(self):
        """Test that server_url trailing slash is stripped."""
        connector = _Connector(
            api_key="sk_test",
            name=None,
            agent_id=None,
            server_url="https://test.server.com/",
            keys_dir=None,
            auto_badge=True,
            dev_mode=False,
        )
        
        assert connector.server_url == "https://test.server.com"

    def test_ensure_agent_with_agent_id(self):
        """Test _ensure_agent fetches specific agent."""
        connector = _Connector(
            api_key="sk_test",
            name=None,
            agent_id="specific-agent-id",
            server_url="https://test.server.com",
            keys_dir=None,
            auto_badge=True,
            dev_mode=False,
        )
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"id": "specific-agent-id", "name": "My Agent"}}
        connector._client.get = MagicMock(return_value=mock_response)
        
        result = connector._ensure_agent()
        
        connector._client.get.assert_called_once_with("/v1/agents/specific-agent-id")
        assert result == {"id": "specific-agent-id", "name": "My Agent"}

    def test_ensure_agent_not_found(self):
        """Test _ensure_agent raises on 404."""
        connector = _Connector(
            api_key="sk_test",
            name=None,
            agent_id="missing-agent",
            server_url="https://test.server.com",
            keys_dir=None,
            auto_badge=True,
            dev_mode=False,
        )
        
        mock_response = MagicMock()
        mock_response.status_code = 404
        connector._client.get = MagicMock(return_value=mock_response)
        
        with pytest.raises(ValueError, match="Agent missing-agent not found"):
            connector._ensure_agent()

    def test_ensure_agent_lists_and_finds_by_name(self):
        """Test _ensure_agent finds agent by name."""
        connector = _Connector(
            api_key="sk_test",
            name="Target Agent",
            agent_id=None,
            server_url="https://test.server.com",
            keys_dir=None,
            auto_badge=True,
            dev_mode=False,
        )
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {"id": "agent-1", "name": "Other Agent"},
                {"id": "agent-2", "name": "Target Agent"},
            ]
        }
        connector._client.get = MagicMock(return_value=mock_response)
        
        result = connector._ensure_agent()
        
        assert result == {"id": "agent-2", "name": "Target Agent"}

    def test_ensure_agent_uses_first_when_no_name(self):
        """Test _ensure_agent uses first agent when no name specified."""
        connector = _Connector(
            api_key="sk_test",
            name=None,
            agent_id=None,
            server_url="https://test.server.com",
            keys_dir=None,
            auto_badge=True,
            dev_mode=False,
        )
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {"id": "first-agent", "name": "First"},
                {"id": "second-agent", "name": "Second"},
            ]
        }
        connector._client.get = MagicMock(return_value=mock_response)
        
        result = connector._ensure_agent()
        
        assert result == {"id": "first-agent", "name": "First"}

    def test_create_agent(self):
        """Test _create_agent creates new agent."""
        connector = _Connector(
            api_key="sk_test",
            name="New Agent",
            agent_id=None,
            server_url="https://test.server.com",
            keys_dir=None,
            auto_badge=True,
            dev_mode=False,
        )
        
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"data": {"id": "new-agent-id", "name": "New Agent"}}
        connector._client.post = MagicMock(return_value=mock_response)
        
        result = connector._create_agent()
        
        connector._client.post.assert_called_once_with("/v1/agents", json={
            "name": "New Agent",
            "protocol": "a2a",
        })
        assert result == {"id": "new-agent-id", "name": "New Agent"}

    def test_ensure_agent_fetch_error(self):
        """Test _ensure_agent raises on server error."""
        connector = _Connector(
            api_key="sk_test",
            name=None,
            agent_id="some-agent",
            server_url="https://test.server.com",
            keys_dir=None,
            auto_badge=True,
            dev_mode=False,
        )
        
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        connector._client.get = MagicMock(return_value=mock_response)
        
        with pytest.raises(RuntimeError, match="Failed to fetch agent"):
            connector._ensure_agent()

    def test_ensure_agent_list_error(self):
        """Test _ensure_agent raises when listing fails."""
        connector = _Connector(
            api_key="sk_test",
            name=None,
            agent_id=None,
            server_url="https://test.server.com",
            keys_dir=None,
            auto_badge=True,
            dev_mode=False,
        )
        
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Failed to list"
        connector._client.get = MagicMock(return_value=mock_response)
        
        with pytest.raises(RuntimeError, match="Failed to list agents"):
            connector._ensure_agent()

    def test_ensure_agent_creates_when_empty(self):
        """Test _ensure_agent creates agent when list is empty."""
        connector = _Connector(
            api_key="sk_test",
            name=None,
            agent_id=None,
            server_url="https://test.server.com",
            keys_dir=None,
            auto_badge=True,
            dev_mode=False,
        )
        
        # First call returns empty list, second call creates
        list_response = MagicMock()
        list_response.status_code = 200
        list_response.json.return_value = {"data": []}
        
        create_response = MagicMock()
        create_response.status_code = 201
        create_response.json.return_value = {"data": {"id": "new-id", "name": "New"}}
        
        connector._client.get = MagicMock(return_value=list_response)
        connector._client.post = MagicMock(return_value=create_response)
        
        result = connector._ensure_agent()
        
        assert result == {"id": "new-id", "name": "New"}
        connector._client.post.assert_called_once()

    def test_create_agent_generates_name(self):
        """Test _create_agent generates name when not provided."""
        connector = _Connector(
            api_key="sk_test",
            name=None,
            agent_id=None,
            server_url="https://test.server.com",
            keys_dir=None,
            auto_badge=True,
            dev_mode=False,
        )
        
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"data": {"id": "new-id", "name": "Agent-abc123"}}
        connector._client.post = MagicMock(return_value=mock_response)
        
        result = connector._create_agent()
        
        # Name should start with "Agent-"
        call_args = connector._client.post.call_args
        assert call_args[1]["json"]["name"].startswith("Agent-")

    def test_create_agent_failure(self):
        """Test _create_agent raises on failure."""
        connector = _Connector(
            api_key="sk_test",
            name="Test",
            agent_id=None,
            server_url="https://test.server.com",
            keys_dir=None,
            auto_badge=True,
            dev_mode=False,
        )
        
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Bad request"
        connector._client.post = MagicMock(return_value=mock_response)
        
        with pytest.raises(RuntimeError, match="Failed to create agent"):
            connector._create_agent()

    def test_connect_full_flow(self, tmp_path):
        """Test connect() executes full flow."""
        connector = _Connector(
            api_key="sk_test",
            name="Test Agent",
            agent_id=None,
            server_url="https://test.server.com",
            keys_dir=tmp_path / "keys",
            auto_badge=False,  # Skip badge setup for simplicity
            dev_mode=False,
        )
        
        # Mock _ensure_agent
        connector._ensure_agent = MagicMock(return_value={
            "id": "agent-123",
            "name": "Test Agent",
        })
        
        # Mock _init_identity  
        connector._init_identity = MagicMock(return_value="did:key:z6MkTest")
        
        result = connector.connect()
        
        assert result.agent_id == "agent-123"
        assert result.did == "did:key:z6MkTest"
        assert result.name == "Test Agent"
        assert result.keys_dir == tmp_path / "keys"
        connector._ensure_agent.assert_called_once()
        connector._init_identity.assert_called_once()

    def test_connect_with_auto_badge(self, tmp_path):
        """Test connect() sets up badge when auto_badge=True."""
        connector = _Connector(
            api_key="sk_test",
            name="Test Agent",
            agent_id=None,
            server_url="https://test.server.com",
            keys_dir=tmp_path / "keys",
            auto_badge=True,
            dev_mode=False,
        )
        
        connector._ensure_agent = MagicMock(return_value={
            "id": "agent-123",
            "name": "Test Agent",
        })
        connector._init_identity = MagicMock(return_value="did:key:z6MkTest")
        connector._setup_badge = MagicMock(return_value=(
            "badge-jwt",
            "2026-12-31T00:00:00Z",
            MagicMock(),  # keeper
            MagicMock(),  # guard
        ))
        
        result = connector.connect()
        
        assert result.badge == "badge-jwt"
        assert result.badge_expires_at == "2026-12-31T00:00:00Z"
        connector._setup_badge.assert_called_once()

    def test_connect_skips_badge_in_dev_mode(self, tmp_path):
        """Test connect() skips badge in dev_mode."""
        connector = _Connector(
            api_key="sk_test",
            name="Test Agent",
            agent_id=None,
            server_url="https://test.server.com",
            keys_dir=tmp_path / "keys",
            auto_badge=True,
            dev_mode=True,  # Dev mode should skip badge
        )
        
        connector._ensure_agent = MagicMock(return_value={
            "id": "agent-123",
            "name": "Test Agent",
        })
        connector._init_identity = MagicMock(return_value="did:key:z6MkTest")
        connector._setup_badge = MagicMock()
        
        result = connector.connect()
        
        assert result.badge is None
        connector._setup_badge.assert_not_called()

    def test_connect_generates_name_from_id(self, tmp_path):
        """Test connect() generates name from agent ID when missing."""
        connector = _Connector(
            api_key="sk_test",
            name=None,
            agent_id=None,
            server_url="https://test.server.com",
            keys_dir=tmp_path / "keys",
            auto_badge=False,
            dev_mode=False,
        )
        
        connector._ensure_agent = MagicMock(return_value={
            "id": "agent-123456789",
            "name": None,  # No name from server
        })
        connector._init_identity = MagicMock(return_value="did:key:z6MkTest")
        
        result = connector.connect()
        
        # Should generate name from first 8 chars of ID
        assert result.name == "Agent-agent-12"

    def test_init_identity_uses_existing(self, tmp_path):
        """Test _init_identity returns existing DID if files exist."""
        connector = _Connector(
            api_key="sk_test",
            name="Test",
            agent_id="agent-123",
            server_url="https://test.server.com",
            keys_dir=tmp_path,
            auto_badge=False,
            dev_mode=False,
        )
        
        # Create existing identity files
        (tmp_path / "did.txt").write_text("did:key:z6MkExisting")
        (tmp_path / "private.jwk").write_text('{"kty":"OKP"}')
        
        result = connector._init_identity()
        
        assert result == "did:key:z6MkExisting"

    def test_init_identity_calls_rpc(self, tmp_path):
        """Test _init_identity calls capiscio-core RPC."""
        from capiscio_sdk.connect import ConfigurationError
        
        connector = _Connector(
            api_key="sk_test",
            name="Test",
            agent_id="agent-123",
            server_url="https://test.server.com",
            keys_dir=tmp_path,
            auto_badge=False,
            dev_mode=False,
        )
        
        mock_rpc = MagicMock()
        mock_rpc.simpleguard.init.return_value = (
            {"did": "did:key:z6MkNew", "registered": True},
            None,
        )
        
        # Directly set _rpc_client to skip instantiation (connect.py checks if not self._rpc_client)
        connector._rpc_client = mock_rpc
        result = connector._init_identity()
        
        assert result == "did:key:z6MkNew"
        # Note: connect() not called since _rpc_client was preset
        mock_rpc.simpleguard.init.assert_called_once_with(
            api_key="sk_test",
            agent_id="agent-123",
            server_url="https://test.server.com",
            output_dir=str(tmp_path),
            force=False,
        )

    def test_init_identity_rpc_error(self, tmp_path):
        """Test _init_identity raises on RPC error."""
        from capiscio_sdk.connect import ConfigurationError
        
        connector = _Connector(
            api_key="sk_test",
            name="Test",
            agent_id="agent-123",
            server_url="https://test.server.com",
            keys_dir=tmp_path,
            auto_badge=False,
            dev_mode=False,
        )
        
        mock_rpc = MagicMock()
        mock_rpc.simpleguard.init.return_value = (None, "RPC failed")
        
        # Directly set _rpc_client to skip instantiation (connect.py checks if not self._rpc_client)
        connector._rpc_client = mock_rpc
        with pytest.raises(ConfigurationError, match="Failed to initialize identity"):
            connector._init_identity()

    def test_setup_badge_success(self, tmp_path):
        """Test _setup_badge sets up keeper and guard."""
        connector = _Connector(
            api_key="sk_test",
            name="Test",
            agent_id="agent-123",
            server_url="https://test.server.com",
            keys_dir=tmp_path,
            auto_badge=True,
            dev_mode=False,
        )
        
        mock_keeper = MagicMock()
        mock_keeper.get_current_badge.return_value = "badge-jwt"
        mock_keeper.badge_expires_at = "2026-12-31T00:00:00Z"
        
        mock_guard = MagicMock()
        
        with patch("capiscio_sdk.badge_keeper.BadgeKeeper", return_value=mock_keeper):
            with patch("capiscio_sdk.simple_guard.SimpleGuard", return_value=mock_guard):
                badge, expires, keeper, guard = connector._setup_badge()
        
        assert badge == "badge-jwt"
        assert expires == "2026-12-31T00:00:00Z"
        assert keeper == mock_keeper
        assert guard == mock_guard
        mock_keeper.start.assert_called_once()
        mock_keeper.get_current_badge.assert_called_once()

    def test_setup_badge_failure_continues(self, tmp_path):
        """Test _setup_badge returns None on failure without raising."""
        connector = _Connector(
            api_key="sk_test",
            name="Test",
            agent_id="agent-123",
            server_url="https://test.server.com",
            keys_dir=tmp_path,
            auto_badge=True,
            dev_mode=False,
        )
        
        with patch("capiscio_sdk.badge_keeper.BadgeKeeper", side_effect=Exception("Setup failed")):
            badge, expires, keeper, guard = connector._setup_badge()
        
        assert badge is None
        assert expires is None
        assert keeper is None
        assert guard is None


class TestDefaultPaths:
    """Tests for default path constants."""

    def test_default_config_dir(self):
        """Test DEFAULT_CONFIG_DIR is in home directory."""
        assert DEFAULT_CONFIG_DIR == Path.home() / ".capiscio"

    def test_default_keys_dir(self):
        """Test DEFAULT_KEYS_DIR is under config dir."""
        assert DEFAULT_KEYS_DIR == Path.home() / ".capiscio" / "keys"

    def test_prod_registry(self):
        """Test PROD_REGISTRY constant."""
        assert PROD_REGISTRY == "https://registry.capisc.io"
