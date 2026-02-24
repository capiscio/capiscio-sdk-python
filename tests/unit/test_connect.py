"""Unit tests for capiscio_sdk.connect module."""

import os
import pytest
import httpx
from pathlib import Path
from unittest.mock import MagicMock, patch

import capiscio_sdk.connect as connect_module
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
                    domain=None,
                    agent_card=None,
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
        
        connector._client.get.assert_called_once_with("/v1/sdk/agents/specific-agent-id")
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
        connector._find_agent_from_local_keys = MagicMock(return_value=None)
        
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
        connector._find_agent_from_local_keys = MagicMock(return_value=None)
        
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
        
        connector._client.post.assert_called_once_with("/v1/sdk/agents", json={
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

    def test_ensure_agent_creates_when_name_not_found(self):
        """Test _ensure_agent creates agent when name specified but not found.
        
        This is the key "Let's Encrypt" behavior: if the user specifies a name
        and no agent with that name exists, we create one with that name.
        """
        connector = _Connector(
            api_key="sk_test",
            name="my-new-agent",  # Specified name
            agent_id=None,
            server_url="https://test.server.com",
            keys_dir=None,
            auto_badge=True,
            dev_mode=False,
        )
        
        # Agents exist but none match the specified name
        list_response = MagicMock()
        list_response.status_code = 200
        list_response.json.return_value = {
            "data": [
                {"id": "agent-1", "name": "other-agent"},
                {"id": "agent-2", "name": "another-agent"},
            ]
        }
        
        create_response = MagicMock()
        create_response.status_code = 201
        create_response.json.return_value = {"data": {"id": "new-id", "name": "my-new-agent"}}
        
        connector._client.get = MagicMock(return_value=list_response)
        connector._client.post = MagicMock(return_value=create_response)
        connector._find_agent_from_local_keys = MagicMock(return_value=None)
        
        result = connector._ensure_agent()
        
        # Should create new agent, NOT return agents[0]
        assert result == {"id": "new-id", "name": "my-new-agent"}
        connector._client.post.assert_called_once()
        # Verify the name was passed to create
        call_args = connector._client.post.call_args
        assert call_args[1]["json"]["name"] == "my-new-agent"

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

    def test_ensure_agent_network_error(self):
        """Test _ensure_agent handles network errors gracefully."""
        connector = _Connector(
            api_key="sk_test",
            name=None,
            agent_id="some-agent",
            server_url="https://test.server.com",
            keys_dir=None,
            auto_badge=True,
            dev_mode=False,
        )
        
        connector._client.get = MagicMock(side_effect=httpx.ConnectError("Connection refused"))
        
        with pytest.raises(RuntimeError, match="Network error connecting to server"):
            connector._ensure_agent()

    def test_create_agent_network_error(self):
        """Test _create_agent handles network errors gracefully."""
        connector = _Connector(
            api_key="sk_test",
            name="Test",
            agent_id=None,
            server_url="https://test.server.com",
            keys_dir=None,
            auto_badge=True,
            dev_mode=False,
        )
        
        connector._client.post = MagicMock(side_effect=httpx.TimeoutException("Timeout"))
        
        with pytest.raises(RuntimeError, match="Network error creating agent"):
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
        # User-provided keys_dir is preserved for backward compatibility
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
        
        # Create existing identity files (public.jwk has kid field with DID)
        (tmp_path / "private.jwk").write_text('{"kty":"OKP","crv":"Ed25519"}')
        (tmp_path / "public.jwk").write_text('{"kty":"OKP","crv":"Ed25519","kid":"did:key:z6MkExisting"}')
        
        # Mock _ensure_did_registered to return None (server DID matches local)
        connector._ensure_did_registered = MagicMock(return_value=None)
        
        result = connector._init_identity()
        
        assert result == "did:key:z6MkExisting"

    def test_init_identity_calls_rpc(self, tmp_path):
        """Test _init_identity calls capiscio-core RPC."""
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


class TestEnsureDidRegistered:
    """Tests for _ensure_did_registered method."""

    def test_server_returns_error(self, tmp_path):
        """Test _ensure_did_registered handles server error gracefully."""
        connector = _Connector(
            api_key="sk_test",
            name="Test",
            agent_id="agent-123",
            server_url="https://test.server.com",
            keys_dir=tmp_path,
            auto_badge=False,
            dev_mode=False,
        )
        
        mock_client = MagicMock()
        mock_client.get.return_value = MagicMock(status_code=500)
        connector._client = mock_client
        
        # Should not raise, just log warning
        connector._ensure_did_registered("did:key:z6MkTest", {"kty": "OKP", "kid": "did:key:z6MkTest"})
        
        mock_client.get.assert_called_once_with("/v1/sdk/agents/agent-123")

    def test_server_has_same_did(self, tmp_path):
        """Test _ensure_did_registered when server already has the same DID."""
        connector = _Connector(
            api_key="sk_test",
            name="Test",
            agent_id="agent-123",
            server_url="https://test.server.com",
            keys_dir=tmp_path,
            auto_badge=False,
            dev_mode=False,
        )
        
        mock_client = MagicMock()
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {"data": {"did": "did:key:z6MkTest"}}
        mock_client.get.return_value = mock_resp
        connector._client = mock_client
        
        # Should return without calling PATCH
        connector._ensure_did_registered("did:key:z6MkTest", {"kty": "OKP", "kid": "did:key:z6MkTest"})
        
        mock_client.get.assert_called_once()
        mock_client.patch.assert_not_called()

    def test_server_has_different_did(self, tmp_path):
        """Test _ensure_did_registered when server has a different DID (e.g., did:web)."""
        connector = _Connector(
            api_key="sk_test",
            name="Test",
            agent_id="agent-123",
            server_url="https://test.server.com",
            keys_dir=tmp_path,
            auto_badge=False,
            dev_mode=False,
        )
        
        mock_client = MagicMock()
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {"data": {"did": "did:web:example.com:agent"}}
        mock_client.get.return_value = mock_resp
        connector._client = mock_client
        
        # Should return without calling PATCH (server's DID takes precedence)
        connector._ensure_did_registered("did:key:z6MkTest", {"kty": "OKP", "kid": "did:key:z6MkTest"})
        
        mock_client.get.assert_called_once()
        mock_client.patch.assert_not_called()

    def test_server_has_no_did_registers(self, tmp_path):
        """Test _ensure_did_registered registers DID when server has none."""
        connector = _Connector(
            api_key="sk_test",
            name="Test",
            agent_id="agent-123",
            server_url="https://test.server.com",
            keys_dir=tmp_path,
            auto_badge=False,
            dev_mode=False,
        )
        
        mock_client = MagicMock()
        mock_get_resp = MagicMock(status_code=200)
        mock_get_resp.json.return_value = {"data": {"did": None}}
        mock_patch_resp = MagicMock(status_code=200)
        mock_client.get.return_value = mock_get_resp
        mock_client.patch.return_value = mock_patch_resp
        connector._client = mock_client
        
        public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": "abc123", "kid": "did:key:z6MkTest"}
        connector._ensure_did_registered("did:key:z6MkTest", public_jwk)
        
        mock_client.get.assert_called_once()
        mock_client.patch.assert_called_once()
        # Verify PATCH was called with correct endpoint and payload
        call_args = mock_client.patch.call_args
        assert call_args[0][0] == "/v1/sdk/agents/agent-123/identity"

    def test_server_patch_fails_logs_warning(self, tmp_path):
        """Test _ensure_did_registered handles PATCH failure gracefully."""
        connector = _Connector(
            api_key="sk_test",
            name="Test",
            agent_id="agent-123",
            server_url="https://test.server.com",
            keys_dir=tmp_path,
            auto_badge=False,
            dev_mode=False,
        )
        
        mock_client = MagicMock()
        mock_get_resp = MagicMock(status_code=200)
        mock_get_resp.json.return_value = {"data": {"did": None}}
        mock_patch_resp = MagicMock(status_code=500)
        mock_client.get.return_value = mock_get_resp
        mock_client.patch.return_value = mock_patch_resp
        connector._client = mock_client
        
        # Should not raise, just log warning
        connector._ensure_did_registered("did:key:z6MkTest", {"kty": "OKP", "kid": "did:key:z6MkTest"})


class TestInitIdentityErrorPaths:
    """Tests for _init_identity error recovery paths."""

    def test_invalid_kid_regenerates(self, tmp_path):
        """Test _init_identity regenerates when public.jwk has invalid kid."""
        connector = _Connector(
            api_key="sk_test",
            name="Test",
            agent_id="agent-123",
            server_url="https://test.server.com",
            keys_dir=tmp_path,
            auto_badge=False,
            dev_mode=False,
        )
        
        # Create keys with invalid kid (not a DID)
        (tmp_path / "private.jwk").write_text('{"kty": "OKP", "d": "secret"}')
        (tmp_path / "public.jwk").write_text('{"kty": "OKP", "kid": "not-a-did"}')
        
        mock_rpc = MagicMock()
        mock_rpc.simpleguard.init.return_value = (
            {"did": "did:key:z6MkNew", "registered": True},
            None,
        )
        connector._rpc_client = mock_rpc
        
        result = connector._init_identity()
        
        # Should regenerate via RPC since kid is invalid
        assert result == "did:key:z6MkNew"
        mock_rpc.simpleguard.init.assert_called_once()

    def test_json_decode_error_regenerates(self, tmp_path):
        """Test _init_identity regenerates when public.jwk has invalid JSON."""
        connector = _Connector(
            api_key="sk_test",
            name="Test",
            agent_id="agent-123",
            server_url="https://test.server.com",
            keys_dir=tmp_path,
            auto_badge=False,
            dev_mode=False,
        )
        
        # Create keys with invalid JSON
        (tmp_path / "private.jwk").write_text('{"kty": "OKP"}')
        (tmp_path / "public.jwk").write_text('not valid json')
        
        mock_rpc = MagicMock()
        mock_rpc.simpleguard.init.return_value = (
            {"did": "did:key:z6MkNew", "registered": True},
            None,
        )
        connector._rpc_client = mock_rpc
        
        result = connector._init_identity()
        
        # Should regenerate via RPC since JSON is invalid
        assert result == "did:key:z6MkNew"
        mock_rpc.simpleguard.init.assert_called_once()

    def test_missing_kid_regenerates(self, tmp_path):
        """Test _init_identity regenerates when public.jwk has no kid field."""
        connector = _Connector(
            api_key="sk_test",
            name="Test",
            agent_id="agent-123",
            server_url="https://test.server.com",
            keys_dir=tmp_path,
            auto_badge=False,
            dev_mode=False,
        )
        
        # Create keys without kid field
        (tmp_path / "private.jwk").write_text('{"kty": "OKP", "d": "secret"}')
        (tmp_path / "public.jwk").write_text('{"kty": "OKP", "crv": "Ed25519", "x": "abc123"}')
        
        mock_rpc = MagicMock()
        mock_rpc.simpleguard.init.return_value = (
            {"did": "did:key:z6MkNew", "registered": True},
            None,
        )
        connector._rpc_client = mock_rpc
        
        result = connector._init_identity()
        
        # Should regenerate via RPC since kid is missing
        assert result == "did:key:z6MkNew"
        mock_rpc.simpleguard.init.assert_called_once()


class TestReadDidFromKeys:
    """Tests for the _read_did_from_keys standalone helper function."""

    def test_read_did_from_public_jwk_kid(self, tmp_path):
        """Test reading DID from public.jwk kid field."""
        from capiscio_sdk.connect import _read_did_from_keys
        
        # Create public.jwk with kid field
        (tmp_path / "public.jwk").write_text(
            '{"kty":"OKP","crv":"Ed25519","kid":"did:key:z6MkTestFromKid","x":"AAAA"}'
        )
        
        result = _read_did_from_keys(tmp_path)
        assert result == "did:key:z6MkTestFromKid"

    def test_read_did_from_did_txt_fallback(self, tmp_path):
        """Test reading DID from did.txt when public.jwk has no kid."""
        from capiscio_sdk.connect import _read_did_from_keys
        
        # Create public.jwk without kid (legacy format)
        (tmp_path / "public.jwk").write_text('{"kty":"OKP","crv":"Ed25519","x":"AAAA"}')
        # Create did.txt as fallback
        (tmp_path / "did.txt").write_text("did:key:z6MkFromDidTxt")
        
        result = _read_did_from_keys(tmp_path)
        assert result == "did:key:z6MkFromDidTxt"

    def test_read_did_malformed_json(self, tmp_path):
        """Test handling of malformed JSON in public.jwk."""
        from capiscio_sdk.connect import _read_did_from_keys
        
        (tmp_path / "public.jwk").write_text("not valid json")
        (tmp_path / "did.txt").write_text("did:key:z6MkFallback")
        
        result = _read_did_from_keys(tmp_path)
        assert result == "did:key:z6MkFallback"

    def test_read_did_no_files_returns_none(self, tmp_path):
        """Test returns None when no DID files exist."""
        from capiscio_sdk.connect import _read_did_from_keys
        
        result = _read_did_from_keys(tmp_path)
        assert result is None


class TestFindAgentFromLocalKeys:
    """Tests for _find_agent_from_local_keys method."""

    def test_skips_non_uuid_directories(self, tmp_path):
        """Test that non-UUID directories are skipped."""
        connector = _Connector(
            api_key="sk_test",
            name="Test",
            agent_id=None,
            server_url="https://test.server.com",
            keys_dir=tmp_path,
            auto_badge=False,
            dev_mode=False,
        )
        
        # Create directory with non-UUID name
        non_uuid_dir = tmp_path / "not-a-uuid"
        non_uuid_dir.mkdir()
        (non_uuid_dir / "private.jwk").write_text('{"kty":"OKP"}')
        (non_uuid_dir / "public.jwk").write_text('{"kty":"OKP","kid":"did:key:z6MkTest"}')
        
        # Mock the HTTP client to track calls
        mock_response = MagicMock()
        mock_response.status_code = 404
        connector._client = MagicMock()
        connector._client.get = MagicMock(return_value=mock_response)
        
        # Patch DEFAULT_KEYS_DIR.exists() to prevent scanning real ~/.capiscio/keys
        original_default_exists = DEFAULT_KEYS_DIR.exists
        try:
            object.__setattr__(DEFAULT_KEYS_DIR, 'exists', lambda: False)
        except (TypeError, AttributeError):
            # Path objects are immutable, use alternative approach
            pass
        
        result = connector._find_agent_from_local_keys()
        
        # Should not make API call for non-UUID directory
        # (may have calls for real UUIDs in DEFAULT_KEYS_DIR, but not for "not-a-uuid")
        for call in connector._client.get.call_args_list:
            # Ensure the non-UUID directory was not used
            assert "not-a-uuid" not in str(call)

    def test_finds_agent_with_valid_uuid_keys(self, tmp_path):
        """Test finding agent when valid UUID directory has keys."""
        connector = _Connector(
            api_key="sk_test",
            name="Test",
            agent_id=None,
            server_url="https://test.server.com",
            keys_dir=tmp_path,
            auto_badge=False,
            dev_mode=False,
        )
        
        # Create directory with valid UUID name
        agent_uuid = "12345678-1234-1234-1234-123456789012"
        uuid_dir = tmp_path / agent_uuid
        uuid_dir.mkdir()
        (uuid_dir / "private.jwk").write_text('{"kty":"OKP"}')
        (uuid_dir / "public.jwk").write_text('{"kty":"OKP","kid":"did:key:z6MkTest"}')
        
        # Mock the HTTP client
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"id": agent_uuid, "name": "Test"}}
        connector._client = MagicMock()
        connector._client.get = MagicMock(return_value=mock_response)
        
        result = connector._find_agent_from_local_keys()
        
        assert result is not None
        assert result["id"] == agent_uuid


class TestEnsureDidRegisteredMethod:
    """Tests for _ensure_did_registered method."""

    def test_returns_server_did_when_different(self, tmp_path):
        """Test returns server DID when it differs from local."""
        connector = _Connector(
            api_key="sk_test",
            name="Test",
            agent_id="agent-123",
            server_url="https://test.server.com",
            keys_dir=tmp_path,
            auto_badge=False,
            dev_mode=False,
        )
        
        # Mock client to return agent with different DID
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"did": "did:web:example.com:agent"}}
        connector._client = MagicMock()
        connector._client.get = MagicMock(return_value=mock_response)
        
        result = connector._ensure_did_registered("did:key:z6MkLocal", {"kty": "OKP"})
        
        assert result == "did:web:example.com:agent"

    def test_returns_none_when_did_matches(self, tmp_path):
        """Test returns None when server DID matches local."""
        connector = _Connector(
            api_key="sk_test",
            name="Test",
            agent_id="agent-123",
            server_url="https://test.server.com",
            keys_dir=tmp_path,
            auto_badge=False,
            dev_mode=False,
        )
        
        # Mock client to return agent with matching DID
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"did": "did:key:z6MkLocal"}}
        connector._client = MagicMock()
        connector._client.get = MagicMock(return_value=mock_response)
        
        result = connector._ensure_did_registered("did:key:z6MkLocal", {"kty": "OKP"})
        
        assert result is None

    def test_registers_did_when_server_has_none(self, tmp_path):
        """Test registers DID via PATCH when server has no DID."""
        connector = _Connector(
            api_key="sk_test",
            name="Test",
            agent_id="agent-123",
            server_url="https://test.server.com",
            keys_dir=tmp_path,
            auto_badge=False,
            dev_mode=False,
        )
        
        # Mock responses: GET returns no DID, PATCH succeeds
        mock_get = MagicMock()
        mock_get.status_code = 200
        mock_get.json.return_value = {"data": {"did": None}}
        
        mock_patch = MagicMock()
        mock_patch.status_code = 200
        
        connector._client = MagicMock()
        connector._client.get = MagicMock(return_value=mock_get)
        connector._client.patch = MagicMock(return_value=mock_patch)
        
        result = connector._ensure_did_registered("did:key:z6MkNew", {"kty": "OKP"})
        
        # Should call PATCH to register
        connector._client.patch.assert_called_once()
        assert result is None  # No different DID to return
