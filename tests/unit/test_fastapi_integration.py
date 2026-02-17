"""Tests for FastAPI integration.

These tests verify FastAPI middleware behavior using mocks,
since the actual Go core may not be running during unit tests.
"""
import json
import pytest
from unittest.mock import MagicMock, patch
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from capiscio_sdk.errors import VerificationError
from capiscio_sdk.integrations.fastapi import CapiscioMiddleware
from capiscio_sdk.config import SecurityConfig, DownstreamConfig


@pytest.fixture
def mock_guard():
    """Create a mock SimpleGuard that doesn't need Go core."""
    guard = MagicMock()
    guard.agent_id = "test-agent-123"
    guard.signing_kid = "test-key"
    return guard


@pytest.fixture
def app(mock_guard):
    """Create FastAPI app with Capiscio middleware."""
    app = FastAPI()
    app.add_middleware(CapiscioMiddleware, guard=mock_guard)
    
    @app.post("/test")
    async def test_endpoint(request: Request):
        # Verify we can read the body again
        body = await request.json()
        return {
            "agent": request.state.agent_id,
            "received_body": body
        }
    return app


@pytest.fixture
def client(app):
    return TestClient(app)


def test_middleware_missing_header(client):
    """Test that missing header returns 401."""
    response = client.post("/test", json={"foo": "bar"})
    assert response.status_code == 401
    assert "Missing X-Capiscio-Badge" in response.json()["error"]


def test_middleware_valid_request(client, mock_guard):
    """Test that valid request passes and body is preserved."""
    body_dict = {"foo": "bar"}
    body_bytes = json.dumps(body_dict).encode('utf-8')
    
    # Mock verification to succeed - iss becomes request.state.agent_id
    mock_guard.verify_inbound.return_value = {
        "sub": "recipient-agent",
        "iss": "test-agent-123",  # This becomes agent_id
        "iat": 1234567890,
    }
    
    # Send request with Badge header (RFC-002 §9.1)
    headers = {"X-Capiscio-Badge": "mock.jws.token", "Content-Type": "application/json"}
    response = client.post("/test", content=body_bytes, headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert data["agent"] == "test-agent-123"
    assert data["received_body"] == body_dict
    
    # Check Server-Timing header
    assert "Server-Timing" in response.headers
    assert "capiscio-auth" in response.headers["Server-Timing"]
    
    # Verify guard.verify_inbound was called with correct args
    mock_guard.verify_inbound.assert_called_once()
    call_args = mock_guard.verify_inbound.call_args
    assert call_args[0][0] == "mock.jws.token"
    assert call_args[1]["body"] == body_bytes


def test_middleware_tampered_body(client, mock_guard):
    """Test that middleware blocks tampered body (VerificationError -> 403)."""
    # Mock verification to raise VerificationError (body hash mismatch)
    mock_guard.verify_inbound.side_effect = VerificationError("Body hash mismatch")
    
    headers = {"X-Capiscio-Badge": "mock.jws.token"}
    response = client.post("/test", json={"foo": "baz"}, headers=headers)
    
    assert response.status_code == 403
    assert "Access Denied" in response.json()["error"]


def test_middleware_invalid_signature(client, mock_guard):
    """Test that middleware blocks invalid signatures (VerificationError -> 403)."""
    # Mock verification to raise VerificationError
    mock_guard.verify_inbound.side_effect = VerificationError("Invalid signature")
    
    headers = {"X-Capiscio-Badge": "invalid.jws.token"}
    response = client.post("/test", json={"foo": "bar"}, headers=headers)
    
    assert response.status_code == 403
    assert "Access Denied" in response.json()["error"]


def test_middleware_exclude_paths():
    """Test that exclude_paths parameter allows bypassing verification."""
    mock_guard = MagicMock()
    mock_guard.agent_id = "test-agent"
    
    app = FastAPI()
    app.add_middleware(
        CapiscioMiddleware, 
        guard=mock_guard,
        exclude_paths=["/health", "/.well-known/agent-card.json"]
    )
    
    @app.get("/health")
    async def health():
        return {"status": "ok"}
    
    @app.get("/.well-known/agent-card.json")
    async def agent_card():
        return {"name": "Test Agent"}
    
    @app.post("/protected")
    async def protected():
        return {"secret": "data"}
    
    client = TestClient(app)
    
    # Excluded paths should work without header
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    
    response = client.get("/.well-known/agent-card.json")
    assert response.status_code == 200
    assert response.json()["name"] == "Test Agent"
    
    # Non-excluded paths should require header
    response = client.post("/protected", json={})
    assert response.status_code == 401
    assert "Missing X-Capiscio-Badge" in response.json()["error"]


class TestSecurityConfigIntegration:
    """Tests for SecurityConfig integration with middleware."""
    
    def test_middleware_accepts_security_config(self):
        """Test that middleware accepts SecurityConfig parameter."""
        mock_guard = MagicMock()
        mock_guard.agent_id = "test-agent"
        
        config = SecurityConfig(
            downstream=DownstreamConfig(require_signatures=True),
            fail_mode="block",
        )
        
        app = FastAPI()
        # Should not raise
        app.add_middleware(
            CapiscioMiddleware,
            guard=mock_guard,
            config=config,
        )
        
        @app.get("/test")
        async def test_endpoint():
            return {"ok": True}
        
        client = TestClient(app)
        # Verify middleware is installed by checking 401 on missing header
        response = client.get("/test")
        assert response.status_code == 401
    
    def test_middleware_fail_mode_log(self):
        """Test fail_mode='log' allows request on verification failure."""
        mock_guard = MagicMock()
        mock_guard.agent_id = "test-agent"
        mock_guard.verify_inbound.side_effect = VerificationError("Invalid badge")
        
        config = SecurityConfig(
            downstream=DownstreamConfig(require_signatures=True),
            fail_mode="log",  # Log-only mode
        )
        
        app = FastAPI()
        app.add_middleware(
            CapiscioMiddleware,
            guard=mock_guard,
            config=config,
        )
        
        @app.post("/test")
        async def test_endpoint():
            return {"allowed": True}
        
        client = TestClient(app)
        headers = {"X-Capiscio-Badge": "invalid.badge.token"}
        response = client.post("/test", json={}, headers=headers)
        
        # In log mode, should allow the request even though verification failed
        assert response.status_code == 200
        assert response.json()["allowed"] is True
    
    def test_middleware_fail_mode_monitor(self):
        """Test fail_mode='monitor' allows request on verification failure."""
        mock_guard = MagicMock()
        mock_guard.agent_id = "test-agent"
        mock_guard.verify_inbound.side_effect = VerificationError("Invalid badge")
        
        config = SecurityConfig(
            downstream=DownstreamConfig(require_signatures=True),
            fail_mode="monitor",  # Monitor mode - same as log
        )
        
        app = FastAPI()
        app.add_middleware(
            CapiscioMiddleware,
            guard=mock_guard,
            config=config,
        )
        
        @app.post("/test")
        async def test_endpoint():
            return {"allowed": True}
        
        client = TestClient(app)
        headers = {"X-Capiscio-Badge": "invalid.badge.token"}
        response = client.post("/test", json={}, headers=headers)
        
        # In monitor mode, should allow the request even though verification failed
        assert response.status_code == 200
        assert response.json()["allowed"] is True
    
    def test_middleware_fail_mode_block(self):
        """Test fail_mode='block' blocks request on verification failure."""
        mock_guard = MagicMock()
        mock_guard.agent_id = "test-agent"
        mock_guard.verify_inbound.side_effect = VerificationError("Invalid badge")
        
        config = SecurityConfig(
            downstream=DownstreamConfig(require_signatures=True),
            fail_mode="block",  # Block mode
        )
        
        app = FastAPI()
        app.add_middleware(
            CapiscioMiddleware,
            guard=mock_guard,
            config=config,
        )
        
        @app.post("/test")
        async def test_endpoint():
            return {"allowed": True}
        
        client = TestClient(app)
        headers = {"X-Capiscio-Badge": "invalid.badge.token"}
        response = client.post("/test", json={}, headers=headers)
        
        # In block mode, should block the request
        assert response.status_code == 403
        assert "Access Denied" in response.json()["error"]
    
    def test_middleware_config_none_uses_defaults(self):
        """Test that config=None uses default strict behavior."""
        mock_guard = MagicMock()
        mock_guard.agent_id = "test-agent"
        mock_guard.verify_inbound.side_effect = VerificationError("Invalid badge")
        
        app = FastAPI()
        app.add_middleware(
            CapiscioMiddleware,
            guard=mock_guard,
            config=None,  # Explicit None
        )
        
        @app.post("/test")
        async def test_endpoint():
            return {"allowed": True}
        
        client = TestClient(app)
        headers = {"X-Capiscio-Badge": "invalid.badge.token"}
        response = client.post("/test", json={}, headers=headers)
        
        # Default should be strict mode
        assert response.status_code == 403
    
    def test_security_config_from_env(self):
        """Test SecurityConfig.from_env() reads environment variables."""
        with patch.dict('os.environ', {
            'CAPISCIO_REQUIRE_SIGNATURES': 'true',
            'CAPISCIO_FAIL_MODE': 'monitor',
            'CAPISCIO_RATE_LIMIT_RPM': '100',
        }):
            config = SecurityConfig.from_env()
            
            assert config.downstream.require_signatures is True
            assert config.fail_mode == "monitor"
            assert config.downstream.rate_limit_requests_per_minute == 100

    def test_middleware_options_bypass(self):
        """Test that OPTIONS requests bypass verification (CORS preflight)."""
        mock_guard = MagicMock()
        mock_guard.agent_id = "test-agent"
        
        app = FastAPI()
        app.add_middleware(
            CapiscioMiddleware,
            guard=mock_guard,
        )
        
        @app.api_route("/test", methods=["OPTIONS", "POST"])
        async def test_endpoint():
            return {"ok": True}
        
        client = TestClient(app)
        # OPTIONS should pass without header
        response = client.options("/test")
        assert response.status_code == 200
        # verify_inbound should NOT have been called
        mock_guard.verify_inbound.assert_not_called()
    
    def test_middleware_require_signatures_false(self):
        """Test require_signatures=False allows requests without badge."""
        mock_guard = MagicMock()
        mock_guard.agent_id = "test-agent"
        
        config = SecurityConfig(
            downstream=DownstreamConfig(require_signatures=False),  # No badge required
            fail_mode="block",
        )
        
        app = FastAPI()
        app.add_middleware(
            CapiscioMiddleware,
            guard=mock_guard,
            config=config,
        )
        
        @app.post("/test")
        async def test_endpoint(request: Request):
            # Should have None for agent info
            return {
                "agent": getattr(request.state, 'agent', 'not-set'),
                "agent_id": getattr(request.state, 'agent_id', 'not-set'),
            }
        
        client = TestClient(app)
        # Request WITHOUT badge header should pass
        response = client.post("/test", json={})
        assert response.status_code == 200
        data = response.json()
        assert data["agent"] is None
        assert data["agent_id"] is None
        # verify_inbound should NOT have been called
        mock_guard.verify_inbound.assert_not_called()
    
    def test_middleware_missing_badge_log_mode(self):
        """Test missing badge with fail_mode='log' allows request through."""
        mock_guard = MagicMock()
        mock_guard.agent_id = "test-agent"
        
        config = SecurityConfig(
            downstream=DownstreamConfig(require_signatures=True),  # Badge required
            fail_mode="log",  # But just log failures
        )
        
        app = FastAPI()
        app.add_middleware(
            CapiscioMiddleware,
            guard=mock_guard,
            config=config,
        )
        
        @app.post("/test")
        async def test_endpoint(request: Request):
            return {
                "agent": getattr(request.state, 'agent', 'not-set'),
                "agent_id": getattr(request.state, 'agent_id', 'not-set'),
            }
        
        client = TestClient(app)
        # Request WITHOUT badge header - should pass in log mode
        response = client.post("/test", json={})
        assert response.status_code == 200
        data = response.json()
        assert data["agent"] is None
        assert data["agent_id"] is None
    
    def test_middleware_missing_badge_monitor_mode(self):
        """Test missing badge with fail_mode='monitor' allows request through."""
        mock_guard = MagicMock()
        mock_guard.agent_id = "test-agent"
        
        config = SecurityConfig(
            downstream=DownstreamConfig(require_signatures=True),  # Badge required
            fail_mode="monitor",  # But just monitor failures
        )
        
        app = FastAPI()
        app.add_middleware(
            CapiscioMiddleware,
            guard=mock_guard,
            config=config,
        )
        
        @app.post("/test")
        async def test_endpoint(request: Request):
            return {
                "agent": getattr(request.state, 'agent', 'not-set'),
                "agent_id": getattr(request.state, 'agent_id', 'not-set'),
            }
        
        client = TestClient(app)
        # Request WITHOUT badge header - should pass in monitor mode
        response = client.post("/test", json={})
        assert response.status_code == 200
        data = response.json()
        assert data["agent"] is None
        assert data["agent_id"] is None
