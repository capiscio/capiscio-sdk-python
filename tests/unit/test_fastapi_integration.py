"""Tests for FastAPI integration.

These tests verify FastAPI middleware behavior using mocks,
since the actual Go core may not be running during unit tests.
"""
import json
import pytest
from unittest.mock import MagicMock
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from capiscio_sdk.errors import VerificationError
from capiscio_sdk.integrations.fastapi import CapiscioMiddleware


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
