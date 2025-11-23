"""Tests for FastAPI integration."""
import json
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from capiscio_sdk.simple_guard import SimpleGuard
from capiscio_sdk.integrations.fastapi import CapiscioMiddleware

@pytest.fixture
def guard():
    return SimpleGuard(dev_mode=True)

@pytest.fixture
def app(guard):
    app = FastAPI()
    app.add_middleware(CapiscioMiddleware, guard=guard)
    
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
    assert "Missing X-Capiscio-JWS" in response.json()["error"]

def test_middleware_valid_request(client, guard):
    """Test that valid request passes and body is preserved."""
    payload = {"sub": "test-agent"}
    body_dict = {"foo": "bar"}
    body_bytes = json.dumps(body_dict).encode('utf-8')
    
    token = guard.sign_outbound(payload, body=body_bytes)
    headers = {"X-Capiscio-JWS": token, "Content-Type": "application/json"}
    
    # Use content=body_bytes to ensure exact byte match
    response = client.post("/test", content=body_bytes, headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert data["agent"] == guard.agent_id
    assert data["received_body"] == body_dict
    
    # Check Server-Timing header
    assert "Server-Timing" in response.headers
    assert "capiscio-auth" in response.headers["Server-Timing"]

def test_middleware_tampered_body(client, guard):
    """Test that middleware blocks tampered body."""
    payload = {"sub": "test-agent"}
    original_body = b'{"foo":"bar"}'
    
    token = guard.sign_outbound(payload, body=original_body)
    headers = {"X-Capiscio-JWS": token}
    
    # Send different body
    response = client.post("/test", json={"foo": "baz"}, headers=headers)
    
    assert response.status_code == 403
    assert "Integrity Check Failed" in response.json()["error"]
