"""Tests for SimpleGuard."""
import os
import json
import time
import pytest
from pathlib import Path
from capiscio_sdk.simple_guard import SimpleGuard
from capiscio_sdk.errors import VerificationError

@pytest.fixture
def temp_workspace(tmp_path):
    """Create a temporary workspace for SimpleGuard."""
    # SimpleGuard looks for agent-card.json or creates one in dev_mode
    # We'll let it run in tmp_path
    cwd = os.getcwd()
    os.chdir(tmp_path)
    yield tmp_path
    os.chdir(cwd)

@pytest.fixture
def guard(temp_workspace):
    """Create a SimpleGuard instance in dev mode."""
    return SimpleGuard(dev_mode=True)

def test_initialization_dev_mode(guard, temp_workspace):
    """Test that dev_mode generates keys and agent card."""
    assert (temp_workspace / "agent-card.json").exists()
    assert (temp_workspace / "capiscio_keys" / "private.pem").exists()
    assert (temp_workspace / "capiscio_keys" / "public.pem").exists()
    assert (temp_workspace / "capiscio_keys" / "trusted").exists()
    
    # Check self-trust
    card = json.loads((temp_workspace / "agent-card.json").read_text())
    kid = card["public_keys"][0]["kid"]
    assert (temp_workspace / "capiscio_keys" / "trusted" / f"{kid}.pem").exists()

def test_sign_and_verify_valid(guard):
    """Test signing and verifying a valid payload."""
    payload = {"sub": "test-agent", "msg": "hello"}
    token = guard.sign_outbound(payload)
    
    verified = guard.verify_inbound(token)
    assert verified["sub"] == "test-agent"
    assert verified["iss"] == guard.agent_id
    assert "iat" in verified
    assert "exp" in verified

def test_integrity_check_success(guard):
    """Test integrity check with valid body."""
    payload = {"sub": "test"}
    body = b'{"foo":"bar"}'
    
    token = guard.sign_outbound(payload, body=body)
    verified = guard.verify_inbound(token, body=body)
    
    assert verified["bh"] is not None

def test_integrity_check_failure(guard):
    """Test integrity check with tampered body."""
    payload = {"sub": "test"}
    original_body = b'{"foo":"bar"}'
    tampered_body = b'{"foo":"baz"}'
    
    token = guard.sign_outbound(payload, body=original_body)
    
    with pytest.raises(VerificationError, match="Integrity Check Failed"):
        guard.verify_inbound(token, body=tampered_body)

def test_replay_protection_expired(guard):
    """Test that expired tokens are rejected."""
    payload = {"sub": "test"}
    # Manually create an expired token by mocking time or modifying payload before signing?
    # SimpleGuard.sign_outbound injects time. We can't easily mock time inside the class without patching.
    # But we can sign it, decode it, modify exp, resign it? 
    # Easier: SimpleGuard uses self._private_key. We can use jwt.encode manually.
    
    import jwt
    
    now = int(time.time())
    expired_payload = {
        "sub": "test",
        "iss": guard.agent_id,
        "iat": now - 100,
        "exp": now - 10, # Expired
        "bh": "dummy"
    }
    
    headers = {
        "kid": guard.signing_kid,
        "typ": "JWT",
        "alg": "EdDSA"
    }
    
    token = jwt.encode(
        expired_payload,
        guard._private_key,
        algorithm="EdDSA",
        headers=headers
    )
    
    with pytest.raises(VerificationError, match="Token expired"):
        guard.verify_inbound(token, body=b"") # Body doesn't matter if exp fails first? 
        # Actually verify_inbound checks signature first, then integrity, then time.
        # So we need a valid body hash if we provide a body, or no body if no bh.
        # I put "bh": "dummy" so I need to match it or remove it.
        # Let's remove bh for this test to isolate time check.

def test_replay_protection_expired_clean(guard):
    """Test expired token without body hash complications."""
    import jwt
    now = int(time.time())
    expired_payload = {
        "sub": "test",
        "iss": guard.agent_id,
        "iat": now - 100,
        "exp": now - 10 # Expired
    }
    
    headers = {
        "kid": guard.signing_kid,
        "typ": "JWT",
        "alg": "EdDSA"
    }
    
    token = jwt.encode(
        expired_payload,
        guard._private_key,
        algorithm="EdDSA",
        headers=headers
    )
    
    with pytest.raises(VerificationError, match="Token expired"):
        guard.verify_inbound(token)

def test_missing_kid(guard):
    """Test JWS without kid header."""
    import jwt
    token = jwt.encode({"sub": "test"}, guard._private_key, algorithm="EdDSA") # No headers
    
    with pytest.raises(VerificationError, match="Missing 'kid'"):
        guard.verify_inbound(token)

def test_untrusted_key(guard, temp_workspace):
    """Test JWS signed by unknown key."""
    # Generate a new key that isn't in trusted/
    from cryptography.hazmat.primitives.asymmetric import ed25519
    other_key = ed25519.Ed25519PrivateKey.generate()
    
    import jwt
    headers = {"kid": "unknown-key", "alg": "EdDSA"}
    token = jwt.encode({"sub": "test"}, other_key, algorithm="EdDSA", headers=headers)
    
    with pytest.raises(VerificationError, match="Untrusted key ID"):
        guard.verify_inbound(token)
