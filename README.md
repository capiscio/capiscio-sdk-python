# CapiscIO SDK (Python)

**Enforcement-First Security for A2A Agents.**

[![PyPI version](https://badge.fury.io/py/capiscio-sdk.svg)](https://badge.fury.io/py/capiscio-sdk)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

**CapiscIO** is the "Customs Officer" for your AI Agent. It provides military-grade Identity and Integrity enforcement for the [Agent-to-Agent (A2A) Protocol](https://github.com/google/A2A) with **zero configuration**.

## 🚀 The 60-Second Upgrade

Turn any FastAPI application into a Verified A2A Agent in 3 lines of code.

```python
from fastapi import FastAPI
from capiscio_sdk.simple_guard import SimpleGuard
from capiscio_sdk.integrations.fastapi import CapiscioMiddleware

# 1. Initialize Guard (Auto-generates keys in dev_mode)
guard = SimpleGuard(dev_mode=True)

app = FastAPI()

# 2. Add Enforcement Middleware
app.add_middleware(CapiscioMiddleware, guard=guard)

@app.post("/agent/task")
async def handle_task(request: Request):
    # 🔒 Only reachable if Identity + Integrity are verified
    caller = request.state.agent_id
    return {"status": "accepted", "verified_caller": caller}
```

## 🛡️ What You Get (Out of the Box)

1.  **Zero-Config Identity**:
    *   Auto-generates **Ed25519** keys and `agent-card.json` on first run.
    *   No manual key management required for development.

2.  **Payload Integrity**:
    *   Enforces **SHA-256 Body Hash (`bh`)** verification.
    *   Blocks tampered payloads instantly (returns `403 Forbidden`).

3.  **Replay Protection**:
    *   Enforces strict **60-second** token expiration (`exp`).
    *   Prevents replay attacks and ensures freshness.

4.  **Performance Telemetry**:
    *   Adds `<1ms` overhead.
    *   Includes `Server-Timing` headers for transparent monitoring.

## Installation

```bash
pip install capiscio-sdk
```

## 🎯 Agent Card Validation with CoreValidator

The SDK includes a **Go core-backed validator** for Agent Card validation. This ensures consistent validation behavior across all CapiscIO SDKs (Python, Node.js, etc.).

### Quick Validation

```python
from capiscio_sdk.validators import validate_agent_card

# One-shot validation
result = validate_agent_card({
    "name": "My Agent",
    "url": "https://myagent.example.com",
    "version": "1.0.0",
    "skills": [{"id": "chat", "name": "Chat", "description": "Chat skill"}]
})

print(f"Valid: {result.success}")
print(f"Compliance Score: {result.compliance.total}/100 ({result.compliance.rating})")
print(f"Trust Score: {result.trust.total}/100 ({result.trust.rating})")
```

### Multi-Dimensional Scoring

CoreValidator returns rich multi-dimensional scores:

```python
from capiscio_sdk.validators import CoreValidator

with CoreValidator() as validator:
    result = validator.validate_agent_card(card)
    
    # 📊 Compliance Score (0-100)
    print(f"Compliance: {result.compliance.total}")
    print(f"  - Core Fields: {result.compliance.breakdown.core_fields.score}")
    print(f"  - Skills Quality: {result.compliance.breakdown.skills_quality.score}")
    print(f"  - Format Compliance: {result.compliance.breakdown.format_compliance.score}")
    print(f"  - Data Quality: {result.compliance.breakdown.data_quality.score}")
    
    # 🔒 Trust Score (0-100)
    print(f"Trust: {result.trust.total}")
    print(f"  - Signatures: {result.trust.breakdown.signatures.score}")
    print(f"  - Provider: {result.trust.breakdown.provider.score}")
    print(f"  - Security: {result.trust.breakdown.security.score}")
    print(f"  - Documentation: {result.trust.breakdown.documentation.score}")
    
    # 📡 Availability Score (when tested)
    if result.availability.tested:
        print(f"Availability: {result.availability.total}")
```

### Score Ratings

| Score Range | Compliance Rating | Trust Rating |
|-------------|-------------------|--------------|
| 90-100      | A+                | Verified     |
| 80-89       | A                 | High         |
| 70-79       | B                 | Good         |
| 60-69       | C                 | Moderate     |
| 50-59       | D                 | Low          |
| 0-49        | F                 | Untrusted    |

### Async Fetch and Validate

```python
async def check_remote_agent(agent_url: str):
    with CoreValidator() as validator:
        result = await validator.fetch_and_validate(agent_url)
        return result.success and result.compliance.total >= 80
```

### Migration from Legacy Validators

```python
# ❌ Deprecated (will be removed in v1.0.0)
from capiscio_sdk.validators import AgentCardValidator
validator = AgentCardValidator()  # Shows deprecation warning

# ✅ Recommended
from capiscio_sdk.validators import CoreValidator, validate_agent_card
result = validate_agent_card(card)  # Uses Go core
```

## 🔏 Trust Badge Verification (RFC-002)

CapiscIO Trust Badges provide cryptographic proof of agent identity verification. The SDK supports verifying badges issued by the CapiscIO registry or self-signed badges for development.

### Trust Levels

| Level | Name | Description |
|-------|------|-------------|
| 0 | Self-Signed (SS) | No external validation, `did:key` issuer |
| 1 | Domain Validated (DV) | Domain ownership verified |
| 2 | Organization Validated (OV) | Organization identity verified |
| 3 | Extended Validated (EV) | Highest level of identity verification |
| 4 | Community Vouched (CV) | Verified with peer attestations |

### Verify a Trust Badge

```python
from capiscio_sdk._rpc.client import CapiscioRPCClient

# Connect to gRPC server (auto-starts if needed)
client = CapiscioRPCClient()
client.connect()

# Badge token (JWS format)
badge_token = "eyJhbGciOiJFZERTQSJ9.eyJqdGkiOi..."

# Verify badge (production - rejects self-signed)
valid, claims, warnings, error = client.badge.verify_badge_with_options(
    badge_token,
    accept_self_signed=False  # Default: reject self-signed badges
)

if valid:
    print(f"✅ Badge verified!")
    print(f"   Issuer: {claims['iss']}")
    print(f"   Subject: {claims['sub']}")
    print(f"   Trust Level: {claims['trust_level']}")  # "0", "1", "2", "3", or "4"
    print(f"   Expires: {claims['exp']}")
else:
    print(f"❌ Verification failed: {error}")

client.close()
```

### Accept Self-Signed Badges (Development)

For development/testing, you can accept self-signed (Level 0) badges:

```python
# Development mode - accept self-signed badges
valid, claims, warnings, error = client.badge.verify_badge_with_options(
    badge_token,
    accept_self_signed=True  # ⚠️ Only for development!
)

if valid and claims['trust_level'] == '0':
    print("⚠️ Self-signed badge - not suitable for production")
```

### Verification Options

```python
# Full verification options
valid, claims, warnings, error = client.badge.verify_badge_with_options(
    token=badge_token,
    accept_self_signed=False,      # Reject Level 0 badges
    trusted_issuers=["https://registry.capisc.io"],  # Allowlist of trusted CAs
    audience="my-service",         # Expected audience claim
    skip_revocation=False,         # Check revocation status
    skip_agent_status=False        # Check agent is not disabled
)
```

### Badge Claims Structure

```python
# Example claims from a verified badge
claims = {
    "jti": "550e8400-e29b-41d4-a716-446655440000",  # Unique badge ID
    "iss": "https://registry.capisc.io",            # Issuer URL
    "sub": "did:web:registry.capisc.io:agents:abc123",  # Agent DID
    "iat": 1702234567,                              # Issued at (Unix timestamp)
    "exp": 1702320967,                              # Expires at (Unix timestamp)
    "trust_level": "2",                             # "0"-"4"
    "aud": ["my-service"],                          # Audience (optional)
}
```

## 🔌 gRPC SDK Integration (All 7 Services)

The SDK provides a comprehensive gRPC client that wraps all `capiscio-core` functionality. The client auto-starts the local gRPC server if needed.

### Connection Modes

```python
from capiscio_sdk._rpc.client import CapiscioRPCClient

# Auto-start mode (recommended for local development)
client = CapiscioRPCClient()  # Auto-starts capiscio-core gRPC server
client.connect()

# Connect to existing Unix socket
client = CapiscioRPCClient(address="unix:///tmp/capiscio.sock", auto_start=False)
client.connect()

# Connect to remote TCP server
client = CapiscioRPCClient(address="localhost:50051", auto_start=False)
client.connect()

# Context manager (auto-cleanup)
with CapiscioRPCClient() as client:
    # Use client...
    pass  # Automatically disconnects
```

### 1. BadgeService - Trust Badge Operations

```python
with CapiscioRPCClient() as client:
    # Sign a badge
    token, claims = client.badge.sign_badge(
        claims={
            "jti": "550e8400-e29b-41d4-a716-446655440000",
            "iss": "https://registry.capisc.io",
            "sub": "did:web:registry.capisc.io:agents:my-agent",
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
            "trust_level": "2"
        },
        private_key_jwk='{"kty":"OKP",...}',
        key_id="key-1"
    )

    # Verify with full options
    valid, claims, warnings, error = client.badge.verify_badge_with_options(
        token,
        accept_self_signed=True,
        trusted_issuers=["https://registry.capisc.io"],
        audience="my-service"
    )

    # Parse without verification
    claims, error = client.badge.parse_badge(token)

    # Request CA-signed badge
    token, error = client.badge.request_badge(
        agent_id="my-agent-123",
        api_key="capi_key_...",
        ca_url="https://registry.capisc.io"
    )

    # Start badge keeper (auto-renewal)
    for event in client.badge.start_keeper(
        private_key_jwk='{"kty":"OKP",...}',
        subject="did:web:registry.capisc.io:agents:my-agent",
        ca_url="https://registry.capisc.io",
        ttl_seconds=300,
        renew_before_seconds=60
    ):
        if event.event_type == "renewed":
            print(f"Badge renewed: {event.badge_token}")
```

### 2. DIDService - DID Parsing

```python
with CapiscioRPCClient() as client:
    # Parse did:web identifier
    did_info, error = client.did.parse("did:web:registry.capisc.io:agents:my-agent")

    if did_info:
        print(f"Method: {did_info['method']}")          # "web"
        print(f"Domain: {did_info['domain']}")          # "registry.capisc.io"
        print(f"Path: {did_info['path']}")              # "agents/my-agent"
        print(f"Document URL: {did_info['document_url']}")  # "https://registry.capisc.io/agents/my-agent/did.json"
```

### 3. TrustStoreService - Manage Trusted CA Keys

```python
with CapiscioRPCClient() as client:
    # Add trusted CA key
    kid, error = client.trust.add_key(
        did="did:web:registry.capisc.io",
        public_key=b'{"kty":"OKP",...}',
        format="JWK"
    )

    print(f"Added key: {kid}")
```

### 4. RevocationService - Check Revocation Status

```python
with CapiscioRPCClient() as client:
    # Check if badge is revoked
    is_revoked = client.revocation.is_revoked("badge-jti-12345")

    if is_revoked:
        print("⚠️ Badge has been revoked!")
```

### 5. ScoringService - Agent Card Scoring

```python
with CapiscioRPCClient() as client:
    # Score an agent card
    result, error = client.scoring.score_agent_card(agent_card_json)

    if result:
        print(f"Overall Score: {result['overall_score']}/100")
        print(f"Compliance: {result['compliance_score']}/100")
        print(f"Trust: {result['trust_score']}/100")
        print(f"Availability: {result['availability_score']}/100")

    # Validate a specific rule
    rule_result, error = client.scoring.validate_rule("rule-001", agent_card_json)

    # List available rule sets
    rule_sets, error = client.scoring.list_rule_sets()

    # Get specific rule set
    rule_set, error = client.scoring.get_rule_set("default")

    # Aggregate multiple scores
    aggregated, error = client.scoring.aggregate_scores(
        results=[
            {"overall_score": 85},
            {"overall_score": 90},
            {"overall_score": 88}
        ],
        method="average"  # or "min", "max"
    )
```

### 6. SimpleGuardService - JWS Signing & Verification

```python
with CapiscioRPCClient() as client:
    # Sign a payload
    signature, error = client.simpleguard.sign(
        payload=b"important message",
        key_id="my-key-1"
    )

    # Verify a signature
    valid, payload, error = client.simpleguard.verify(
        signature=signature,
        expected_payload=b"important message",
        public_key_jwk='{"kty":"OKP",...}'
    )

    # Sign with attached payload (JWS Compact)
    jws, error = client.simpleguard.sign_attached(
        payload=b"message",
        key_id="my-key-1"
    )

    # Verify attached signature
    valid, payload, error = client.simpleguard.verify_attached(
        jws=jws,
        public_key_jwk='{"kty":"OKP",...}'
    )

    # Get key information
    key_info, error = client.simpleguard.get_key_info("my-key-1")
```

### 7. RegistryService - Fetch Agent Cards

```python
with CapiscioRPCClient() as client:
    # Get agent card by DID
    agent_card, error = client.registry.get_agent(
        did="did:web:registry.capisc.io:agents:my-agent"
    )

    if agent_card:
        print(f"Agent Name: {agent_card['name']}")
        print(f"URL: {agent_card['url']}")
```

### Process Manager

The SDK includes automatic process management for the `capiscio-core` gRPC server:

```python
from capiscio_sdk._rpc.process import get_process_manager

# Get singleton process manager
pm = get_process_manager()

# Ensure server is running (auto-starts if needed)
address = pm.ensure_running(timeout=10.0)
print(f"gRPC server running at: {address}")

# Manually start server
pm.start()

# Stop server
pm.stop()

# Check if running
if pm.is_running():
    print("Server is running")
```

**Auto-Start Behavior:**
- ✅ Automatically downloads `capiscio-core` binary if not found
- ✅ Starts on Unix socket by default (`~/.capiscio/rpc.sock`)
- ✅ Handles server crashes and restarts
- ✅ Cleans up on process exit

## How It Works

### 1. The Handshake
CapiscIO enforces the **A2A Trust Protocol**:
*   **Sender**: Signs the request body (JWS + Body Hash).
*   **Receiver**: Verifies the signature and re-hashes the body to ensure integrity.

### 2. The "Customs Officer"
The `SimpleGuard` acts as a local authority. It manages your agent's "Passport" (Agent Card) and verifies the "Visas" (Tokens) of incoming requests.

### 3. Go Core Integration
The SDK delegates validation to `capiscio-core` (Go) via gRPC for:
*   **Consistent behavior** across all CapiscIO SDKs
*   **High performance** validation (Go's speed + Python's flexibility)
*   **Single source of truth** for validation rules

### 4. Telemetry
Every response includes a `Server-Timing` header showing exactly how fast the verification was:
```http
Server-Timing: capiscio-auth;dur=0.618;desc="CapiscIO Verification"
```

## Documentation

- [Official Documentation](https://docs.capisc.io)
- [A2A Protocol Spec](https://github.com/google/A2A)

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.
