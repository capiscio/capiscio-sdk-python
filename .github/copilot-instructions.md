# capiscio-sdk-python - GitHub Copilot Instructions

## 🛑 ABSOLUTE RULES - NO EXCEPTIONS

These rules are non-negotiable. Violating them will cause production issues.

### 1. ALL WORK VIA PULL REQUESTS
- **NEVER commit directly to `main`.** All changes MUST go through PRs.
- Create feature branches: `feature/`, `fix/`, `chore/`
- PRs require CI to pass before merge consideration

### 2. LOCAL CI VALIDATION BEFORE PUSH
- **ALL tests MUST pass locally before pushing to a PR.**
- Run: `pytest -v`
- If tests fail locally, fix them before pushing. Never push failing code.

### 3. RFCs ARE READ-ONLY
- **DO NOT modify RFCs without explicit team authorization.**
- Implementation must conform to RFCs in `capiscio-rfcs/`

### 4. NO WATCH/BLOCKING COMMANDS
- **NEVER run blocking commands** without timeout
- Use `timeout` wrapper for long-running commands

---

## Repository Purpose

**capiscio-sdk-python** is the official Python SDK for CapiscIO, providing:
- SimpleGuard: Runtime badge verification middleware
- gRPC Client: Interface to capiscio-core gRPC services
- Badge verification utilities
- DID resolution helpers

**Technology Stack**: Python 3.9+, gRPC, cryptography, FastAPI/Flask integration

## Architecture

```
capiscio_sdk/
├── __init__.py
├── simple_guard.py          # Middleware for FastAPI/Flask
├── grpc_client.py           # gRPC client for capiscio-core
├── badge_verifier.py        # Badge verification logic
├── did_resolver.py          # DID resolution
├── models.py                # Data models
└── exceptions.py            # Custom exceptions
```

## Critical Development Rules

### 1. SimpleGuard Middleware

**FastAPI Integration:**
```python
from fastapi import FastAPI, HTTPException, Request
from capiscio_sdk import SimpleGuard, BadgeVerificationError

app = FastAPI()

# Initialize SimpleGuard
guard = SimpleGuard(
    issuer_url="https://registry.capisc.io",
    min_trust_level=1,  # Don't accept self-signed
    cache_ttl=300,      # 5 minutes
)

@app.middleware("http")
async def verify_badge_middleware(request: Request, call_next):
    # Skip health checks
    if request.url.path == "/health":
        return await call_next(request)
    
    # Extract badge from header
    badge_token = request.headers.get("X-CapiscIO-Badge")
    if not badge_token:
        raise HTTPException(status_code=401, detail="Missing badge")
    
    # Verify badge
    try:
        badge = await guard.verify(badge_token)
        request.state.badge = badge
        request.state.agent_did = badge.subject
    except BadgeVerificationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    
    return await call_next(request)

@app.get("/protected")
async def protected_route(request: Request):
    agent_did = request.state.agent_did
    return {"message": f"Hello {agent_did}"}
```

**Flask Integration:**
```python
from flask import Flask, request, g, jsonify
from capiscio_sdk import SimpleGuard, BadgeVerificationError

app = Flask(__name__)

guard = SimpleGuard(
    issuer_url="https://registry.capisc.io",
    min_trust_level=1,
)

@app.before_request
def verify_badge():
    # Skip health checks
    if request.path == "/health":
        return None
    
    # Extract badge
    badge_token = request.headers.get("X-CapiscIO-Badge")
    if not badge_token:
        return jsonify({"error": "Missing badge"}), 401
    
    # Verify badge
    try:
        badge = guard.verify_sync(badge_token)
        g.badge = badge
        g.agent_did = badge.subject
    except BadgeVerificationError as e:
        return jsonify({"error": str(e)}), 401

@app.route("/protected")
def protected_route():
    return jsonify({"message": f"Hello {g.agent_did}"})
```

### 2. gRPC Client Usage

**Initialize Client:**
```python
from capiscio_sdk import CapiscioGRPCClient

# Connect to capiscio-core gRPC server
client = CapiscioGRPCClient(
    address="localhost:50051",
    secure=False,  # Use TLS in production
)
```

**Badge Verification:**
```python
from capiscio_sdk.grpc_client import VerifyBadgeRequest

# Verify badge via gRPC
request = VerifyBadgeRequest(
    token="eyJhbGc...",
    issuer_url="https://registry.capisc.io",
)

response = client.verify_badge(request)

if response.valid:
    print(f"Badge valid for {response.badge.subject}")
    print(f"Trust level: {response.badge.trust_level}")
else:
    print(f"Badge invalid: {response.error}")
```

**DID Resolution:**
```python
from capiscio_sdk.grpc_client import ResolveDIDRequest

request = ResolveDIDRequest(
    did="did:web:registry.capisc.io:agents:my-agent"
)

response = client.resolve_did(request)

if response.success:
    print(f"Public key: {response.did_document.verification_method[0].public_key_jwk}")
else:
    print(f"Resolution failed: {response.error}")
```

**Gateway Validation:**
```python
from capiscio_sdk.grpc_client import ValidateGatewayRequest

# Validate incoming request at gateway
request = ValidateGatewayRequest(
    badge_token="eyJhbGc...",
    target_url="https://agent.example.com/endpoint",
    min_trust_level=1,
)

response = client.validate_gateway(request)

if response.allowed:
    print(f"Request allowed for agent: {response.agent_did}")
else:
    print(f"Request denied: {response.reason}")
```

### 3. Badge Verification Logic

**Core Verification Function:**
```python
import jwt
import requests
from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

class BadgeVerifier:
    def __init__(self, issuer_url: str, min_trust_level: int = 1):
        self.issuer_url = issuer_url
        self.min_trust_level = min_trust_level
        self._jwks_cache: Dict[str, Any] = {}
    
    async def verify(self, token: str) -> Badge:
        # Step 1: Parse token
        unverified_claims = jwt.decode(
            token,
            options={"verify_signature": False}
        )
        
        # Step 2: Fetch JWKS
        jwks = await self._fetch_jwks(unverified_claims["iss"])
        
        # Step 3: Verify signature
        try:
            claims = jwt.decode(
                token,
                key=jwks,
                algorithms=["EdDSA"],
                options={"verify_signature": True}
            )
        except jwt.InvalidSignatureError:
            raise BadgeVerificationError("Invalid signature")
        
        # Step 4: Validate claims
        self._validate_claims(claims)
        
        # Step 5: Create badge object
        return Badge.from_claims(claims)
    
    async def _fetch_jwks(self, issuer: str) -> Dict[str, Any]:
        # Check cache
        if issuer in self._jwks_cache:
            return self._jwks_cache[issuer]
        
        # Fetch from issuer
        jwks_url = f"{issuer}/.well-known/jwks.json"
        response = requests.get(jwks_url, timeout=5)
        response.raise_for_status()
        
        jwks = response.json()
        self._jwks_cache[issuer] = jwks
        
        return jwks
    
    def _validate_claims(self, claims: Dict[str, Any]) -> None:
        # Check required claims
        required = ["iss", "sub", "jti", "exp", "iat", "trust_level"]
        for claim in required:
            if claim not in claims:
                raise BadgeVerificationError(f"Missing claim: {claim}")
        
        # Check expiration
        if claims["exp"] < time.time():
            raise BadgeVerificationError("Badge expired")
        
        # Check trust level
        if claims["trust_level"] < self.min_trust_level:
            raise BadgeVerificationError(
                f"Trust level {claims['trust_level']} below minimum {self.min_trust_level}"
            )
        
        # Check DID format
        if not claims["sub"].startswith("did:"):
            raise BadgeVerificationError("Invalid DID format")
```

### 4. Data Models

**Badge Model:**
```python
from dataclasses import dataclass
from typing import Optional
from datetime import datetime

@dataclass
class Badge:
    issuer: str
    subject: str  # Agent DID
    token_id: str
    expires_at: datetime
    issued_at: datetime
    not_before: Optional[datetime]
    trust_level: int
    ial: Optional[int] = None
    cnf: Optional[dict] = None
    
    @classmethod
    def from_claims(cls, claims: dict) -> "Badge":
        return cls(
            issuer=claims["iss"],
            subject=claims["sub"],
            token_id=claims["jti"],
            expires_at=datetime.fromtimestamp(claims["exp"]),
            issued_at=datetime.fromtimestamp(claims["iat"]),
            not_before=datetime.fromtimestamp(claims["nbf"]) if "nbf" in claims else None,
            trust_level=claims["trust_level"],
            ial=claims.get("ial"),
            cnf=claims.get("cnf"),
        )
    
    @property
    def is_expired(self) -> bool:
        return datetime.now() > self.expires_at
    
    @property
    def is_ial1(self) -> bool:
        return self.ial == 1 and self.cnf is not None
```

### 5. Exception Handling

**Custom Exceptions:**
```python
class BadgeVerificationError(Exception):
    """Raised when badge verification fails"""
    pass

class DIDResolutionError(Exception):
    """Raised when DID resolution fails"""
    pass

class GRPCConnectionError(Exception):
    """Raised when gRPC connection fails"""
    pass
```

**Usage:**
```python
try:
    badge = await guard.verify(token)
except BadgeVerificationError as e:
    logger.error(f"Badge verification failed: {e}")
    raise HTTPException(status_code=401, detail=str(e))
except Exception as e:
    logger.exception("Unexpected error during verification")
    raise HTTPException(status_code=500, detail="Internal server error")
```

## Testing

### Unit Tests
```python
import pytest
from capiscio_sdk import BadgeVerifier, BadgeVerificationError

@pytest.mark.asyncio
async def test_verify_valid_badge():
    verifier = BadgeVerifier(
        issuer_url="https://registry.capisc.io",
        min_trust_level=1
    )
    
    token = generate_test_badge()  # Helper function
    
    badge = await verifier.verify(token)
    
    assert badge.trust_level >= 1
    assert badge.subject.startswith("did:")

@pytest.mark.asyncio
async def test_verify_expired_badge():
    verifier = BadgeVerifier(
        issuer_url="https://registry.capisc.io",
        min_trust_level=1
    )
    
    token = generate_expired_badge()
    
    with pytest.raises(BadgeVerificationError, match="expired"):
        await verifier.verify(token)
```

### Integration Tests
```python
@pytest.mark.integration
def test_grpc_client_verify_badge():
    client = CapiscioGRPCClient(address="localhost:50051")
    
    request = VerifyBadgeRequest(token=test_token)
    response = client.verify_badge(request)
    
    assert response.valid
    assert response.badge.trust_level >= 1
```

## Common Development Tasks

### Installing
```bash
# Install in development mode
pip install -e .

# Install with all extras
pip install -e ".[dev,grpc]"
```

### Running Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=capiscio_sdk --cov-report=html

# Run specific test
pytest tests/test_simple_guard.py -v
```

### Type Checking
```bash
# Run mypy
mypy capiscio_sdk/

# Run with strict mode
mypy --strict capiscio_sdk/
```

### Linting
```bash
# Run ruff
ruff check capiscio_sdk/

# Auto-fix
ruff check --fix capiscio_sdk/

# Format
ruff format capiscio_sdk/
```

## Code Quality Standards

### 1. Type Hints
```python
# ✅ Use type hints
async def verify(self, token: str) -> Badge:
    pass

# ❌ No type hints
async def verify(self, token):
    pass
```

### 2. Docstrings
```python
def verify_sync(self, token: str) -> Badge:
    """Verify a badge synchronously.
    
    Args:
        token: The JWS badge token
        
    Returns:
        Badge: The verified badge object
        
    Raises:
        BadgeVerificationError: If verification fails
    """
    pass
```

### 3. Async/Await
```python
# ✅ Use async for I/O operations
async def fetch_jwks(self, issuer: str) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{issuer}/.well-known/jwks.json") as response:
            return await response.json()

# Also provide sync version for compatibility
def fetch_jwks_sync(self, issuer: str) -> dict:
    response = requests.get(f"{issuer}/.well-known/jwks.json")
    return response.json()
```

## Common Pitfalls

1. **Don't skip signature verification** - Always verify JWS
2. **Don't accept self-signed badges in production** - Set min_trust_level >= 1
3. **Don't cache badges forever** - Implement TTL
4. **Don't ignore exceptions** - Handle verification errors properly
5. **Don't log sensitive data** - Redact tokens in logs

## Environment Variables

```bash
# gRPC Client
CAPISCIO_GRPC_ADDRESS="localhost:50051"
CAPISCIO_GRPC_SECURE="false"

# Badge Verification
CAPISCIO_ISSUER_URL="https://registry.capisc.io"
CAPISCIO_MIN_TRUST_LEVEL="1"
CAPISCIO_CACHE_TTL="300"
```

## References

- gRPC documentation: 225 lines in docs/grpc-integration.md
- Badge verification: docs/badge-verification.md
- DID resolution: docs/did-resolution.md
- RFC-002: https://github.com/capiscio/capiscio-rfcs/blob/main/docs/002-trust-badge.md
- RFC-003: https://github.com/capiscio/capiscio-rfcs/blob/main/docs/003-key-ownership-proof.md
