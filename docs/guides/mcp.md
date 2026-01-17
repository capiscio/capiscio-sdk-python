# MCP Security Integration

**Model Context Protocol (MCP) integration for validating tool access and server identity.**

The CapiscIO Python SDK provides security middleware for MCP tools, implementing:

- **RFC-006**: Tool access evaluation based on trust levels
- **RFC-007**: Server identity verification via trust badges

## Installation

The MCP module requires the `mcp` extra:

```bash
pip install capiscio-sdk[mcp]
```

## Quick Start

### Evaluate Tool Access (RFC-006)

Before allowing a tool to execute, evaluate whether the calling server has sufficient trust:

```python
from capiscio_sdk.mcp import evaluate_tool_access, TrustLevel, DenyReason

# Evaluate whether a server can access a tool
result = evaluate_tool_access(
    tool_name="file_read",
    server_endpoint="https://agent.example.com",
    trust_level=TrustLevel.VERIFIED
)

if result.allow:
    # Proceed with tool execution
    print(f"Access granted with trust level: {result.trust_level}")
else:
    # Handle denial
    print(f"Access denied: {result.deny_reason}")
```

### Verify Server Identity (RFC-007)

Verify that an MCP server has a valid trust badge:

```python
from capiscio_sdk.mcp import verify_server_identity, ServerState

result = verify_server_identity(
    server_endpoint="https://mcp-server.example.com",
    expected_did="did:web:example.com"  # Optional
)

if result.state == ServerState.VERIFIED:
    print(f"Server verified! DID: {result.did}")
    print(f"Trust badge: {result.badge_jws}")
else:
    print(f"Verification failed: {result.state}")
```

---

## Core Functions

### `evaluate_tool_access()`

Evaluates whether a tool access request should be allowed based on the server's trust level.

```python
def evaluate_tool_access(
    tool_name: str,
    server_endpoint: str,
    trust_level: TrustLevel,
    required_level: TrustLevel = TrustLevel.REGISTERED,
    tool_policy: ToolPolicy | None = None,
) -> ToolAccessResult:
    """
    Evaluate tool access based on trust level.
    
    Args:
        tool_name: Name of the tool being accessed
        server_endpoint: URL of the requesting MCP server
        trust_level: Current trust level of the server
        required_level: Minimum trust level required (default: REGISTERED)
        tool_policy: Optional custom policy for this tool
    
    Returns:
        ToolAccessResult with allow/deny decision and metadata
    """
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tool_name` | `str` | ✅ | Name of the tool being accessed |
| `server_endpoint` | `str` | ✅ | URL of the requesting MCP server |
| `trust_level` | `TrustLevel` | ✅ | Server's current trust level |
| `required_level` | `TrustLevel` | ❌ | Minimum required trust (default: `REGISTERED`) |
| `tool_policy` | `ToolPolicy` | ❌ | Custom access policy for this tool |

#### Return Value

`ToolAccessResult` with the following attributes:

```python
@dataclass
class ToolAccessResult:
    allow: bool                    # Whether access is granted
    trust_level: TrustLevel        # Effective trust level
    deny_reason: DenyReason | None # Reason if denied
    tool_name: str                 # Tool that was evaluated
    server_endpoint: str           # Server that requested access
    evaluated_at: datetime         # When evaluation occurred
```

---

### `verify_server_identity()`

Verifies an MCP server's identity through its trust badge.

```python
def verify_server_identity(
    server_endpoint: str,
    expected_did: str | None = None,
    timeout: float = 10.0,
    verify_tls: bool = True,
) -> ServerIdentityResult:
    """
    Verify server identity via trust badge.
    
    Args:
        server_endpoint: MCP server URL to verify
        expected_did: Optional expected DID for binding verification
        timeout: Request timeout in seconds
        verify_tls: Whether to verify TLS certificates
    
    Returns:
        ServerIdentityResult with verification state and badge data
    """
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `server_endpoint` | `str` | ✅ | MCP server URL to verify |
| `expected_did` | `str` | ❌ | Expected DID for binding check |
| `timeout` | `float` | ❌ | Request timeout (default: 10.0s) |
| `verify_tls` | `bool` | ❌ | Verify TLS certs (default: `True`) |

#### Return Value

`ServerIdentityResult` with the following attributes:

```python
@dataclass
class ServerIdentityResult:
    state: ServerState           # Verification result state
    server_endpoint: str         # Server that was verified
    did: str | None              # Resolved DID (if verified)
    badge_jws: str | None        # Raw badge JWS (if retrieved)
    badge_payload: dict | None   # Decoded badge payload
    error: str | None            # Error message (if failed)
    verified_at: datetime        # When verification occurred
```

---

### `parse_server_identity_http()`

Extract server identity from HTTP response headers.

```python
def parse_server_identity_http(
    headers: dict[str, str]
) -> ServerIdentity | None:
    """
    Parse server identity from HTTP headers.
    
    Looks for:
    - X-CapiscIO-Badge: JWS trust badge
    - X-CapiscIO-DID: Server DID
    
    Args:
        headers: HTTP response headers
    
    Returns:
        ServerIdentity if badge found, None otherwise
    """
```

#### Example

```python
import httpx
from capiscio_sdk.mcp import parse_server_identity_http

response = httpx.get("https://mcp-server.example.com/health")
identity = parse_server_identity_http(dict(response.headers))

if identity:
    print(f"Server DID: {identity.did}")
    print(f"Badge issued: {identity.badge_issued_at}")
```

---

### `parse_server_identity_jsonrpc()`

Extract server identity from JSON-RPC response metadata.

```python
def parse_server_identity_jsonrpc(
    response: dict
) -> ServerIdentity | None:
    """
    Parse server identity from JSON-RPC response.
    
    Looks for identity in:
    - response["_meta"]["capiscio"]
    - response["result"]["_meta"]["capiscio"]
    
    Args:
        response: JSON-RPC response dict
    
    Returns:
        ServerIdentity if found, None otherwise
    """
```

#### Example

```python
from capiscio_sdk.mcp import parse_server_identity_jsonrpc

# JSON-RPC response with embedded identity
response = {
    "jsonrpc": "2.0",
    "id": 1,
    "result": {...},
    "_meta": {
        "capiscio": {
            "did": "did:web:example.com",
            "badge": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9..."
        }
    }
}

identity = parse_server_identity_jsonrpc(response)
if identity:
    print(f"Verified server: {identity.did}")
```

---

## Types Reference

### TrustLevel

Trust levels in ascending order of privilege:

```python
class TrustLevel(str, Enum):
    UNKNOWN = "unknown"           # No trust information
    REGISTERED = "registered"     # Basic registration only
    VERIFIED = "verified"         # Identity verified
    AUDITED = "audited"          # Security audit passed
    CERTIFIED = "certified"      # Full certification
```

### DenyReason

Reasons for access denial:

```python
class DenyReason(str, Enum):
    INSUFFICIENT_TRUST = "insufficient_trust"  # Trust level too low
    EXPIRED_BADGE = "expired_badge"            # Badge has expired
    REVOKED_BADGE = "revoked_badge"            # Badge was revoked
    INVALID_SIGNATURE = "invalid_signature"    # Badge signature invalid
    POLICY_VIOLATION = "policy_violation"      # Tool policy not satisfied
    UNKNOWN_SERVER = "unknown_server"          # Server not recognized
```

### ServerState

Server verification states:

```python
class ServerState(str, Enum):
    VERIFIED = "verified"         # Successfully verified
    UNVERIFIED = "unverified"     # No badge found
    EXPIRED = "expired"           # Badge expired
    REVOKED = "revoked"           # Badge revoked
    INVALID = "invalid"           # Invalid badge data
    UNREACHABLE = "unreachable"   # Could not reach server
    TIMEOUT = "timeout"           # Request timed out
    ERROR = "error"               # Other error occurred
```

### ServerIdentity

Server identity information:

```python
@dataclass
class ServerIdentity:
    did: str                      # Server's DID
    badge_jws: str                # Raw JWS badge
    badge_issued_at: datetime     # When badge was issued
    badge_expires_at: datetime    # When badge expires
    trust_level: TrustLevel       # Server's trust level
```

### ToolPolicy

Custom tool access policies:

```python
@dataclass
class ToolPolicy:
    required_trust_level: TrustLevel   # Minimum trust required
    allowed_dids: list[str] | None     # Allowlist of DIDs
    blocked_dids: list[str] | None     # Blocklist of DIDs
    require_badge: bool                # Require valid badge
```

---

## Integration Patterns

### FastAPI Middleware

```python
from fastapi import FastAPI, Request, HTTPException
from capiscio_sdk.mcp import (
    verify_server_identity,
    parse_server_identity_http,
    ServerState
)

app = FastAPI()

@app.middleware("http")
async def mcp_security_middleware(request: Request, call_next):
    # Check for CapiscIO badge in headers
    identity = parse_server_identity_http(dict(request.headers))
    
    if identity:
        # Verify the badge
        result = verify_server_identity(
            server_endpoint=str(request.client.host),
            expected_did=identity.did
        )
        
        if result.state != ServerState.VERIFIED:
            raise HTTPException(
                status_code=403,
                detail=f"Server verification failed: {result.state}"
            )
        
        # Attach verified identity to request state
        request.state.mcp_identity = identity
    
    return await call_next(request)
```

### Tool Decorator

```python
from functools import wraps
from capiscio_sdk.mcp import evaluate_tool_access, TrustLevel

def require_trust(level: TrustLevel):
    """Decorator to require minimum trust level for tool access."""
    def decorator(func):
        @wraps(func)
        def wrapper(tool_name: str, server_endpoint: str, trust_level: TrustLevel, *args, **kwargs):
            result = evaluate_tool_access(
                tool_name=tool_name,
                server_endpoint=server_endpoint,
                trust_level=trust_level,
                required_level=level
            )
            
            if not result.allow:
                raise PermissionError(
                    f"Tool '{tool_name}' requires {level.value} trust, "
                    f"but server has {trust_level.value}: {result.deny_reason}"
                )
            
            return func(tool_name, server_endpoint, trust_level, *args, **kwargs)
        return wrapper
    return decorator

# Usage
@require_trust(TrustLevel.VERIFIED)
def sensitive_tool(tool_name: str, server_endpoint: str, trust_level: TrustLevel):
    """This tool requires VERIFIED trust level."""
    return {"result": "sensitive operation completed"}
```

### Async Verification

```python
import asyncio
from capiscio_sdk.mcp import verify_server_identity, ServerState

async def verify_servers(endpoints: list[str]) -> dict[str, ServerState]:
    """Verify multiple servers concurrently."""
    
    async def verify_one(endpoint: str) -> tuple[str, ServerState]:
        # verify_server_identity is sync, run in executor
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            verify_server_identity,
            endpoint
        )
        return endpoint, result.state
    
    tasks = [verify_one(ep) for ep in endpoints]
    results = await asyncio.gather(*tasks)
    
    return dict(results)

# Usage
async def main():
    servers = [
        "https://server1.example.com",
        "https://server2.example.com",
        "https://server3.example.com",
    ]
    
    states = await verify_servers(servers)
    for server, state in states.items():
        print(f"{server}: {state}")
```

---

## Best Practices

### 1. Cache Verification Results

Server identity verification involves network calls. Cache results appropriately:

```python
from functools import lru_cache
from datetime import datetime, timedelta

@lru_cache(maxsize=100)
def cached_verify(server_endpoint: str, cache_key: str) -> ServerIdentityResult:
    """Cache verification for 5 minutes using time-based cache key."""
    return verify_server_identity(server_endpoint)

def verify_with_cache(server_endpoint: str) -> ServerIdentityResult:
    # Generate cache key that expires every 5 minutes
    cache_key = datetime.now().strftime("%Y%m%d%H%M")[:-1]  # Truncate to 5min
    return cached_verify(server_endpoint, cache_key)
```

### 2. Fail Secure

Default to denying access when verification fails:

```python
def secure_tool_access(tool_name: str, server_endpoint: str) -> bool:
    try:
        result = verify_server_identity(server_endpoint)
        return result.state == ServerState.VERIFIED
    except Exception as e:
        # Log the error but default to DENY
        logger.error(f"Verification failed for {server_endpoint}: {e}")
        return False
```

### 3. Use Tool Policies for Sensitive Operations

```python
# Define policies for sensitive tools
TOOL_POLICIES = {
    "file_write": ToolPolicy(
        required_trust_level=TrustLevel.AUDITED,
        require_badge=True
    ),
    "execute_code": ToolPolicy(
        required_trust_level=TrustLevel.CERTIFIED,
        allowed_dids=["did:web:trusted-partner.com"],
        require_badge=True
    ),
    "read_config": ToolPolicy(
        required_trust_level=TrustLevel.VERIFIED,
        require_badge=True
    ),
}

def evaluate_with_policy(tool_name: str, server_endpoint: str, trust_level: TrustLevel):
    policy = TOOL_POLICIES.get(tool_name)
    return evaluate_tool_access(
        tool_name=tool_name,
        server_endpoint=server_endpoint,
        trust_level=trust_level,
        tool_policy=policy
    )
```

---

## Related Documentation

- [Badge Verification Guide](badge-verification.md) - Core badge verification patterns
- [Configuration Guide](configuration.md) - SDK configuration options
- [Scoring System](scoring.md) - Trust scoring methodology

## RFC References

- [RFC-006: MCP Tool Access Evaluation](/rfcs/rfc-006/)
- [RFC-007: MCP Server Identity Verification](/rfcs/rfc-007/)
