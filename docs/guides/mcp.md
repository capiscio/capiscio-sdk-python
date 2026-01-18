# MCP Service Client (Low-Level gRPC)

**Low-level gRPC client for MCP security operations via capiscio-core.**

The CapiscIO Python SDK provides access to MCP security operations (RFC-006 Tool Authority
and RFC-007 Server Identity) through the `MCPClient` gRPC wrapper.

!!! note "Looking for high-level MCP integration?"
    This guide documents the **low-level gRPC API** for direct capiscio-core access.
    
    For a high-level MCP integration library with decorators like `@guard`, see the
    **[capiscio-mcp-python](https://github.com/capiscio/capiscio-mcp-python)** package:
    
    ```bash
    pip install capiscio-mcp
    ```

## Overview

The SDK's `MCPClient` provides direct access to capiscio-core's MCPService gRPC methods:

- **`evaluate_tool_access()`** - RFC-006 §6.2-6.4: Evaluate tool access and emit evidence
- **`verify_server_identity()`** - RFC-007 §7.2: Verify server identity from DID + badge  
- **`parse_server_identity_http()`** - RFC-007 §5.2: Extract identity from HTTP headers
- **`parse_server_identity_jsonrpc()`** - RFC-007 §5.3: Extract identity from JSON-RPC _meta
- **`health()`** - Service health and version check

## Quick Start

```python
from capiscio_sdk._rpc.client import CapiscioRPCClient

# Connect to capiscio-core gRPC server
client = CapiscioRPCClient(address="localhost:50051")
client.connect()

try:
    # Check service health
    health = client.mcp.health()
    print(f"MCP service: {health['core_version']}")

    # Evaluate tool access (RFC-006)
    result = client.mcp.evaluate_tool_access(
        tool_name="read_file",
        params_hash="sha256:abc123",
        server_origin="https://example.com",
        badge_jws=badge_token,  # Caller's badge
        min_trust_level=1,
    )
    
    if result["decision"] == "allow":
        print(f"Access granted for {result['agent_did']}")
    else:
        print(f"Access denied: {result['deny_reason']}")

finally:
    client.close()
```

---

## MCPClient Methods

### `evaluate_tool_access()`

Evaluate tool access request (RFC-006 §6.2-6.4). Returns both a decision and evidence record atomically.

```python
result = client.mcp.evaluate_tool_access(
    tool_name="write_file",
    params_hash="sha256:...",        # Hash of tool parameters for audit
    server_origin="https://...",      # MCP server origin
    badge_jws=badge_token,            # Caller's badge (or use api_key)
    # api_key="...",                  # Alternative: API key auth
    min_trust_level=2,                # Minimum required trust (0-4)
    accept_level_zero=False,          # Accept self-signed badges?
    allowed_tools=["read_file", "write_file"],  # Optional allowlist
    trusted_issuers=["did:web:capiscio.io"],    # Trusted badge issuers
)
```

**Returns dict with:**

| Field | Type | Description |
|-------|------|-------------|
| `decision` | `str` | `"allow"` or `"deny"` |
| `deny_reason` | `str` | Reason if denied (e.g., `"trust_insufficient"`) |
| `deny_detail` | `str` | Detailed error message |
| `agent_did` | `str` | DID of authenticated agent |
| `badge_jti` | `str` | Badge JTI if badge was used |
| `auth_level` | `str` | `"anonymous"`, `"api_key"`, or `"badge"` |
| `trust_level` | `int` | Agent's trust level (0-4) |
| `evidence_json` | `str` | RFC-006 §7 evidence record |
| `evidence_id` | `str` | Unique evidence ID |
| `timestamp` | `str` | ISO timestamp |

### `verify_server_identity()`

Verify MCP server identity (RFC-007 §7.2). Checks DID + badge and transport origin binding.

```python
result = client.mcp.verify_server_identity(
    server_did="did:web:example.com:mcp:server",
    server_badge=badge_token,           # Server's badge JWT
    transport_origin="https://example.com",
    endpoint_path="/mcp",
    min_trust_level=1,
    accept_level_zero=False,
    offline_mode=False,                 # Use cache only?
    skip_origin_binding=False,          # Skip RFC-007 §5.3 check?
)
```

**Returns dict with:**

| Field | Type | Description |
|-------|------|-------------|
| `state` | `str` | `"verified_principal"`, `"declared_principal"`, or `"unverified_origin"` |
| `trust_level` | `int` | Server's trust level (0-4) |
| `server_did` | `str` | Verified server DID |
| `badge_jti` | `str` | Server badge JTI |
| `error_code` | `str` | Error code if verification failed |
| `error_detail` | `str` | Detailed error message |

### `parse_server_identity_http()`

Parse server identity from HTTP headers (RFC-007 §5.2).

```python
result = client.mcp.parse_server_identity_http(
    capiscio_server_did="did:web:example.com:server",
    capiscio_server_badge="eyJhbGc...",
)

if result["identity_present"]:
    # Verify the extracted identity
    verification = client.mcp.verify_server_identity(
        server_did=result["server_did"],
        server_badge=result["server_badge"],
        transport_origin="https://example.com",
    )
```

**Returns dict with:**

| Field | Type | Description |
|-------|------|-------------|
| `server_did` | `str` | Extracted server DID |
| `server_badge` | `str` | Extracted server badge |
| `identity_present` | `bool` | Whether identity was found |

### `parse_server_identity_jsonrpc()`

Parse server identity from JSON-RPC _meta (RFC-007 §5.3). For stdio transport.

```python
import json

meta = json.dumps({
    "_meta": {
        "serverDid": "did:web:example.com",
        "serverBadge": "eyJhbGc..."
    }
})

result = client.mcp.parse_server_identity_jsonrpc(meta_json=meta)
```

### `health()`

Check MCP service health and version compatibility.

```python
result = client.mcp.health(client_version="capiscio-sdk-python/1.0.0")

print(f"Healthy: {result['healthy']}")
print(f"Core version: {result['core_version']}")
print(f"Proto version: {result['proto_version']}")
print(f"Compatible: {result['version_compatible']}")
```

---

## Trust Levels (RFC-002 §5)

| Level | Name | Description |
|-------|------|-------------|
| 0 | Self-Signed | Development only, no verification |
| 1 | Registered | Basic registration with registry |
| 2 | Domain-Validated (DV) | Domain ownership verified |
| 3 | Organization-Validated (OV) | Organization identity verified |
| 4 | Extended-Validation (EV) | Full audit and certification |

---

## Deny Reasons

| Reason | Description |
|--------|-------------|
| `badge_missing` | No badge or API key provided |
| `badge_invalid` | Badge signature invalid |
| `badge_expired` | Badge has expired |
| `badge_revoked` | Badge was revoked |
| `trust_insufficient` | Trust level below minimum |
| `tool_not_allowed` | Tool not in allowed list |
| `issuer_untrusted` | Badge issuer not trusted |
| `policy_denied` | Custom policy denied access |

---

## Server States

| State | Description |
|-------|-------------|
| `verified_principal` | Server identity fully verified |
| `declared_principal` | DID declared but not fully verified |
| `unverified_origin` | Could not verify transport origin binding |

---

## Example: Full MCP Flow

```python
from capiscio_sdk._rpc.client import CapiscioRPCClient

def mcp_tool_handler(request, badge_token: str):
    """Handle an MCP tool call with security validation."""
    
    client = CapiscioRPCClient()
    client.connect()
    
    try:
        # 1. Evaluate tool access
        access = client.mcp.evaluate_tool_access(
            tool_name=request.tool_name,
            params_hash=hash_params(request.params),
            server_origin=request.origin,
            badge_jws=badge_token,
            min_trust_level=2,  # Require DV or higher
        )
        
        if access["decision"] != "allow":
            return {"error": access["deny_detail"]}
        
        # 2. Execute tool (access granted)
        result = execute_tool(request.tool_name, request.params)
        
        # 3. Return with evidence ID for audit trail
        return {
            "result": result,
            "_evidence_id": access["evidence_id"],
        }
        
    finally:
        client.close()
```

---

## Related Documentation

- [Badge Verification Guide](badge-verification.md) - Trust badge operations
- [Configuration Guide](configuration.md) - SDK configuration
- [API Reference](../api-reference.md#mcpclient-rfc-006--rfc-007) - Full MCPClient API

## High-Level Alternative

For high-level MCP integration with decorators and middleware, use **capiscio-mcp-python**:

```bash
pip install capiscio-mcp
```

```python
from capiscio_mcp import guard

@guard(min_trust_level=2)
async def my_tool(param: str) -> str:
    """This tool requires Trust Level 2+."""
    return f"Result: {param}"
```

See [capiscio-mcp documentation](https://docs.capiscio.io/mcp-python/) for details.
