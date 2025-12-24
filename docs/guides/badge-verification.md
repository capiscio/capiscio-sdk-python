# Badge Verification Guide

This guide covers how to verify Trust Badges using the CapiscIO SDK. Trust Badges are JWS tokens that provide verifiable identity for AI agents, as specified in RFC-002.

## Quick Start

```python
from capiscio_sdk.badge import verify_badge, parse_badge

# Verify a badge with full validation
result = verify_badge(
    token,
    trusted_issuers=["https://registry.capisc.io"],
    audience="https://my-service.example.com",
)

if result.valid:
    print(f"Agent {result.claims.agent_id} verified")
    print(f"Trust level: {result.claims.trust_level}")
else:
    print(f"Verification failed: {result.error}")
```

## Core Concepts

### Trust Levels

Badges include a **Trust Level** claim indicating verification depth:

| Level | Name | Description |
|-------|------|-------------|
| 0 | SS (Self-Signed) | No external validation (development only) |
| 1 | DV (Domain Validated) | Domain ownership verified |
| 2 | OV (Organization Validated) | Organization identity verified |
| 3 | EV (Extended Validation) | Extended identity verification |
| 4 | CV (Community Vouched) | Peer attestations verified |

```python
from capiscio_sdk.badge import TrustLevel

# Access trust level from claims
if result.claims.trust_level == TrustLevel.LEVEL_2:
    print("Organization-validated agent")
```

### Verification Modes

Three modes control how verification is performed:

```python
from capiscio_sdk.badge import verify_badge, VerifyMode

# Online: Real-time checks against registry (default)
result = verify_badge(token, mode=VerifyMode.ONLINE)

# Offline: Use local trust store only
result = verify_badge(token, mode=VerifyMode.OFFLINE)

# Hybrid: Online with fallback to cache
result = verify_badge(token, mode=VerifyMode.HYBRID)
```

## Verification API

### verify_badge()

Full RFC-002 verification including signature, claims, revocation, and agent status.

```python
from capiscio_sdk.badge import verify_badge, VerifyMode

result = verify_badge(
    token,
    trusted_issuers=["https://registry.capisc.io"],  # Required in production
    audience="https://my-service.example.com",        # Your service URL
    mode=VerifyMode.ONLINE,                           # Verification mode
    skip_revocation_check=False,                      # Testing only
    skip_agent_status_check=False,                    # Testing only
    public_key_jwk=None,                              # Override for offline
)

if result.valid:
    claims = result.claims
    print(f"Agent: {claims.agent_id}")
    print(f"Domain: {claims.domain}")
    print(f"Trust Level: {claims.trust_level}")
    print(f"Expires: {claims.expires_at}")
else:
    print(f"Error: {result.error}")
    print(f"Error Code: {result.error_code}")
```

### Using VerifyOptions

For more complex configurations, use `VerifyOptions`:

```python
from capiscio_sdk.badge import verify_badge, VerifyOptions, VerifyMode

options = VerifyOptions(
    mode=VerifyMode.HYBRID,
    trusted_issuers=["https://registry.capisc.io"],
    audience="https://api.example.com",
    skip_revocation_check=False,
    skip_agent_status_check=False,
    public_key_jwk=None,
)

result = verify_badge(token, options=options)
```

### parse_badge()

Parse badge claims without verification (for inspection):

```python
from capiscio_sdk.badge import parse_badge

claims = parse_badge(token)
print(f"Issuer: {claims.issuer}")
print(f"Subject: {claims.subject}")
print(f"Agent ID: {claims.agent_id}")
print(f"Domain: {claims.domain}")
print(f"Issued: {claims.issued_at}")
print(f"Expires: {claims.expires_at}")
print(f"Expired: {claims.is_expired}")
```

## Error Handling

Verification returns structured errors with RFC-002 error codes:

```python
from capiscio_sdk.badge import verify_badge

result = verify_badge(token)

if not result.valid:
    match result.error_code:
        case "BADGE_MALFORMED":
            print("Token is not a valid JWT/JWS")
        case "BADGE_SIGNATURE_INVALID":
            print("Signature verification failed")
        case "BADGE_EXPIRED":
            print("Badge has expired")
        case "BADGE_NOT_YET_VALID":
            print("Badge not yet valid (iat in future)")
        case "BADGE_ISSUER_UNTRUSTED":
            print("Issuer not in trusted list")
        case "BADGE_AUDIENCE_MISMATCH":
            print("Audience doesn't match")
        case "BADGE_REVOKED":
            print("Badge has been revoked")
        case "BADGE_CLAIMS_INVALID":
            print("Required claims missing or invalid")
        case "BADGE_AGENT_DISABLED":
            print("Agent has been disabled")
        case _:
            print(f"Unknown error: {result.error}")
```

## BadgeClaims Reference

The `BadgeClaims` dataclass provides access to all badge claims:

| Field | Type | Description |
|-------|------|-------------|
| `jti` | `str` | Unique badge identifier (UUID) |
| `issuer` | `str` | Badge issuer URL (CA) |
| `subject` | `str` | Agent DID (did:web format) |
| `audience` | `List[str]` | Intended audience URLs |
| `issued_at` | `datetime` | When the badge was issued |
| `expires_at` | `datetime` | When the badge expires |
| `trust_level` | `TrustLevel` | Trust level (1=DV, 2=OV, 3=EV) |
| `domain` | `str` | Agent's verified domain |
| `agent_name` | `str` | Human-readable agent name |

**Properties:**

| Property | Type | Description |
|----------|------|-------------|
| `agent_id` | `str` | Extracted agent ID from subject DID |
| `is_expired` | `bool` | Whether the badge has expired |
| `is_not_yet_valid` | `bool` | Whether the badge is not yet valid |

## Production Checklist

1. **Always specify trusted_issuers** - Don't accept badges from unknown CAs
2. **Set audience** - Verify badges are intended for your service
3. **Use ONLINE or HYBRID mode** - Check revocation status
4. **Reject self-signed in production** - Level 0 badges are for development only
5. **Log verification failures** - Track security events
6. **Handle errors gracefully** - Don't expose internal details

```python
def verify_agent_badge(token: str) -> bool:
    """Production badge verification."""
    result = verify_badge(
        token,
        trusted_issuers=["https://registry.capisc.io"],
        audience="https://api.myservice.com",
        mode=VerifyMode.HYBRID,
    )
    
    if not result.valid:
        logger.warning(f"Badge verification failed: {result.error_code}")
        return False
    
    # Reject self-signed in production
    if result.claims.trust_level.value == "0":
        logger.warning("Rejected self-signed badge")
        return False
    
    logger.info(f"Verified agent: {result.claims.agent_id}")
    return True
```

## Development & Testing

For development, you can use self-signed badges:

```python
# Accept self-signed for local development
result = verify_badge(
    token,
    mode=VerifyMode.OFFLINE,
    skip_revocation_check=True,
    skip_agent_status_check=True,
)
```

> ⚠️ **Warning**: Never use these options in production!

## See Also

- [RFC-002 Trust Badge Specification](https://docs.capisc.io/rfcs/002-trust-badge/)
- [API Reference](../api-reference.md)
- [Configuration Guide](./configuration.md)
