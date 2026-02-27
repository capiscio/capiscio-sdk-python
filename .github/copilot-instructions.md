# capiscio-sdk-python - GitHub Copilot Instructions

## ABSOLUTE RULES - NO EXCEPTIONS

These rules are non-negotiable. Violating them will cause production issues.

### 1. ALL WORK VIA PULL REQUESTS
- **NEVER commit directly to `main`.** All changes MUST go through PRs.
- Create feature branches: `feature/`, `fix/`, `chore/`
- PRs require CI to pass before merge consideration

### 2. LOCAL CI VALIDATION BEFORE PUSH
- **ALL tests MUST pass locally before pushing to a PR.**
- Run: `.venv/bin/python -m pytest tests/unit -v`
- System Python may not have pytest — always use the project venv.
- If tests fail locally, fix them before pushing. Never push failing code.

### 3. RFCs ARE READ-ONLY
- **DO NOT modify RFCs without explicit team authorization.**
- Implementation must conform to RFCs in `capiscio-rfcs/`

### 4. NO WATCH/BLOCKING COMMANDS
- **NEVER run blocking commands** without timeout
- Use `timeout` wrapper for long-running commands

---

## CRITICAL: Read First

**Before starting work, read the workspace context files:**
1. `../../.context/CURRENT_SPRINT.md` - Sprint goals and priorities
2. `../../.context/ACTIVE_TASKS.md` - Active tasks (check for conflicts)
3. `../../.context/SESSION_LOG.md` - Recent session history

**After significant work, update:**
- `../../.context/ACTIVE_TASKS.md` - Update task status
- `../../.context/SESSION_LOG.md` - Log what was done

---

## Repository Purpose

**capiscio-sdk-python** is the official Python SDK for CapiscIO, providing:
- **CapiscIO.connect()** - "Let's Encrypt" style one-liner for agent identity (DID + badge + events)
- **SimpleGuard** - Message signing/verification via capiscio-core Go gRPC
- **CapiscioMiddleware** - FastAPI/Starlette ASGI middleware for badge verification + auto-events
- **EventEmitter** - Batched event emission to CapiscIO registry
- **BadgeKeeper** - Automatic badge renewal for continuous operation
- **Validators** - Agent Card, message, protocol, signature validation (CoreValidator uses Go core)
- **CapiscioSecurityExecutor** - A2A agent wrapper with validation, rate-limiting, caching

**Technology Stack**: Python 3.9+, gRPC (to capiscio-core Go binary), httpx, pydantic, cachetools

**Current Version**: v2.4.1
**Default Branch:** `main`

---

## Architecture

The SDK follows a **"Thin SDK + Core gRPC"** pattern. All cryptographic operations
(key generation, signing, DID derivation, badge verification) are performed by the
capiscio-core Go binary via gRPC, ensuring consistency across all language SDKs.

```
capiscio_sdk/
├── __init__.py              # Public API: secure(), SimpleGuard, SecurityConfig, errors, types
├── connect.py               # CapiscIO.connect() - one-liner agent identity setup
├── simple_guard.py          # SimpleGuard - message signing/verification via gRPC
├── events.py                # EventEmitter - batched event emission (10 events / 5s flush)
├── badge.py                 # Badge API - verify_badge(), get_badge(), issue helpers
├── badge_keeper.py          # BadgeKeeper - automatic badge renewal daemon thread
├── dv.py                    # Domain Validation badge orders (RFC-002 v1.2)
├── executor.py              # CapiscioSecurityExecutor - A2A agent wrapper
├── config.py                # SecurityConfig, DownstreamConfig, UpstreamConfig (pydantic)
├── errors.py                # CapiscioSecurityError, ValidationError, SignatureError, etc.
├── types.py                 # ValidationResult, ValidationIssue, ValidationSeverity (pydantic)
├── _rpc/
│   ├── client.py            # CapiscioRPCClient - gRPC wrapper for capiscio-core
│   ├── process.py           # ProcessManager - auto-downloads and manages the Go binary
│   └── gen/capiscio/v1/     # Generated protobuf stubs (simpleguard, badge, did, mcp, etc.)
├── integrations/
│   └── fastapi.py           # CapiscioMiddleware - ASGI middleware with auto-events
├── validators/
│   ├── __init__.py          # CoreValidator (Go-backed), MessageValidator, ProtocolValidator
│   ├── _core.py             # CoreValidator implementation (gRPC to Go)
│   ├── agent_card.py        # AgentCardValidator (DEPRECATED - use CoreValidator)
│   ├── certificate.py       # Certificate validation
│   ├── message.py           # A2A message structure validation
│   ├── protocol.py          # A2A protocol compliance validation
│   ├── semver.py            # Semantic version validation
│   ├── signature.py         # Signature validation
│   └── url_security.py      # URL and SSRF validation
├── scoring/                 # DEPRECATED - scoring now in Go core
│   ├── trust.py, availability.py, compliance.py, types.py
└── infrastructure/
    ├── cache.py             # TTL cache for validation results
    └── rate_limiter.py      # Rate limiting for downstream requests
```

### Key Architectural Decisions

1. **Crypto in Go, integration in Python** - All crypto ops go through `CapiscioRPCClient` → Go core gRPC.
   The Go binary is auto-downloaded by `ProcessManager` on first use.
2. **CoreValidator over pure Python** - `CoreValidator` delegates Agent Card validation to Go core.
   The old `AgentCardValidator` is deprecated.
3. **EventEmitter batching** - Events are queued and flushed in batches of 10 or every 5 seconds.
4. **Auto-events are opt-in** - `CapiscioMiddleware` emits request lifecycle events only when
   an `EventEmitter` instance is explicitly passed.

---

## Critical Development Rules

### 1. CapiscIO.connect() - Agent Identity Setup

```python
from capiscio_sdk.connect import CapiscIO

# One-liner: generates keys, derives DID, registers, gets badge
agent = CapiscIO.connect(api_key="sk_live_...")

print(agent.did)           # did:key:z6Mk...
print(agent.badge)         # Current JWS badge token (auto-renewed)
agent.emit("task_started", {"task_id": "123"})
```

### 2. SimpleGuard - Message Signing & Verification

```python
from capiscio_sdk import SimpleGuard

guard = SimpleGuard(dev_mode=True)  # or pass key_dir, registry_url
token = guard.sign_outbound({"sub": "test"}, body=b"hello")
claims = guard.verify_inbound(token, body=b"hello")
```

All crypto is delegated to Go core via `CapiscioRPCClient`.

### 3. CapiscioMiddleware - FastAPI/Starlette Integration

```python
from fastapi import FastAPI
from capiscio_sdk.integrations.fastapi import CapiscioMiddleware
from capiscio_sdk.events import EventEmitter

app = FastAPI()

# Without auto-events (badge verification only)
app.add_middleware(CapiscioMiddleware,
    issuer_url="https://registry.capisc.io",
    mode="enforce",              # "enforce" | "log"
    exclude_paths=["/health"],
)

# With auto-events (opt-in observability)
emitter = EventEmitter(
    server_url="https://registry.capisc.io",
    api_key="sk_live_...",
    agent_id="my-agent",
)
app.add_middleware(CapiscioMiddleware,
    issuer_url="https://registry.capisc.io",
    mode="enforce",
    exclude_paths=["/health"],
    emitter=emitter,             # Enables request_received/completed/failed events
)
```

Auto-events emitted: `request_received`, `request_completed`, `request_failed`,
`verification_success`, `verification_failed`.

### 4. EventEmitter - Batched Event Pipeline

```python
from capiscio_sdk.events import EventEmitter

emitter = EventEmitter(
    server_url="https://registry.capisc.io",
    api_key="sk_live_...",
    agent_id="my-agent-id",
    batch_size=10,       # Flush every 10 events
    flush_interval=5.0,  # Or every 5 seconds
)

emitter.emit("task_started", {"task_id": "123"})
emitter.emit("tool_call", {"tool": "search"})
emitter.flush()  # Force flush
emitter.close()  # Flush + stop background thread
```

Events go to `POST /v1/events` on the CapiscIO registry server.

### 5. CapiscioRPCClient - Go Core gRPC Interface

```python
from capiscio_sdk._rpc.client import CapiscioRPCClient

client = CapiscioRPCClient()  # Auto-starts Go binary via ProcessManager
# Services: SimpleGuardService, BadgeService, DIDService, MCPService,
#           TrustStoreService, RevocationService, ScoringService
```

**Never instantiate gRPC directly** — always use `CapiscioRPCClient` which handles
process lifecycle, port management, and health checks.

### 6. Error Hierarchy

```python
from capiscio_sdk.errors import (
    CapiscioSecurityError,       # Base
    CapiscioValidationError,     # Validation failures
    CapiscioSignatureError,      # Signature verification failures
    CapiscioRateLimitError,      # Rate limit exceeded
    CapiscioUpstreamError,       # Upstream agent errors
    ConfigurationError,          # Bad config / missing keys
    VerificationError,           # Badge/signature verification
)
```

---

## Testing

### Running Tests
```bash
# Unit tests only (fast, no external deps)
.venv/bin/python -m pytest tests/unit -v

# Full suite (includes integration tests that need Go core)
.venv/bin/python -m pytest -v

# Coverage
.venv/bin/python -m pytest tests/unit --cov=capiscio_sdk --cov-report=html

# Specific test
.venv/bin/python -m pytest tests/unit/test_fastapi_integration.py -v
```

### Test Structure
```
tests/
├── unit/
│   ├── test_events.py              # EventEmitter tests
│   ├── test_fastapi_integration.py # CapiscioMiddleware tests (incl auto-events)
│   ├── test_simple_guard.py        # SimpleGuard tests
│   ├── test_config.py              # Config tests
│   └── ...
├── integration/
│   ├── test_connect.py             # CapiscIO.connect() integration
│   ├── test_process.py             # Go binary process management
│   └── ...
└── conftest.py
```

### Installing
```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

---

## Environment Variables

```bash
# Connect / Registration
CAPISCIO_API_KEY="sk_live_..."
CAPISCIO_REGISTRY_URL="https://registry.capisc.io"

# SimpleGuard
CAPISCIO_KEY_DIR="~/.capiscio/keys"
CAPISCIO_DEV_MODE="true"

# Core binary (auto-managed)
CAPISCIO_CORE_BIN="/path/to/capiscio-core"   # Override auto-download
CAPISCIO_CORE_PORT="50051"                    # Override gRPC port
```

## Version Alignment

This SDK MUST stay aligned with:
- capiscio-core v2.4.0 (Go binary it wraps)
- capiscio-server v2.4.0 (registry API it calls)
- capiscio-python v2.4.0 (CLI wrapper that downloads core)
- capiscio-node v2.4.0 (JS CLI wrapper)

## Common Pitfalls

1. **Don't bypass Go core** - All crypto must go through `CapiscioRPCClient`, never implement locally
2. **Don't use system Python for tests** - Always use `.venv/bin/python -m pytest`
3. **Don't manually edit `_rpc/gen/`** - These are generated protobuf stubs
4. **Don't use deprecated `AgentCardValidator`** - Use `CoreValidator` instead
5. **Don't make EventEmitter opt-out** - Auto-events must be opt-in (GDPR privacy-by-design)

## References

- RFC-002: Trust Badge Specification
- RFC-003: Key Ownership Proof (PoP)
- `docs/guides/configuration.md` - Full configuration guide
- `docs/api-reference.md` - API reference
