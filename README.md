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

## How It Works

### 1. The Handshake
CapiscIO enforces the **A2A Trust Protocol**:
*   **Sender**: Signs the request body (JWS + Body Hash).
*   **Receiver**: Verifies the signature and re-hashes the body to ensure integrity.

### 2. The "Customs Officer"
The `SimpleGuard` acts as a local authority. It manages your agent's "Passport" (Agent Card) and verifies the "Visas" (Tokens) of incoming requests.

### 3. Telemetry
Every response includes a `Server-Timing` header showing exactly how fast the verification was:
```http
Server-Timing: capiscio-auth;dur=0.618;desc="CapiscIO Verification"
```

## Documentation

- [Official Documentation](https://docs.capisc.io)
- [A2A Protocol Spec](https://github.com/google/A2A)

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.
