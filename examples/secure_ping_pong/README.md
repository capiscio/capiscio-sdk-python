# Secure Ping Pong Demo

This demo shows how **CapiscIO SimpleGuard** secures an Agent-to-Agent interaction with zero configuration.

## Prerequisites

```bash
pip install fastapi uvicorn requests capiscio-sdk
```

## Running the Demo

1. **Start the Server:**
   The server will auto-generate its identity (`agent-card.json`) and keys (`capiscio_keys/`) on the first run.

   ```bash
   python server.py
   ```

2. **Run the Client:**
   In a separate terminal, run the client. It will use the same generated keys (simulating a trusted peer) to sign requests.

   ```bash
   python client.py
   ```

## What Happens?

1. **Auto-Discovery:** `SimpleGuard(dev_mode=True)` detects missing keys and generates an Ed25519 keypair locally.
2. **Self-Trust:** In dev mode, it adds its own public key to the `trusted/` store so it can verify its own signatures (loopback).
3. **Enforcement:**
   - The **Valid Request** passes because it has a valid JWS signed by a trusted key.
   - The **Attack Request** fails (401/403) because it lacks a valid signature.

## Directory Structure (Generated)

After running, you will see:

```text
secure_ping_pong/
  agent-card.json        # Your Agent's Identity
  capiscio_keys/         # Your Secrets (GitIgnored)
    private.pem
    public.pem
    trusted/
      <kid>.pem          # Trusted Peers
```
