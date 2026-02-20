# capiscio-sdk-python Integration Tests

This directory contains integration tests that verify capiscio-sdk-python functionality against a live capiscio-server instance.

## Scope Ownership

- `capiscio-sdk-python` integration CI is intentionally narrow and focuses on SDK-to-server contract behavior.
- Cross-product workflows and server-dependent end-to-end scenarios are owned by `capiscio-e2e-tests`.
- This split avoids duplicated orchestration and keeps ownership explicit.

## Test Types

### 1. `test_real_executor.py` (Existing)
- Tests SDK security middleware with real AgentExecutor
- Uses **mocked** validation (no server calls)
- Fast, good for unit-level integration testing

### 2. `test_server_integration.py` (NEW - Phase 1B)
- Tests SDK → server HTTP/gRPC calls
- Uses **live** capiscio-server instance
- Validates end-to-end workflows

## Architecture

```
┌─────────────────────┐
│ capiscio-sdk-python │
│   (BadgeClient,     │
│    BadgeVerifier,   │
│    SimpleGuard)     │
└──────────┬──────────┘
           │ HTTP/gRPC
           ▼
┌─────────────────────┐
│  capiscio-server    │
│   (Badge CA,        │
│    JWKS endpoint,   │
│    Agent Registry)  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   PostgreSQL DB     │
└─────────────────────┘
```

## Running Tests

### Prerequisites

None! Docker Compose handles all dependencies.

### Run with Docker Compose

```bash
cd tests/integration
docker-compose up --build --abort-on-container-exit
```

### Run Specific Tests

```bash
# Run only server integration tests
docker-compose run --rm test-runner pytest tests/integration/test_server_integration.py -v

# Run only badge client tests
docker-compose run --rm test-runner pytest tests/integration/test_server_integration.py::TestBadgeClientIntegration -v

# Run with debug output
PYTEST_ARGS="-vv -s" docker-compose up --abort-on-container-exit
```

### Run Locally (Without Docker)

1. Start capiscio-server:
   ```bash
   cd /Users/beondenood/Development/CapiscIO/capiscio-server
   make run
   ```

2. Run tests:
   ```bash
   cd /Users/beondenood/Development/CapiscIO/capiscio-sdk-python
   export API_BASE_URL=http://localhost:8080
   pytest tests/integration/ -v
   ```

## Test Coverage

### ✅ Implemented (Task 8)
- [ ] BadgeClient → Server badge issuance
- [ ] BadgeClient error handling (invalid API key, nonexistent agent)
- [ ] BadgeVerifier → Server JWKS verification (skipped - needs agent setup)
- [ ] Server JWKS endpoint accessibility
- [ ] Server agent registry endpoint accessibility

### 🔲 Pending (Tasks 9-10)
- [ ] SimpleGuard → Server validation flow (Task 9)
- [ ] BadgeKeeper auto-renewal workflow (Task 10)
- [ ] PoP challenge-response integration
- [ ] Full badge lifecycle (issue → verify → renew)

## Environment Variables

- `API_BASE_URL`: Base URL for capiscio-server (default: `http://localhost:8080`)
- `TEST_API_KEY`: API key for test agent (default: `test-api-key-placeholder`)
- `PYTEST_ARGS`: Additional pytest arguments

## CI/CD Integration

In GitHub Actions:

```yaml
- name: Run SDK integration tests
  run: |
    cd capiscio-sdk-python/tests/integration
    docker-compose run --rm test-runner pytest tests/integration/test_server_integration.py -v
```

## Troubleshooting

**Server not healthy**: Increase healthcheck retries in docker-compose.yml

**Database connection errors**: Check `DATABASE_URL` environment variable

**Import errors**: Ensure `PYTHONPATH=/workspace` is set

**Tests skip with "agent not registered"**: Expected - requires agent setup in server first

## Next Steps (Phase 1B)

1. ✅ Task 8: Basic BadgeClient → Server tests
2. 🔲 Task 9: SimpleGuard validation flow
3. 🔲 Task 10: BadgeKeeper auto-renewal
4. 🔲 Task 11: gRPC scoring service integration
5. 🔲 Task 12: Optimize Docker Compose for SDK tests
