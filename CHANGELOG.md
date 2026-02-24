# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Automatic Binary Download**: SDK now automatically downloads capiscio-core binary if not found
  - Downloads from GitHub releases (defaults to v2.4.0)
  - Platform detection for macOS (arm64/x86_64), Linux (arm64/x86_64), and Windows
  - Binary caching in `~/.capiscio/bin/` directory
  - Automatic executable permissions for Unix-like systems
  - Fallback search order: `CAPISCIO_BINARY` env var → local development path → system PATH → cached binary → auto-download

### Changed
- **Improved Process Management**: Enhanced error logging and binary discovery

## [2.4.1] - 2026-02-08

### Added
- **CapiscIO.connect()**: "Let's Encrypt" style one-liner agent setup
  - Single API call handles key generation, DID creation, registration, and badge request
  - Cryptographic operations performed by capiscio-core Go library via gRPC
  - Context manager support for automatic resource cleanup
- **CapiscIO.from_env()**: Initialize from `CAPISCIO_API_KEY` environment variable
- **AgentIdentity**: Dataclass representing a fully-configured agent
  - `emit()`: Send events to the registry
  - `status()`: Get agent status including badge validity
  - `close()`: Clean up resources (also works as context manager)
- **EventEmitter**: Agent event emission with batching
  - Thread-safe batch operations
  - Automatic flush on batch size threshold
  - Convenience methods: `task_started()`, `task_completed()`, `task_failed()`, `tool_call()`, `tool_result()`

### Fixed
- **httpx exception handling**: Network errors now raise `RuntimeError` with sanitized messages
- **Error message sanitization**: Removed `resp.text` from error messages to prevent API key exposure
- **Agent name lookup**: When `name` is specified but no agent matches, a new agent is now created (previously fell back to first existing agent)

## [2.4.0] - 2026-01-18

### Fixed
- **RFC-002 Alignment**: TrustLevel enum values now match RFC-002 §5 exactly
- **BadgeClaims**: Aligned claim field names with RFC-002 specification
- **to_dict()**: Now preserves `cnf` claim for IAL-1 badges (round-trip serialization)
- **has_key_binding**: Consistently checks both `ial=='1'` AND `cnf` presence

### Added
- **MCP Service Client**: RFC-006/RFC-007 operations via MCP protocol
- **MCP gRPC Client**: Server identity operations

## [2.3.1] - 2025-01-14

### Fixed
- Fixed `__version__` in package `__init__.py` (was 0.3.1, now 2.3.1)
- Aligned all version references across package metadata

## [0.1.0] - 2025-01-10

### Added
- **Comprehensive Integration Tests (26 tests)**
  - Real A2A SDK integration testing with official types
  - All Part types tested: TextPart, FilePart (bytes/URI), DataPart, mixed parts
  - Both role values tested: user, agent
  - Optional fields tested: contextId, taskId, metadata
  - Edge cases: empty text, long text (10KB), Unicode/special characters
  - Security patterns: XSS attempts, SQL injection, oversized messages (100+ parts), null bytes
  - Malformed messages: invalid roles, empty messageId, empty parts array
  - Coverage: All tests passing in ~1.27 seconds

- **GitHub Actions CI/CD**
  - `pr-checks.yml`: Comprehensive PR validation (Python 3.10-3.13, linting, type checking, tests, security scanning)
  - Enhanced `publish.yml`: Now runs full test suite before publishing to PyPI
  - `docs.yml`: Automated documentation deployment (GitHub Pages, Cloudflare Pages)

- **Foundation Layer**
  - Core types: `ValidationResult`, `ValidationIssue`, `ValidationSeverity`, `RateLimitInfo`, `CacheEntry`
  - Error hierarchy: 7 exception classes for different security scenarios
  - Configuration system with 4 presets: `development()`, `production()`, `strict()`, `from_env()`

- **Validators**
  - `MessageValidator`: Validates A2A v0.3.0 message structure
    - Required fields: `messageId` (non-empty string), `role` (enum), `parts` (array)
    - Optional fields: `contextId`, `taskId`, `metadata`
    - Supports all Part types: `TextPart`, `FilePart` (FileWithBytes/FileWithUri), `DataPart`
    - Part validation: kind discriminator ("text"|"file"|"data") with type-specific validation
  - `ProtocolValidator`: Validates protocol version, headers, and message types

- **Infrastructure**
  - `ValidationCache`: TTL-based in-memory cache with invalidation support
  - `RateLimiter`: Token bucket algorithm with per-identifier rate limiting
  - Configurable cache size and TTL

- **Security Executor**
  - `CapiscIOSecurityExecutor`: Main wrapper for agent executors
  - Three integration patterns:
    - Minimal: `secure(agent)` - one-liner integration
    - Explicit: `CapiscIOSecurityExecutor(agent, config)` - full control
    - Decorator: `@secure_agent(config)` - pythonic decorator pattern
  - Configurable fail modes: `block`, `monitor`, `log`
  - Request rate limiting with identifier-based buckets
  - Validation result caching for performance

- **Documentation**
  - Complete rewrite of all examples to use official A2A SDK types
  - Updated configuration guide with correct A2A message fields
  - Comprehensive quickstart with real-world integration examples
  - API reference documentation
  - Apache 2.0 license, Contributing guidelines, Security policy

### Technical Details
- Python 3.10+ support (tested on 3.10, 3.11, 3.12, 3.13)
- Type hints with `py.typed` marker
- Pydantic models for validation
- Token bucket rate limiting algorithm
- TTL-based caching with LRU eviction
- Delegate pattern for attribute access

### Test Coverage
- **Total: 150 tests, 99.3% passing (149 passing, 1 skipped)**
  - Unit tests: 124 tests (including 14 MessageValidator tests)
  - Integration tests: 26 tests (all passing)
  - Skipped: 1 module (test_executor.py - covered by integration tests)

### Release Notes
This is an **early 0.1.0 release**. While the middleware has comprehensive test coverage (150 tests) and validates all official A2A message structures correctly, it has not yet been battle-tested in production environments. We recommend:

- ✅ **Safe for**: Development environments, testing, evaluation
- ⚠️ **Use with monitoring**: Staging environments, non-critical production
- ❌ **Not yet ready for**: Mission-critical production without extensive internal testing

**Planned for v1.0**: Load testing, stress testing, concurrent request testing, performance benchmarking, production hardening based on real-world feedback

### Installation
```bash
pip install capiscio-sdk==0.1.0
```

---

## [Unreleased]

## [2.3.0] - 2025-01-14

**Major Release** - Complete Trust Badge ecosystem with gRPC backend, PoP protocol, and DV badge flow.

This release introduces the **capiscio-core gRPC integration**, enabling high-performance badge operations through a native Go backend. The SDK now provides a complete implementation of RFC-002 (Trust Badges) and RFC-003 (Proof of Possession).

### Added

#### Trust Badge API (`capiscio_sdk.badge`)
- **`verify_badge()`** - Full badge verification with signature, expiration, and revocation checks
- **`parse_badge()`** - Parse badge claims without verification (for inspection)
- **`request_badge()` / `request_badge_sync()`** - Request new badges from CA
- **`request_pop_badge()` / `request_pop_badge_sync()`** - RFC-003 Proof of Possession badge requests
- **`start_badge_keeper()`** - Start automatic badge renewal
- **`BadgeClaims`** dataclass with full RFC-002 claim support
- **`VerifyOptions`** - Configurable verification (audience, issuers, clock skew)
- **`VerifyMode`** enum - `ONLINE`, `OFFLINE`, `HYBRID` verification modes
- **`TrustLevel`** enum - Level 1 (DV), Level 2 (OV), Level 3 (EV)

#### Badge Lifecycle Management (`capiscio_sdk.badge_keeper`)
- **`BadgeKeeper`** class - Automatic badge renewal with background thread
  - Configurable renewal threshold (renew N seconds before expiry)
  - Exponential backoff retry on failure
  - Callback support for badge updates (`on_renew`)
  - Integration with `SimpleGuard` for seamless auth
- **`BadgeKeeperConfig`** - Full configuration options (TTL, trust level, output file)

#### Domain Validation API (`capiscio_sdk.dv`)
- **`create_dv_order()`** - Create DV badge order with HTTP-01 or DNS-01 challenge
- **`get_dv_order()`** - Check order status
- **`finalize_dv_order()`** - Complete validation and receive grant JWT
- **`DVOrder`** dataclass - Order details (challenge token, validation URL, DNS record)
- **`DVGrant`** dataclass - Signed grant JWT for badge issuance

#### gRPC Backend (`capiscio_sdk._rpc`)
- **`CapiscioRPCClient`** - High-level gRPC client for capiscio-core
  - Auto-starts local capiscio-core binary when needed
  - Connection pooling and health checks
  - Context manager support (`with CapiscioRPCClient() as client:`)
- **Generated Protocol Buffers** for all services:
  - `BadgeService` - Badge parsing, verification, issuance
  - `DIDService` - DID parsing and resolution
  - `TrustService` - Trust level operations
  - `RevocationService` - Badge revocation checks
  - `ScoringService` - Trust scoring calculations
  - `SimpleGuardService` - Request signing and verification
  - `RegistryService` - Agent registry operations
- **`ProcessManager`** - Manages capiscio-core subprocess lifecycle

#### Core Validator (`capiscio_sdk.validators`)
- **`CoreValidator`** class - Go-backed validation for agent cards
- **`validate_agent_card()`** - One-liner validation using Go core
- RFC-004 Agent Card schema validation
- Much faster than pure-Python validation

#### RFC-002 v1.3 §7.5 Staleness Options
- Configurable badge staleness thresholds
- `max_age` parameter for verification
- Grace period support for expiring badges

### Changed
- **Version Alignment**: SDK version now matches other CapiscIO products (capiscio-server, capiscio-ui, capiscio-core v2.3.0)
- **SimpleGuard Refactoring**: 
  - Now uses gRPC backend for cryptographic operations
  - Improved request signing with `sign_request()` / `verify_request()`
  - Better error messages with RFC references
- **Scoring Module**: Enhanced with gRPC-backed calculations

### Fixed
- **CI/CD Pipeline**: 
  - Publish workflow now runs only unit tests (prevents false failures from missing infrastructure)
  - Integration tests moved to dedicated workflow with Docker infrastructure
- **Lint Issues**: Fixed all ruff warnings, updated to latest ruff config
- **FastAPI Integration**: Improved middleware error handling

### Infrastructure
- **New Integration Test Suite** with Docker Compose:
  - `test_badge_keeper.py` - Badge lifecycle tests
  - `test_dv_badge_flow.py` - Full DV flow E2E tests
  - `test_dv_order_api.py` - DV API tests
  - `test_dv_sdk.py` - SDK integration tests
  - `test_grpc_scoring.py` - gRPC scoring tests
  - `test_server_integration.py` - Server integration tests
  - `test_simple_guard.py` - SimpleGuard tests
- **New Unit Tests**:
  - `test_badge.py` - Badge API unit tests
  - `test_badge_keeper.py` - BadgeKeeper unit tests
  - `test_core_validator.py` - CoreValidator tests
  - `test_pop_badge.py` - PoP protocol tests
- **GitHub Actions Workflows**:
  - `integration-tests.yml` - Full integration tests with capiscio-server + postgres + capiscio-core

### Documentation
- **Comprehensive gRPC Integration Guide** (`docs/guides/badge-verification.md`)
- **Badge Verification Guide** with code examples
- **GitHub Copilot Instructions** for AI-assisted development
- **API Reference** updates for all new modules

### Dependencies
- Added `grpcio` and `grpcio-tools` for gRPC support
- Added `protobuf` for Protocol Buffer serialization
- Updated `cryptography` to latest version

### Statistics
- **+12,568 lines of code** added
- **63 files** changed
- **7 new modules** added
- **1,321 line** gRPC client implementation
- **737 line** badge API implementation
- **304 line** BadgeKeeper implementation
- **296 line** DV API implementation

### Migration from v0.3.x
This release is backwards compatible. Existing `SimpleGuard` and `CapiscioSecurityExecutor` usage continues to work. New features are additive.

To use new badge features:
```python
from capiscio_sdk import verify_badge, BadgeKeeper, create_dv_order

# Verify an incoming badge
result = verify_badge(token, trusted_issuers=["https://registry.capisc.io"])

# Auto-renew badges
keeper = BadgeKeeper(api_url="...", api_key="...", agent_id="...")
keeper.start()

# Get a DV badge
order = create_dv_order(domain="example.com", challenge_type="http-01", jwk=jwk)
```

## [0.3.1] - 2025-11-23

### Fixed
- **Release Automation**: Bumped version to trigger fresh GitHub Release and PyPI publication with correct artifacts.

## [0.3.0] - 2025-11-22

### Added
- **SimpleGuard Security Strategy**:
  - **Identity**: Ed25519 Trust Badge verification (`X-Capiscio-Badge` header per RFC-002 §9.1).
  - **Integrity**: SHA-256 Body Hash verification (`bh` claim) to prevent payload tampering.
  - **Freshness**: Replay protection using `exp` (expiration) and `iat` (issued at) claims with a 60-second window.
  - **Zero Config**: Secure by default with minimal setup.
- **FastAPI Integration**:
  - `CapiscioMiddleware`: Automatic request validation and identity injection into `request.state.agent_id`.
  - `Server-Timing` header support for telemetry (verification time).
- **Telemetry**:
  - Added `dur` (duration) metric to `Server-Timing` header for monitoring security overhead.
- **Documentation**:
  - Updated `README.md` with "Enforcement First" strategy.
  - Updated `SECURITY.md` with threat model and verification steps.
  - Added `examples/secure_ping_pong` demo.

### Changed
- **Breaking Change**: Shifted from "Validation" focus to "Enforcement" focus.
- Updated `pyproject.toml` dependencies to include `cryptography` and `pyjwt`.

### Planned for v1.0.0
- Full A2A v1.0 compliance
- Production-ready hardening
- Performance optimizations
- Comprehensive documentation
- CI/CD pipeline
- PyPI release

---

[2.3.0]: https://github.com/capiscio/capiscio-sdk-python/releases/tag/v2.3.0
[0.3.1]: https://github.com/capiscio/capiscio-sdk-python/releases/tag/v0.3.1
[0.3.0]: https://github.com/capiscio/capiscio-sdk-python/releases/tag/v0.3.0
[0.1.0]: https://github.com/capiscio/capiscio-sdk-python/releases/tag/v0.1.0

