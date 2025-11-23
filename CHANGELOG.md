# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

## [0.3.0] - 2025-11-22

### Added
- **SimpleGuard Security Strategy**:
  - **Identity**: Ed25519 JWS signature verification (`x-jws-signature` header).
  - **Integrity**: SHA-256 Body Hash verification (`bh` claim) to prevent payload tampering.
  - **Freshness**: Replay protection using `exp` (expiration) and `iat` (issued at) claims with a 60-second window.
  - **Zero Config**: Secure by default with minimal setup.
- **FastAPI Integration**:
  - `SimpleGuardMiddleware`: Automatic request validation and identity injection into `request.state.identity`.
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

### Removed
- (If any features were removed, list them here. Based on context, we mostly added things, but the strategy shifted).

### Planned for v1.0.0
- Full A2A v1.0 compliance
- Production-ready hardening
- Performance optimizations
- Comprehensive documentation
- CI/CD pipeline
- PyPI release

---

[0.1.0]: https://github.com/capiscio/capiscio-sdk-python/releases/tag/v0.1.0

