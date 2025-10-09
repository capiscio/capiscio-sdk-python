# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-10-09

### Added
- **Foundation Layer (Phase 1)**
  - Core types: `ValidationResult`, `ValidationIssue`, `ValidationSeverity`, `RateLimitInfo`, `CacheEntry`
  - Error hierarchy: 7 exception classes for different security scenarios
  - Configuration system with 4 presets: `development()`, `production()`, `strict()`, `from_env()`
  - Comprehensive unit tests (16 tests, 100% passing)

- **Validators (Phase 2)**
  - `MessageValidator`: Validates A2A message structure (ID, sender, recipient, timestamp, parts)
  - `ProtocolValidator`: Validates protocol version, headers, and message types
  - Comprehensive validation with error and warning levels
  - Unit tests (22 tests, 100% passing)

- **Infrastructure (Phase 3)**
  - `ValidationCache`: TTL-based in-memory cache with invalidation support
  - `RateLimiter`: Token bucket algorithm with per-identifier rate limiting
  - Configurable cache size and TTL
  - Unit tests (13 tests, 100% passing)

- **Security Executor (Phase 4)**
  - `CapiscioSecurityExecutor`: Main wrapper for agent executors
  - Three integration patterns:
    - Minimal: `secure(agent)` - one-liner integration
    - Explicit: `CapiscioSecurityExecutor(agent, config)` - full control
    - Decorator: `@secure_agent(config)` - pythonic decorator pattern
  - Configurable fail modes: `block`, `monitor`, `log`
  - Request rate limiting with identifier-based buckets
  - Validation result caching for performance
  - Unit tests (12 tests, 100% passing)

- **Documentation**
  - Comprehensive README with all integration patterns
  - Usage examples for all three patterns
  - Configuration preset documentation
  - Apache 2.0 license
  - Contributing guidelines
  - Security policy

### Technical Details
- Python 3.10+ support
- Type hints with `py.typed` marker
- Pydantic models for validation
- Token bucket rate limiting algorithm
- TTL-based caching with LRU eviction
- Delegate pattern for attribute access

### Test Coverage
- **Total: 63 tests, 100% passing**
  - Foundation: 16 tests
  - Validators: 22 tests  
  - Infrastructure: 13 tests
  - Executor: 12 tests

---

## [Unreleased]

### Planned for v0.2.0
- Signature verification (crypto validation)
- Agent card validation
- Upstream agent testing
- Integration tests
- End-to-end tests
- Performance benchmarks

### Planned for v1.0.0
- Full A2A v1.0 compliance
- Production-ready hardening
- Performance optimizations
- Comprehensive documentation
- CI/CD pipeline
- PyPI release

---

[0.1.0]: https://github.com/capiscio/a2a-security/releases/tag/v0.1.0

