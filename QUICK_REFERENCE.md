# Quick Reference

## Installation

```bash
pip install capiscio-sdk
```

## One-Line Integration

```python
from capiscio_sdk import secure

agent = secure(MyAgentExecutor())
```

## Configuration Presets

```python
from capiscio_sdk import SecurityConfig

# Development (permissive)
SecurityConfig.development()

# Production (balanced) - default
SecurityConfig.production()

# Strict (maximum security)
SecurityConfig.strict()

# From environment variables
SecurityConfig.from_env()
```

**📖 See [Configuration Guide](docs/guides/configuration.md) for all options.**

## Integration Patterns

### Minimal
```python
agent = secure(MyAgentExecutor())
```

### Explicit
```python
config = SecurityConfig.production()
agent = CapiscIOSecurityExecutor(MyAgentExecutor(), config)
```

### Decorator
```python
@secure_agent(config=SecurityConfig.production())
class MyAgent(AgentExecutor):
    pass
```

## Validators

| Validator | Purpose | Performance |
|-----------|---------|-------------|
| **MessageValidator** | Schema & structure | ~1-5ms |
| **ProtocolValidator** | A2A compliance | ~1-5ms |
| **SignatureValidator** | JWT/JWS verification | ~10-50ms (cached) |
| **SemverValidator** | Version compatibility | <1ms |
| **URLSecurityValidator** | SSRF prevention | ~1-5ms |
| **AgentCardValidator** | Discovery metadata | ~10-50ms (cached) |
| **CertificateValidator** | TLS/SSL validation | ~50-200ms (cached) |

## Configuration Options

### Downstream (Incoming)

```python
config.downstream.validate_schema = True
config.downstream.verify_signatures = True
config.downstream.require_signatures = False
config.downstream.check_protocol_compliance = True
config.downstream.enable_rate_limiting = True
config.downstream.rate_limit_requests_per_minute = 60
```

### Upstream (Outgoing)

```python
config.upstream.validate_agent_cards = True
config.upstream.verify_signatures = True
config.upstream.require_signatures = False
config.upstream.test_endpoints = False
config.upstream.cache_validation = True
config.upstream.cache_timeout = 3600
```

### General

```python
config.fail_mode = "block"  # "block" | "monitor" | "log"
config.log_validation_failures = True
config.timeout_ms = 5000
```

## Error Handling

```python
from capiscio_sdk.errors import (
    CapiscIOValidationError,
    CapiscIOSignatureError,
    CapiscIORateLimitError,
    CapiscIOUpstreamError,
)

try:
    await agent.execute(context, event_queue)
except CapiscIOValidationError as e:
    print(f"Validation failed: {e.message}")
    print(f"Errors: {e.errors}")
except CapiscIORateLimitError as e:
    print(f"Rate limit exceeded, retry after {e.retry_after_seconds}s")
```

## Environment Variables

```bash
# Downstream
export CAPISCIO_VALIDATE_SCHEMA=true
export CAPISCIO_VERIFY_SIGNATURES=true
export CAPISCIO_REQUIRE_SIGNATURES=false
export CAPISCIO_RATE_LIMITING=true
export CAPISCIO_RATE_LIMIT_RPM=60

# Upstream
export CAPISCIO_VALIDATE_UPSTREAM=true
export CAPISCIO_CACHE_VALIDATION=true

# General
export CAPISCIO_FAIL_MODE=block
export CAPISCIO_TIMEOUT_MS=5000
```

## Logging

```python
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("capiscio_sdk")
```

## Common Use Cases

### Development
```python
agent = secure(MyAgentExecutor(), SecurityConfig.development())
```

### Production with Custom Rate Limit
```python
config = SecurityConfig.production()
config.downstream.rate_limit_requests_per_minute = 120
agent = secure(MyAgentExecutor(), config)
```

### Strict Security for Financial Apps
```python
config = SecurityConfig.strict()
config.upstream.test_endpoints = True
agent = secure(MyAgentExecutor(), config)
```

### Monitor Mode (Non-Blocking)
```python
config = SecurityConfig.production()
config.fail_mode = "monitor"
agent = secure(MyAgentExecutor(), config)
```

## Links

- [Full Documentation](https://docs.capisc.io/capiscio-sdk-python)
- [GitHub](https://github.com/capiscio/capiscio-sdk-python)
- [PyPI](https://pypi.org/project/capiscio-sdk/)
- [Report Issues](https://github.com/capiscio/capiscio-sdk-python/issues)
