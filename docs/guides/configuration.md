# Configuration Guide

This guide covers all configuration options for CapiscIO A2A Security, including upstream and downstream protection settings, fail modes, rate limiting, and environment variables.

---

## Which Configuration Should You Use?

**Answer these 3 questions to find your preset:**

1. **Are you in production?**
   - ❌ No → Use `SecurityConfig.development()` (permissive, fast iteration)
   - ✅ Yes → Continue to question 2

2. **Do you handle sensitive data or financial transactions?**
   - ✅ Yes → Use `SecurityConfig.strict()` (maximum security)
   - ❌ No → Continue to question 3

3. **Running in containers/cloud with environment variables?**
   - ✅ Yes → Use `SecurityConfig.from_env()` (12-factor app style)
   - ❌ No → Use `SecurityConfig.production()` (standard deployment)

**Quick reference:**

| Your Situation | Use This Preset | Why |
|----------------|----------------|-----|
| Local development, debugging | `development()` | Fast iteration, see all traffic |
| Standard production API | `production()` | Balanced security/performance |
| Payment processing, sensitive data | `strict()` | Maximum security enforcement |
| Docker, Kubernetes, cloud | `from_env()` | Configure via environment |

---

## Quick Start

### Using Presets

The easiest way to configure the security middleware is using one of the built-in presets:

```python
from capiscio_a2a_security import secure, SecurityConfig

# Development - Permissive, no rate limiting
agent = secure(MyAgent(), SecurityConfig.development())

# Production - Balanced security and performance (default)
agent = secure(MyAgent(), SecurityConfig.production())

# Strict - Maximum security, all checks enabled
agent = secure(MyAgent(), SecurityConfig.strict())

# From Environment - Load from environment variables
agent = secure(MyAgent(), SecurityConfig.from_env())
```

### Custom Configuration

For fine-grained control, create a custom configuration:

```python
from capiscio_a2a_security import SecurityConfig, DownstreamConfig, UpstreamConfig

config = SecurityConfig(
    downstream=DownstreamConfig(
        validate_schema=True,
        verify_signatures=True,
        require_signatures=False,
        check_protocol_compliance=True,
        enable_rate_limiting=True,
        rate_limit_requests_per_minute=100
    ),
    upstream=UpstreamConfig(
        validate_agent_cards=True,
        verify_signatures=True,
        require_signatures=False,
        test_endpoints=False,
        cache_validation=True,
        cache_timeout=3600
    ),
    fail_mode="block",
    strict_mode=False,
    log_validation_failures=True,
    timeout_ms=5000
)

agent = secure(MyAgent(), config)
```

---

## Configuration Reference

### Top-Level Options

#### `fail_mode`

Controls how the middleware responds to validation failures.

**Type:** `"block" | "monitor" | "log"`  
**Default:** `"block"`

**Options:**
- **`"block"`** - Reject requests that fail validation (recommended for production)
- **`"monitor"`** - Log failures but allow requests through (useful for testing)
- **`"log"`** - Only log failures, no blocking or monitoring (development only)

**Example:**
```python
config = SecurityConfig.production()
config.fail_mode = "monitor"  # Test new validators without breaking
```

**Use Cases:**
- **Development:** `"log"` - Fast iteration
- **Staging:** `"monitor"` - Observe behavior before blocking
- **Production:** `"block"` - Protect against threats

---

#### `strict_mode`

Enables strictest validation settings across all validators.

**Type:** `bool`  
**Default:** `False`

When enabled:
- Requires signatures on all messages
- Enables endpoint testing for upstream agents
- Treats warnings as errors
- No tolerance for minor spec deviations

**Example:**
```python
config = SecurityConfig.production()
config.strict_mode = True  # Maximum security
```

⚠️ **Warning:** Strict mode may cause compatibility issues with agents that have minor spec deviations.

---

#### `log_validation_failures`

Controls whether validation failures are logged.

**Type:** `bool`  
**Default:** `True`

**Example:**
```python
config = SecurityConfig.production()
config.log_validation_failures = False  # Reduce log noise
```

**Recommendation:** Keep enabled in production for security monitoring.

---

#### `timeout_ms`

Maximum time in milliseconds for validation operations.

**Type:** `int`  
**Default:** `5000` (5 seconds)

**Example:**
```python
config = SecurityConfig.production()
config.timeout_ms = 3000  # Faster timeout
```

**Recommendation:** 
- **Fast networks:** 2000-3000ms
- **Standard networks:** 5000ms (default)
- **Slow networks:** 8000-10000ms

---

## Downstream Configuration

Downstream settings control validation of **incoming requests** (agents calling your agent).

### `DownstreamConfig` Options

#### `validate_schema`

Validates message structure against A2A schema.

**Type:** `bool`  
**Default:** `True`

**Checks:**
- Required fields present (messageId, role, parts)
- Valid role values ("agent" or "user")
- Valid part kinds ("text", "file", "data")
- Proper field formats and types
- Message structure compliance per A2A v0.3.0 specification

**Example:**
```python
config.downstream.validate_schema = True
```

**Recommendation:** Always keep enabled. Malformed messages can cause crashes.

---

#### `verify_signatures`

Verifies JWS signatures on incoming messages.

**Type:** `bool`  
**Default:** `True`

**What it does:**
- Fetches JWKS from sender's agent card
- Verifies signature cryptographically
- Validates signature format (RFC 7515)
- Checks signature timestamps

**Example:**
```python
config.downstream.verify_signatures = True
config.downstream.require_signatures = False  # Optional but verify if present
```

**Performance:** Adds ~50-200ms per message (first request, then cached)

---

#### `require_signatures`

Requires all incoming messages to have valid signatures.

**Type:** `bool`  
**Default:** `False`

**Behavior:**
- `True` - Reject unsigned messages
- `False` - Allow unsigned messages, but verify if signature present

**Example:**
```python
config.downstream.require_signatures = True  # Strict security
```

**Use Cases:**
- **Financial transactions:** `True` - Must authenticate sender
- **Public APIs:** `False` - Allow anonymous access
- **Internal services:** `False` - Trust network security

---

#### `check_protocol_compliance`

Validates A2A protocol compliance (headers, versions, message types).

**Type:** `bool`  
**Default:** `True`

**Checks:**
- Protocol version compatibility
- Valid message types
- Required headers present
- Header format compliance

**Example:**
```python
config.downstream.check_protocol_compliance = True
```

**Recommendation:** Always keep enabled for spec compliance.

---

#### `enable_rate_limiting`

Enables token bucket rate limiting per sender.

**Type:** `bool`  
**Default:** `True` (production), `False` (development)

**How it works:**
- Tracks requests per sender identifier
- Uses token bucket algorithm
- Limits applied per sender, not global
- No external dependencies (in-memory)

**Example:**
```python
config.downstream.enable_rate_limiting = True
config.downstream.rate_limit_requests_per_minute = 100
```

**When to disable:**
- Local development
- Testing
- When using external rate limiter (API gateway)

---

#### `rate_limit_requests_per_minute`

Maximum requests per minute per sender.

**Type:** `int`  
**Default:** `60`

**Sizing Guide:**
- **Low traffic API:** 60 req/min
- **Medium traffic API:** 100-200 req/min
- **High traffic API:** 500-1000 req/min
- **Batch processing:** 10-20 req/min

**Example:**
```python
config.downstream.rate_limit_requests_per_minute = 120
```

**Formula:** `(peak concurrent users) × (requests per user per minute) × 1.5 buffer`

---

## Upstream Configuration

Upstream settings control validation when **calling other agents** (your agent making requests).

### `UpstreamConfig` Options

#### `validate_agent_cards`

Validates agent cards before calling external agents.

**Type:** `bool`  
**Default:** `True`

**Checks:**
- Agent card schema compliance
- Required fields (name, version, capabilities)
- Valid endpoint URLs
- Provider information
- Skills structure

**Example:**
```python
config.upstream.validate_agent_cards = True
```

**Performance:** Adds ~100-300ms (first call per agent, then cached)

**Recommendation:** Keep enabled to prevent calling malformed agents.

---

#### `verify_signatures`

Verifies signatures on agent cards.

**Type:** `bool`  
**Default:** `True`

**What it does:**
- Validates agent card signature
- Verifies publisher identity
- Checks signature timestamps
- Ensures card integrity

**Example:**
```python
config.upstream.verify_signatures = True
config.upstream.require_signatures = False
```

**Use Cases:**
- **Public agents:** `True` - Verify authenticity
- **Internal agents:** `False` - Trust internal network
- **Testing:** `False` - Simplify development

---

#### `require_signatures`

Requires all agent cards to have valid signatures.

**Type:** `bool`  
**Default:** `False`

**Behavior:**
- `True` - Refuse to call agents without valid signatures
- `False` - Allow unsigned agent cards, but verify if present

**Example:**
```python
config.upstream.require_signatures = True  # Only call verified agents
```

**Strict Mode:** Automatically enabled when `strict_mode = True`

---

#### `test_endpoints`

Tests agent endpoints before calling them.

**Type:** `bool`  
**Default:** `False`

**What it does:**
- Makes HEAD/OPTIONS request to endpoint
- Verifies endpoint is reachable
- Checks TLS certificate validity
- Validates response times

**Example:**
```python
config.upstream.test_endpoints = True
```

**Performance Impact:** 
- Adds ~200-500ms per new agent
- Results cached per agent

**When to enable:**
- **Critical production systems** - Prevent calling dead endpoints
- **Financial transactions** - Verify endpoint before committing
- **Batch jobs** - Test before processing large batches

**When to disable:**
- **Development** - Faster iteration
- **High-throughput APIs** - Minimize latency
- **Behind API gateway** - Gateway handles health checks

---

#### `cache_validation`

Caches validation results for agent cards.

**Type:** `bool`  
**Default:** `True`

**What it caches:**
- Agent card validation results
- Signature verification results
- Endpoint test results

**Example:**
```python
config.upstream.cache_validation = True
config.upstream.cache_timeout = 7200  # 2 hours
```

**Memory Usage:** ~1KB per cached agent

**Recommendation:** Keep enabled for performance.

---

#### `cache_timeout`

Cache TTL in seconds for validation results.

**Type:** `int`  
**Default:** `3600` (1 hour)

**Sizing Guide:**
- **Fast-changing agents:** 300-900 seconds (5-15 minutes)
- **Standard agents:** 3600 seconds (1 hour)
- **Stable agents:** 7200-14400 seconds (2-4 hours)
- **Static agents:** 86400 seconds (24 hours)

**Example:**
```python
config.upstream.cache_timeout = 1800  # 30 minutes
```

**Trade-offs:**
- **Longer:** Better performance, slower to detect agent changes
- **Shorter:** More up-to-date, more validation overhead

---

## Configuration Presets Explained

### Development Preset

**Best for:** Local development, rapid iteration, debugging

```python
SecurityConfig.development()
```

**Settings:**
- ✅ Schema validation
- ✅ Protocol compliance
- ⚠️ Signature verification (optional, not required)
- ❌ Rate limiting disabled
- ❌ Endpoint testing disabled
- **Fail Mode:** `"log"` (only logs, never blocks)

**Use when:**
- Developing new features
- Testing with mock agents
- Debugging validation issues
- Running unit tests

---

### Production Preset

**Best for:** Standard production deployments

```python
SecurityConfig.production()
```

**Settings:**
- ✅ Schema validation
- ✅ Protocol compliance
- ⚠️ Signature verification (optional, not required)
- ✅ Rate limiting (60 req/min)
- ❌ Endpoint testing disabled (performance)
- **Fail Mode:** `"block"` (rejects invalid requests)

**Use when:**
- Running in production
- Serving external traffic
- Need balanced security/performance
- Standard security requirements

---

### Strict Preset

**Best for:** High-security environments, financial systems, regulated industries

```python
SecurityConfig.strict()
```

**Settings:**
- ✅ Schema validation
- ✅ Protocol compliance
- ✅ **Signatures required** (all messages must be signed)
- ✅ Rate limiting (60 req/min)
- ✅ Endpoint testing enabled
- ✅ Strict mode enabled
- **Fail Mode:** `"block"` (rejects invalid requests)

**Use when:**
- Handling sensitive data
- Financial transactions
- Compliance requirements (HIPAA, PCI-DSS)
- Zero-trust architecture

**⚠️ Warning:** May reject agents with minor spec deviations.

---

## Environment Variables

Load configuration from environment variables using `SecurityConfig.from_env()`.

### Downstream Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `CAPISCIO_VALIDATE_SCHEMA` | bool | `true` | Enable schema validation |
| `CAPISCIO_VERIFY_SIGNATURES` | bool | `true` | Verify signatures if present |
| `CAPISCIO_REQUIRE_SIGNATURES` | bool | `false` | Require all messages signed |
| `CAPISCIO_RATE_LIMITING` | bool | `true` | Enable rate limiting |
| `CAPISCIO_RATE_LIMIT_RPM` | int | `60` | Requests per minute limit |

### Upstream Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `CAPISCIO_VALIDATE_UPSTREAM` | bool | `true` | Validate agent cards |
| `CAPISCIO_VERIFY_UPSTREAM_SIGNATURES` | bool | `true` | Verify agent card signatures |
| `CAPISCIO_CACHE_VALIDATION` | bool | `true` | Cache validation results |

### Top-Level Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `CAPISCIO_FAIL_MODE` | string | `block` | Fail mode: block, monitor, log |
| `CAPISCIO_TIMEOUT_MS` | int | `5000` | Validation timeout (milliseconds) |

### Example: Docker Compose

```yaml
services:
  agent:
    environment:
      - CAPISCIO_FAIL_MODE=block
      - CAPISCIO_RATE_LIMITING=true
      - CAPISCIO_RATE_LIMIT_RPM=120
      - CAPISCIO_REQUIRE_SIGNATURES=false
      - CAPISCIO_TIMEOUT_MS=3000
```

### Example: Kubernetes

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: security-config
data:
  CAPISCIO_FAIL_MODE: "block"
  CAPISCIO_RATE_LIMITING: "true"
  CAPISCIO_RATE_LIMIT_RPM: "200"
  CAPISCIO_TIMEOUT_MS: "5000"
```

---

## Common Scenarios

### API Gateway

When behind an API gateway that handles rate limiting and TLS:

```python
config = SecurityConfig.production()
config.downstream.enable_rate_limiting = False  # Gateway handles it
config.upstream.test_endpoints = False  # Gateway does health checks
```

### Internal Microservices

When all agents are internal and trusted:

```python
config = SecurityConfig(
    downstream=DownstreamConfig(
        validate_schema=True,
        verify_signatures=False,  # Trust internal network
        require_signatures=False,
        enable_rate_limiting=False,  # Use service mesh
    ),
    upstream=UpstreamConfig(
        validate_agent_cards=True,
        verify_signatures=False,
        test_endpoints=False,  # Service mesh handles health
    ),
    fail_mode="block"
)
```

### Public API with High Security

```python
config = SecurityConfig.strict()
config.downstream.rate_limit_requests_per_minute = 30  # Conservative
config.upstream.require_signatures = True  # Only call verified agents
config.upstream.test_endpoints = True  # Verify before calling
```

### Development with Real Agents

Test against real agents while developing:

```python
config = SecurityConfig.development()
config.downstream.enable_rate_limiting = True  # Prevent runaway loops
config.downstream.rate_limit_requests_per_minute = 120  # Higher for testing
config.fail_mode = "monitor"  # Log failures but allow through
```

### CI/CD Testing

Fast, deterministic testing:

```python
config = SecurityConfig(
    downstream=DownstreamConfig(
        validate_schema=True,
        verify_signatures=False,  # No network calls
        enable_rate_limiting=False,  # Deterministic timing
    ),
    upstream=UpstreamConfig(
        validate_agent_cards=True,
        verify_signatures=False,  # No network calls
        test_endpoints=False,  # No network calls
        cache_validation=False,  # Deterministic behavior
    ),
    fail_mode="block",
    timeout_ms=1000  # Fast timeout for CI
)
```

---

## Performance Tuning

### Minimize Latency

```python
config = SecurityConfig.production()
config.downstream.enable_rate_limiting = False  # Use external
config.upstream.test_endpoints = False  # Skip health checks
config.upstream.cache_timeout = 7200  # Cache longer
config.timeout_ms = 2000  # Faster timeout
```

**Expected overhead:** ~5-20ms per request

### Maximize Security

```python
config = SecurityConfig.strict()
config.downstream.require_signatures = True
config.upstream.require_signatures = True
config.upstream.test_endpoints = True
config.upstream.cache_timeout = 300  # Refresh frequently
```

**Expected overhead:** ~100-500ms per request (first call per agent)

### Balance Security and Performance

```python
config = SecurityConfig.production()  # Good starting point
config.downstream.rate_limit_requests_per_minute = 100
config.upstream.cache_timeout = 3600
config.timeout_ms = 3000
```

**Expected overhead:** ~10-50ms per request

---

## Troubleshooting

### "Rate limit exceeded" errors

**Problem:** Legitimate traffic being blocked by rate limiting.

**Solutions:**
```python
# Increase rate limit
config.downstream.rate_limit_requests_per_minute = 200

# Or disable for specific scenarios
config.downstream.enable_rate_limiting = False
```

### Signature verification failures

**Problem:** Agents unable to verify each other's signatures.

**Solutions:**
```python
# Make signatures optional
config.downstream.require_signatures = False
config.upstream.require_signatures = False

# Or disable verification temporarily
config.downstream.verify_signatures = False
```

### Timeout errors

**Problem:** Validation operations timing out.

**Solutions:**
```python
# Increase timeout
config.timeout_ms = 10000  # 10 seconds

# Disable expensive operations
config.upstream.test_endpoints = False
```

### High memory usage

**Problem:** Validation cache consuming too much memory.

**Solutions:**
```python
# Shorten cache timeout
config.upstream.cache_timeout = 900  # 15 minutes

# Or disable caching
config.upstream.cache_validation = False
```

---

## Next Steps

- **[Scoring System](scoring.md)** - Understand validation scores
- **[Quick Start](../getting-started/quickstart.md)** - Get started quickly
- **[Core Concepts](../getting-started/concepts.md)** - Learn key concepts
- **[Contributing](../contributing.md)** - Contribute to the project
