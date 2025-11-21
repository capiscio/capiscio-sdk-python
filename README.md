# CapiscIO SDK (Python)

**Runtime security middleware for A2A (Agent-to-Agent) protocol agents**

[![PyPI version](https://badge.fury.io/py/capiscio-sdk.svg)](https://badge.fury.io/py/capiscio-sdk)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

## What is CapiscIO SDK?

CapiscIO SDK provides **always-on runtime protection** for agents using the [A2A (Agent-to-Agent) protocol](https://github.com/google/A2A). It wraps your agent executor to validate incoming requests, verify signatures, and protect against malicious actors—all without requiring peer cooperation.

### Key Features

- ✅ **Message validation** - Schema and protocol compliance checking
- ✅ **Signature verification** - JWS/JWKS cryptographic validation (RFC 7515)
- ✅ **Upstream protection** - Validate agents you call
- ✅ **Downstream protection** - Validate agents calling you
- ✅ **Rate limiting** - Token bucket algorithm
- ✅ **Caching** - Performance-optimized validation results
- ✅ **Three integration patterns** - Minimal, explicit, or decorator

## Installation

```bash
pip install capiscio-sdk
```

## Quick Start


### Pattern 1: Minimal (One-liner with Preset)

```python
from capiscio_sdk import secure, SecurityConfig
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore

# Wrap your agent with security (production defaults)
agent = secure(MyAgentExecutor(), SecurityConfig.production())

# Use in A2A request handler
handler = DefaultRequestHandler(
    agent_executor=agent,
    task_store=InMemoryTaskStore()
)

# Access validation results (three-dimensional scoring)
result = await agent.validate_agent_card(card_url)
print(result.compliance.total, result.trust.total, result.availability.total)
```

### Pattern 2: Granular Control

```python
from capiscio_sdk import CapiscIOSecurityExecutor, SecurityConfig

# Start with a preset, customize what matters to you
config = SecurityConfig.production()
config.downstream.rate_limit_requests_per_minute = 100  # Higher rate limit
config.downstream.require_signatures = True             # Enforce signatures
config.upstream.test_endpoints = True                   # Test before calling
config.fail_mode = "monitor"                            # Log but don't block yet

secure_agent = CapiscIOSecurityExecutor(
    delegate=MyAgentExecutor(),
    config=config
)
```

### Pattern 3: Environment-Driven (12-Factor App)

```python
from capiscio_sdk import secure_agent, SecurityConfig
from a2a import AgentExecutor, RequestContext, EventQueue

@secure_agent(config=SecurityConfig.from_env())
class MyAgentExecutor(AgentExecutor):
    async def execute(self, context: RequestContext, event_queue: EventQueue):
        # Your agent logic - config loaded from env vars
        pass

# Already secured - use directly!
handler = DefaultRequestHandler(agent_executor=MyAgentExecutor())
```

**All 16 configuration options documented in the [Configuration Guide](https://docs.capisc.io/sdk-python/guides/configuration/).**

## Why CapiscIO?

### The Problem

When building A2A agents, you face security risks from:
- **Malicious downstream agents** sending invalid/malicious requests
- **Broken upstream dependencies** with invalid agent cards
- **Protocol violations** causing runtime failures
- **Missing signatures** with no authenticity verification

### The Solution

CapiscIO wraps your agent executor and provides:

1. **Downstream Protection** - Validates all incoming requests
2. **Upstream Protection** - Validates agents you call
3. **Always-On** - Works without peer cooperation
4. **Performance** - Caching and parallel validation
5. **Three-Dimensional Scoring** - Compliance, trust, and availability insights

## Configuration

### Presets

```python
# Development - Permissive, verbose logging
SecurityConfig.development()

# Production - Balanced (default)
SecurityConfig.production()

# Strict - Maximum security
SecurityConfig.strict()

# From environment variables
SecurityConfig.from_env()
```

### Custom Configuration

```python
from capiscio_sdk import SecurityConfig, DownstreamConfig, UpstreamConfig

config = SecurityConfig(
    downstream=DownstreamConfig(
        validate_schema=True,
        verify_signatures=True,
        require_signatures=False,
        enable_rate_limiting=True,
        rate_limit_requests_per_minute=100
    ),
    upstream=UpstreamConfig(
        validate_agent_cards=True,
        verify_signatures=True,
        cache_validation=True,
        cache_timeout=3600  # seconds
    ),
    fail_mode="block",  # "block" | "monitor" | "log"
    timeout_ms=5000
)
```

## Documentation

- [Quickstart Guide](docs/quickstart.md)
- [Configuration Reference](docs/configuration.md)
- [API Documentation](docs/api-reference.md)
- [Examples](examples/)

## Roadmap

- **V1.0** (Q4 2025) - Core middleware (this package)
- **V2.0** (Q2 2026) - Extension protocol (validation feedback)
- **V3.0** (Q3 2026) - Platform integration (trust network)
- **V4.0** (Q4 2026) - Enterprise features (policies, audit logs)

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

## About A2A

The [Agent-to-Agent (A2A) protocol](https://github.com/google/A2A) is an open standard for agent interoperability, supported by Google and 50+ partners including Salesforce, ServiceNow, SAP, Intuit, and more. CapiscIO provides the security layer for production A2A deployments.

## Support

- **Issues:** [GitHub Issues](https://github.com/capiscio/capiscio-sdk-python/issues)
- **Discussions:** [GitHub Discussions](https://github.com/capiscio/capiscio-sdk-python/discussions)
- **Documentation:** [docs.capisc.io](https://docs.capisc.io)
- **Website:** [capisc.io](https://capisc.io)
