---
title: Installation - A2A Security Documentation
description: Install A2A Security Python middleware for runtime agent protection. Supports Python 3.10+ on Linux, macOS, and Windows with pip or Poetry.
keywords: A2A Security installation, Python middleware, agent protection, pip install, Poetry, runtime security
---

# Installation

## Requirements

- **Python:** 3.10 or higher
- **Operating System:** Linux, macOS, or Windows
- **Dependencies:** Automatically installed via pip

## Install from PyPI

The simplest way to install CapiscIO A2A Security is from PyPI:

```bash
pip install capiscio-a2a-security
```

This installs the package and all required dependencies:

- `a2a` - A2A SDK
- `httpx` - Async HTTP client
- `pydantic` - Data validation
- `cryptography` - Signature verification and certificate handling
- `cachetools` - In-memory caching
- `PyJWT` - JWT token handling

## Install from Source

To install the latest development version:

```bash
git clone https://github.com/capiscio/a2a-security.git
cd a2a-security
pip install -e ".[dev]"
```

The `[dev]` extra installs development dependencies including:

- `pytest` - Testing framework
- `pytest-asyncio` - Async test support
- `pytest-cov` - Coverage reporting
- `black` - Code formatting
- `ruff` - Linting
- `mypy` - Type checking

## Verify Installation

Verify the installation by importing the package:

```python
import capiscio_a2a_security

print(capiscio_a2a_security.__version__)
# Output: 1.0.0
```

Or check available validators:

```python
from capiscio_a2a_security import (
    MessageValidator,
    ProtocolValidator,
    SignatureValidator,
    SemverValidator,
    URLSecurityValidator,
    AgentCardValidator,
    CertificateValidator,
)

print("✅ All validators available!")
```

## Optional Dependencies

### Production Monitoring

For production monitoring and observability:

```bash
pip install capiscio-a2a-security[monitoring]
```

This adds:

- `prometheus-client` - Metrics collection
- `structlog` - Structured logging

###Documentation Tools

To build documentation locally:

```bash
pip install capiscio-a2a-security[docs]
```

This adds:

- `mkdocs-material` - Documentation theme
- `mkdocstrings[python]` - API reference generation
- `mike` - Multi-version docs

## Virtual Environment (Recommended)

We recommend using a virtual environment:

```bash
# Create virtual environment
python -m venv .venv

# Activate (Linux/macOS)
source .venv/bin/activate

# Activate (Windows)
.venv\Scripts\activate

# Install package
pip install capiscio-a2a-security
```

## Docker

If you're using Docker, add to your `Dockerfile`:

```dockerfile
FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install capiscio-a2a-security
RUN pip install --no-cache-dir capiscio-a2a-security

COPY . .

CMD ["python", "main.py"]
```

## Troubleshooting

### Import Errors

If you see import errors after installation:

```python
ModuleNotFoundError: No module named 'capiscio_a2a_security'
```

**Solution:** Ensure you're in the correct virtual environment:

```bash
which python  # Should point to your venv
pip list | grep capiscio  # Verify package is installed
```

### Dependency Conflicts

If you encounter dependency conflicts:

```bash
# Check for conflicts
pip check

# Reinstall with --force-reinstall
pip install --force-reinstall capiscio-a2a-security
```

### Version Issues

To upgrade to the latest version:

```bash
pip install --upgrade capiscio-a2a-security
```

To install a specific version:

```bash
pip install capiscio-a2a-security==1.0.0
```

## Next Steps

Now that you have CapiscIO A2A Security installed:

1. [Quick Start Guide](quickstart.md) - Integrate security in 5 minutes
2. [Core Concepts](concepts.md) - Understand how validation works
3. [Scoring Guide](../guides/scoring.md) - Learn about the scoring system

## Getting Help

If you encounter installation issues:

-  [Report an Issue](https://github.com/capiscio/a2a-security/issues)
- 💬 [Ask in Discussions](https://github.com/capiscio/a2a-security/discussions)
