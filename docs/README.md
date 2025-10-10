# CapiscIO A2A Security Documentation

This directory contains the source files for the [CapiscIO A2A Security documentation](https://docs.capisc.io/a2a-security).

## Documentation Structure

```
docs/
├── index.md                        # Home page
├── getting-started/                # Getting started guides
│   ├── installation.md             # Installation instructions
│   ├── quickstart.md               # 5-minute quick start
│   └── concepts.md                 # Core concepts
├── guides/                         # User guides
│   ├── integration-patterns.md    # Integration patterns
│   ├── configuration.md            # Configuration guide
│   ├── validation.md               # Validation deep-dive
│   ├── security-best-practices.md # Security best practices
│   └── troubleshooting.md          # Troubleshooting
├── examples/                       # Code examples
│   ├── minimal-integration.md      # Minimal example
│   ├── explicit-configuration.md   # Explicit config
│   ├── decorator-pattern.md        # Decorator pattern
│   ├── custom-presets.md           # Custom presets
│   └── production-deployment.md    # Production example
├── reference/                      # API reference (auto-generated)
│   ├── index.md                    # API overview
│   ├── validators/                 # Validator documentation
│   ├── executor.md                 # Executor reference
│   ├── configuration.md            # Config reference
│   ├── types.md                    # Types reference
│   ├── errors.md                   # Errors reference
│   └── infrastructure/             # Infrastructure docs
├── changelog.md                    # Changelog
└── contributing.md                 # Contributing guide
```

## Building Documentation Locally

### Install Dependencies

```bash
pip install mkdocs-material "mkdocstrings[python]" mike
```

### Serve Locally

```bash
mkdocs serve
```

Then open http://localhost:8000 in your browser.

### Build Static Site

```bash
mkdocs build
```

Output will be in the `site/` directory.

## Deployment

Documentation is automatically deployed via GitHub Actions:

- **On push to main**: Deploys to `dev` version
- **On tag push (v*)**: Deploys to versioned docs
- **Target**: https://docs.capisc.io/a2a-security

### Deployment Workflow

See `.github/workflows/docs.yml` for the full deployment configuration.

## Writing Documentation

### Markdown Files

- Use standard Markdown syntax
- Add front matter if needed
- Use MkDocs Material extensions (admonitions, tabs, etc.)

### Code Examples

Use fenced code blocks with language identifiers:

```python
from capiscio_a2a_security import secure

agent = secure(MyAgentExecutor())
```

### Admonitions

```markdown
!!! note "Important"
    This is a note admonition.

!!! warning
    This is a warning.

!!! tip "Pro Tip"
    This is a tip.
```

### Content Tabs

```markdown
=== "Python"
    ```python
    # Python code
    ```

=== "TypeScript"
    ```typescript
    // TypeScript code
    ```
```

### API Reference

API documentation is auto-generated from Python docstrings using mkdocstrings.

Example:

```markdown
::: capiscio_a2a_security.validators.MessageValidator
    options:
      show_source: true
      heading_level: 2
```

## Style Guide

- Use clear, concise language
- Provide working code examples
- Include expected output where helpful
- Link to related documentation
- Use consistent formatting

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines on contributing to the documentation.

## Questions?

- 🐛 [Report Documentation Issues](https://github.com/capiscio/a2a-security/issues)
- 💬 [Ask Questions](https://github.com/capiscio/a2a-security/discussions)

