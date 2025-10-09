# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **security@capisc.io**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to Expect

- **Response time:** Within 48 hours
- **Updates:** Every 5 business days
- **Resolution:** We aim to patch critical issues within 7 days

### Disclosure Policy

- Security issues are embargoed until a fix is released
- Credit will be given to reporters (unless anonymity is requested)
- CVE IDs will be assigned for confirmed vulnerabilities

## Security Best Practices

When using Capiscio A2A Security:

1. **Keep dependencies updated**
   ```bash
   pip install --upgrade capiscio-a2a-security
   ```

2. **Use signature verification**
   ```python
   config = SecurityConfig(
       downstream=DownstreamConfig(verify_signatures=True)
   )
   ```

3. **Enable rate limiting**
   ```python
   config = SecurityConfig(
       downstream=DownstreamConfig(enable_rate_limiting=True)
   )
   ```

4. **Use strict mode in production**
   ```python
   config = SecurityConfig.strict()
   ```

5. **Monitor logs for validation failures**
   ```python
   config = SecurityConfig(log_validation_failures=True)
   ```

## Known Security Considerations

### JWS Signature Verification

- Uses `cryptography` library (audited, industry standard)
- Supports RS256, RS384, RS512 algorithms
- JWKS endpoints must use HTTPS

### Rate Limiting

- In-memory implementation (single-server only)
- For distributed systems, use external rate limiter

### Caching

- Validation results cached with TTL
- Cache keys include content hashes
- Invalidation on configuration changes

## Security Scanning

This project uses:
- Dependabot for dependency updates
- CodeQL for static analysis
- Safety for Python dependency checking

## Contact

For security concerns: security@capisc.io
