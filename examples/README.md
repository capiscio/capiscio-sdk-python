# CapiscIO A2A Security Examples

This directory contains complete, runnable examples demonstrating how to integrate CapiscIO A2A Security with real A2A agents.

## 🚀 Quick Start: Simple Secured Agent

The best way to get started is with our complete example agent:

```bash
cd examples/simple_agent
pip install -r requirements.txt
python main.py
```

Then in another terminal:

```bash
python test_client.py
```

This demonstrates a fully functional A2A agent with security middleware in action!

## Available Examples

### Complete Running Examples

#### **Simple Secured Agent** (`simple_agent/`)

A complete A2A agent with security integrated, demonstrating:

- ✅ Basic agent executor implementation following A2A best practices
- ✅ Security integration using the minimal pattern
- ✅ Testing with valid/invalid requests
- ✅ Rate limiting, validation, and error handling in action
- ✅ Runnable server and test client

**[See detailed README](simple_agent/README.md)**

### Code Pattern Examples

*(Standalone code examples - coming soon)*

- `01_minimal_integration.py` - Minimal one-liner integration
- `02_explicit_config.py` - Explicit configuration pattern
- `03_decorator_pattern.py` - Decorator-based integration
- `04_environment_config.py` - Environment-based configuration

## Running Examples

Each example is self-contained with its own:

- `README.md` - Detailed documentation
- `requirements.txt` - Dependencies (for running examples)
- `main.py` - Server to run
- `test_client.py` - Client to test with

### General Pattern

1. **Install dependencies:**
   ```bash
   cd <example-name>
   pip install -r requirements.txt
   ```

2. **Start the server:**
   ```bash
   python main.py
   ```

3. **Test the agent (in another terminal):**
   ```bash
   python test_client.py
   ```

## What You'll Learn

### Security Integration

All examples demonstrate:

- How to wrap an `AgentExecutor` with security
- Different configuration patterns (minimal, explicit, environment-driven)
- How to customize security settings
- How to observe validation results

### Testing Security

Examples include test clients that demonstrate:

- ✅ Valid requests passing through
- 🛡️ Invalid requests being blocked
- 🚦 Rate limiting in action
- 📊 Validation logging and monitoring

### Production Patterns

Examples follow production best practices:

- Proper error handling
- Structured logging
- Configuration management
- A2A protocol compliance

## Using Examples as Integration Tests

These examples also serve as integration tests. See `tests/integration/` for automated tests using the example agents.

## Next Steps

1. **Run the `simple_agent` example** to see security in action
2. **Modify the agent** to add your own capabilities
3. **Customize security** to match your requirements
4. **Deploy to production** using the patterns learned

## More Resources

- [CapiscIO A2A Security Documentation](https://docs.capisc.io/a2a-security/)
- [Configuration Guide](https://docs.capisc.io/a2a-security/guides/configuration/)
- [A2A Protocol](https://a2a-protocol.org)
- [A2A Samples Repository](https://github.com/a2aproject/a2a-samples)

## Contributing Examples

Have a great example to share? We'd love to include it!

1. Create a new directory: `examples/your-example/`
2. Include: `README.md`, `requirements.txt`, `main.py`, `test_client.py`
3. Follow the existing structure
4. Submit a pull request

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.
