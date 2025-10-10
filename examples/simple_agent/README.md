# Simple Secured A2A Agent Example

This example demonstrates how to build a complete A2A agent with CapiscIO Security integrated.

## What This Example Shows

- ✅ Creating a basic A2A `AgentExecutor`
- ✅ Wrapping it with security using the minimal pattern
- ✅ Starting an A2A server with validation enabled
- ✅ Testing with valid and invalid requests
- ✅ Observing security features in action (rate limiting, validation, etc.)

## Files

- **`agent_executor.py`** - The A2A agent implementation
- **`main.py`** - Server that runs the secured agent
- **`test_client.py`** - Test client demonstrating security features
- **`README.md`** - This file

## Prerequisites

```bash
# Make sure you have the packages installed
pip install capiscio-a2a-security a2a-sdk
```

## Running the Example

### 1. Start the Server

```bash
cd examples/simple_agent
python main.py
```

You should see:

```
🛡️  Starting Simple A2A Agent with CapiscIO Security
============================================================
Security Features Enabled:
  ✅ Message validation
  ✅ Protocol compliance checking
  ✅ Rate limiting (60 requests/minute)
  ✅ URL security (SSRF protection)
  ✅ Validation caching
============================================================
Server starting on http://localhost:8080
```

### 2. Test the Agent

In another terminal:

```bash
python test_client.py
```

This will run several tests:

1. **Valid Request** - Shows successful validation and response
2. **Malformed Message** - Shows security blocking invalid requests
3. **Multiple Requests** - Shows normal agent interactions
4. **Rate Limiting** - (Optional) Shows rate limiting in action

## What You'll See

### ✅ Valid Request Passes

```json
{
  "message_id": "msg-123",
  "sender": {"id": "test-client"},
  "recipient": {"id": "simple-agent"},
  "parts": [...]
}
```

**Result:** Request processed, agent responds

### 🛡️ Invalid Request Blocked

```json
{
  "message": {
    "parts": []  // Empty! Security blocks this
  }
}
```

**Result:** `400 Bad Request` - Security validation failed

### 🚦 Rate Limiting

After 60 requests/minute from the same sender:

**Result:** `429 Too Many Requests` - Rate limit exceeded

## Customizing Security

Edit `main.py` to try different configurations:

```python
# Development mode (more permissive)
secured_agent = secure(agent, SecurityConfig.development())

# Strict mode (maximum security)
secured_agent = secure(agent, SecurityConfig.strict())

# Custom configuration
config = SecurityConfig.production()
config.downstream.rate_limit_requests_per_minute = 100
config.fail_mode = "monitor"  # Log but don't block
secured_agent = secure(agent, config)
```

## Next Steps

1. **Modify the agent** - Add more capabilities to `SimpleAgent`
2. **Add upstream calls** - Make the agent call other agents
3. **Test signature verification** - Add JWS signatures to messages
4. **Monitor logs** - See validation results in real-time
5. **Deploy to production** - Use the patterns from this example

## Integration Test

This example also serves as an integration test. Run it as part of your test suite:

```bash
# Terminal 1: Start server
python main.py &

# Terminal 2: Run tests
python test_client.py

# Check exit code
echo $?  # Should be 0 if all tests pass
```

## Learn More

- [CapiscIO A2A Security Documentation](https://docs.capisc.io/a2a-security/)
- [Configuration Guide](https://docs.capisc.io/a2a-security/guides/configuration/)
- [A2A Protocol Specification](https://a2a-protocol.org)
