# Quick Start

Get your A2A agent protected in **5 minutes** with CapiscIO A2A Security.

## See the Difference

### ❌ Without Security

```python
# Your vulnerable agent
class MyAgentExecutor(AgentExecutor):
    async def execute(self, context, event_queue):
        # Process message - but what if it's malicious?
        message = context.message
        url = message.parts[0].get("url")  # What if this is http://localhost/admin?
        await fetch_data(url)  # 💥 SSRF attack succeeds!
```

**Result:** Attacker accesses your internal services, reads secrets, or worse.

### ✅ With Security (One Line)

```python
from capiscio_a2a_security import secure

# Same agent, now protected
secured_agent = secure(MyAgentExecutor())

# Same attack attempted:
# 🛡️ URL validation catches SSRF
# 🚫 Request blocked
# 📝 Attack logged
# ✅ Your agent stays safe
```

**Result:** Attack blocked automatically. You see the attempt in logs. Your agent continues safely.

---

## Prerequisites

- Python 3.10 or higher
- An existing A2A agent executor
- Basic familiarity with the [A2A protocol](https://github.com/google/A2A)

## Installation

```bash
pip install capiscio-a2a-security
```

## Minimal Integration (1 Line of Code)


The fastest way to add security to your agent:

```python
from capiscio_a2a_security import secure
from my_agent import MyAgentExecutor

# Wrap your agent with security (production defaults)
secured_agent = secure(MyAgentExecutor())

# Validate an agent card and access scores
result = await secured_agent.validate_agent_card(card_url)
print(result.compliance.total, result.trust.total, result.availability.total)
```

That's it! Your agent now has:

- ✅ Message validation
- ✅ Protocol compliance checking
- ✅ Rate limiting (60 requests/minute)
- ✅ URL security (SSRF protection)
- ✅ Validation caching

## Complete Example

Here's a complete working example with an A2A server:

```python
from capiscio_a2a_security import secure
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a import AgentExecutor, RequestContext, EventQueue, Message

# 1. Define your agent
class MyAgentExecutor(AgentExecutor):
    """Your agent logic."""
    
    async def execute(
        self,
        context: RequestContext,
        event_queue: EventQueue
    ) -> None:
        """Handle incoming requests."""
        # Your agent implementation
        message = context.message
        print(f"Processing message: {message.message_id}")
        
        # Do your agent work here
        # ...
        
        # Send response
        response = Message(
            message_id="response-123",
            sender={"id": "my-agent"},
            recipient={"id": message.sender["id"]},
            parts=[{
                "root": {
                    "role": "assistant",
                    "parts": [{"text": "Task completed!"}]
                }
            }]
        )
        await event_queue.put(response)

# 2. Wrap with security
secured_agent = secure(MyAgentExecutor())

# 3. Create A2A request handler
handler = DefaultRequestHandler(
    agent_executor=secured_agent,
    task_store=InMemoryTaskStore()
)

# 4. Use in your server (FastAPI example)
from fastapi import FastAPI, Request

app = FastAPI()

@app.post("/v1/tasks")
async def handle_task(request: Request):
    # A2A request handling
    body = await request.json()
    return await handler.handle(body)
```

## What Just Happened?

When you wrapped your agent with `secure()`, it automatically:

1. **Validates incoming messages** before they reach your agent
2. **Checks protocol compliance** (versions, headers, state transitions)
3. **Rate limits requests** (60/minute per agent by default)
4. **Validates URLs** to prevent SSRF attacks
5. **Caches results** for better performance

## Testing It Out

Send a test request to your agent:

```python
import httpx
from a2a.types import Message, TextPart, Role, MessageSendParams

# Create a proper A2A message
message = Message(
    message_id="test-123",
    role=Role.user,
    parts=[TextPart(text="Hello!")]
)

response = httpx.post(
    "http://localhost:8000/v1/tasks",
    json=MessageSendParams(message=message).model_dump(mode="json")
)

print(response.json())
```

## Seeing Validation in Action

### Valid Request ✅

```python
# This passes all validations
secured_agent = secure(MyAgentExecutor())

context = RequestContext(
    message=Message(
        message_id="msg-123",
        sender={"id": "agent-1"},
        recipient={"id": "agent-2"},
        parts=[{"root": {"role": "user", "parts": [{"text": "Hi"}]}}]
    )
)

# Executes successfully
await secured_agent.execute(context, event_queue)
```

### Invalid Request ❌

```python
from capiscio_a2a_security.errors import CapiscIOValidationError

try:
    # Missing required field (message_id)
    context = RequestContext(
        message=Message(
            message_id="",  # Empty!
            sender={"id": "agent-1"},
            recipient={"id": "agent-2"},
            parts=[]
        )
    )
    
    await secured_agent.execute(context, event_queue)
    
except CapiscIOValidationError as e:
    print(f"Validation failed: {e.message}")
    print(f"Errors: {e.errors}")
    # Output: Validation failed: Message validation failed
    # Errors: ['Message ID is required', 'Message has no parts']
```

## Configuration Presets

The `secure()` function uses **production** defaults. You can choose different presets:

📖 **For detailed configuration options, see the [Configuration Guide](../guides/configuration.md).**

```python
from capiscio_a2a_security import secure, SecurityConfig

# Development: Permissive, fast iteration
agent = secure(MyAgentExecutor(), SecurityConfig.development())

# Production: Balanced (default)
agent = secure(MyAgentExecutor(), SecurityConfig.production())

# Strict: Maximum security
agent = secure(MyAgentExecutor(), SecurityConfig.strict())

# From Environment: Load from env vars
agent = secure(MyAgentExecutor(), SecurityConfig.from_env())
```

### Preset Comparison

| Feature | Development | Production | Strict |
|---------|------------|------------|--------|
| **Signature Verification** | ⚪ Optional | ⚪ Optional | ✅ Required |
| **Rate Limiting** | ❌ Disabled | ✅ 60/min | ✅ 60/min |
| **Fail Mode** | 📝 Log | 🚫 Block | 🚫 Block |
| **Schema Validation** | ✅ Enabled | ✅ Enabled | ✅ Enabled |
| **Upstream Testing** | ❌ Disabled | ❌ Disabled | ✅ Enabled |

## Handling Validation Failures

Choose how your agent responds to validation failures:

```python
config = SecurityConfig.production()
config.fail_mode = "block"    # Reject request (default)
# config.fail_mode = "monitor"  # Log but allow
# config.fail_mode = "log"      # Only log, no blocking

agent = secure(MyAgentExecutor(), config)
```

## Viewing Validation Results


Enable logging to see what's being validated:

```python
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("capiscio_a2a_security")

# Now you'll see validation logs:
# INFO - Message validation passed (compliance: 100, trust: 90)
# INFO - Protocol validation passed (compliance: 100)
# WARNING - Rate limit: 45/60 requests used
```

## Next Steps

### Learn More

- [Core Concepts](concepts.md) - Understand how validation works
- [Scoring System](../guides/scoring.md) - Learn about three-dimensional scoring
- [Configuration Guide](../guides/configuration.md) - All configuration options explained
- [Changelog](../changelog.md) - See version history
- [Contributing](../contributing.md) - Contribute to the project

### Coming Soon

Additional guides and examples are being developed:
- Integration patterns and decorator usage
- Production deployment examples
- Security best practices

## Common Questions


??? question "How do I access scores in my code?"
    Use the new three-dimensional scoring API:
    
    ```python
    result = await secured_agent.validate_agent_card(card_url)
    print(result.compliance.total, result.trust.total, result.availability.total)
    ```

??? question "Does this work with Google ADK agents?"
    Yes! CapiscIO A2A Security works with any A2A-compliant agent, including those built with Google's Agent Development Kit (ADK).
    
    ```python
    from adk import ADKAgent
    from capiscio_a2a_security import secure
    
    adk_agent = ADKAgent(...)
    secured_agent = secure(adk_agent)
    ```

??? question "What's the performance overhead?"
    Minimal! With caching enabled, typical overhead is <5ms per request. Validation results are cached with configurable TTL (default 1 hour).

??? question "Can I disable specific validators?"
    Yes! Use explicit configuration:
    
    ```python
    config = SecurityConfig.production()
    config.downstream.validate_schema = True
    config.downstream.verify_signatures = False  # Disable signatures
    config.downstream.enable_rate_limiting = True
    
    agent = secure(MyAgentExecutor(), config)
    ```

??? question "How do I test in development?"
    Use the development preset which is more permissive:
    
    ```python
    agent = secure(MyAgentExecutor(), SecurityConfig.development())
    ```

??? question "Does this require changes to other agents?"
    No! This is unilateral protection. You don't need permission or cooperation from peers.

## Getting Help

- 📖 [Full Documentation](../index.md)
- 🐛 [Report Issues](https://github.com/capiscio/a2a-security/issues)
- 💬 [Ask Questions](https://github.com/capiscio/a2a-security/discussions)
- 📦 [View on PyPI](https://pypi.org/project/capiscio-a2a-security/)
