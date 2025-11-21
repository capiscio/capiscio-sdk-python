"""
Run a simple A2A agent with CapiscIO Security.

This example demonstrates:
1. Creating an agent executor
2. Wrapping it with security (Pattern 1: Minimal)
3. Starting an A2A server
4. Handling requests with validation

Usage:
    python examples/simple_agent/main.py
    
    # In another terminal:
    python examples/simple_agent/test_client.py
"""

import asyncio
from a2a.server.server import A2AServer
from capiscio_sdk import secure, SecurityConfig
from agent_executor import SimpleAgentExecutor


def main():
    """Start the secured A2A agent server."""
    
    # Create the agent executor
    agent = SimpleAgentExecutor()
    
    # Wrap it with security (Pattern 1: Minimal with production defaults)
    secured_agent = secure(agent, SecurityConfig.production())
    
    print("🛡️  Starting Simple A2A Agent with CapiscIO Security")
    print("=" * 60)
    print("Security Features Enabled:")
    print("  ✅ Message validation")
    print("  ✅ Protocol compliance checking")
    print("  ✅ Rate limiting (60 requests/minute)")
    print("  ✅ URL security (SSRF protection)")
    print("  ✅ Validation caching")
    print("=" * 60)
    print("Server starting on http://localhost:8080")
    print("Send requests to test the security features!")
    print("\n💡 Tip: Try sending malformed messages to see validation in action")
    print("=" * 60)
    
    # Create and start the A2A server
    server = A2AServer(
        agent_executor=secured_agent,
        host="localhost",
        port=8080,
    )
    
    # Run the server
    asyncio.run(server.run())


if __name__ == "__main__":
    main()
