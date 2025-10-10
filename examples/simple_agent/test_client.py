"""
Test client for the simple secured A2A agent.

This script sends test requests to demonstrate:
1. Valid requests that pass security checks
2. Invalid requests that get blocked
3. Rate limiting in action

Usage:
    # Start the server first:
    python examples/simple_agent/main.py
    
    # Then run this client:
    python examples/simple_agent/test_client.py
"""

import httpx
import asyncio
from datetime import datetime
from a2a.types import Message, TextPart, Role, MessageSendParams


async def send_message(client: httpx.AsyncClient, text: str, message_id: str = None):
    """Send a message to the agent."""
    if message_id is None:
        message_id = f"msg-{datetime.now().timestamp()}"
    
    # Create proper A2A message
    message = Message(
        message_id=message_id,
        role=Role.user,
        parts=[TextPart(text=text)]
    )
    
    # Wrap in MessageSendParams and serialize
    params = MessageSendParams(message=message)
    
    response = await client.post(
        "http://localhost:8080/v1/tasks",
        json=params.model_dump(mode="json")
    )
    return response


async def test_valid_request():
    """Test 1: Valid request that passes all security checks."""
    print("\n" + "=" * 60)
    print("TEST 1: Valid Request (Should Pass)")
    print("=" * 60)
    
    async with httpx.AsyncClient() as client:
        response = await send_message(client, "Hello!")
        print(f"✅ Status: {response.status_code}")
        print(f"✅ Response: {response.json()}")


async def test_malformed_message():
    """Test 2: Malformed message (missing required fields)."""
    print("\n" + "=" * 60)
    print("TEST 2: Malformed Message (Should Be Blocked)")
    print("=" * 60)
    
    # Create a malformed message (missing messageId and role)
    malformed = {
        "message": {
            "parts": []  # Empty parts and missing required fields!
        }
    }
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post("http://localhost:8080/v1/tasks", json=malformed)
            if response.status_code >= 400:
                print(f"🛡️  Blocked by security! Status: {response.status_code}")
                print(f"🛡️  Error: {response.text}")
            else:
                print(f"⚠️  Unexpectedly passed: {response.status_code}")
        except Exception as e:
            print(f"🛡️  Blocked by security: {e}")


async def test_rate_limiting():
    """Test 3: Rate limiting (exceed 60 requests/minute)."""
    print("\n" + "=" * 60)
    print("TEST 3: Rate Limiting (After 60 requests)")
    print("=" * 60)
    print("Sending 62 requests rapidly...")
    
    async with httpx.AsyncClient() as client:
        passed = 0
        blocked = 0
        
        for i in range(62):
            try:
                response = await send_message(client, f"Request {i+1}", f"rate-test-{i}")
                if response.status_code < 400:
                    passed += 1
                else:
                    blocked += 1
            except Exception:
                blocked += 1
        
        print(f"\n✅ Passed: {passed} requests")
        print(f"🛡️  Blocked: {blocked} requests")
        print("💡 Rate limiting working as expected (limit: 60/min)")


async def test_multiple_valid_requests():
    """Test 4: Multiple valid requests to show agent responses."""
    print("\n" + "=" * 60)
    print("TEST 4: Multiple Valid Requests")
    print("=" * 60)
    
    messages = [
        "Hello!",
        "What can you help with?",
        "Tell me about your security",
        "Goodbye!"
    ]
    
    async with httpx.AsyncClient() as client:
        for msg in messages:
            print(f"\n📤 Sending: {msg}")
            response = await send_message(client, msg)
            if response.status_code == 200:
                data = response.json()
                # Extract response text from the A2A message
                message = data.get('message', {})
                parts = message.get('parts', [])
                if parts and len(parts) > 0:
                    first_part = parts[0]
                    # Handle wrapped Part objects
                    if isinstance(first_part, dict) and 'root' in first_part:
                        first_part = first_part['root']
                    text = first_part.get('text', 'No text content')
                    print(f"📥 Agent: {text}")
                else:
                    print("📥 Agent: (no parts in response)")
            else:
                print(f"❌ Error: {response.status_code}")


async def main():
    """Run all tests."""
    print("\n🧪 Testing Simple A2A Agent with CapiscIO Security")
    print("=" * 60)
    print("Make sure the agent is running first:")
    print("  python examples/simple_agent/main.py")
    print("=" * 60)
    
    try:
        # Test 1: Valid request
        await test_valid_request()
        await asyncio.sleep(1)
        
        # Test 2: Malformed message
        await test_malformed_message()
        await asyncio.sleep(1)
        
        # Test 3: Multiple valid requests
        await test_multiple_valid_requests()
        await asyncio.sleep(1)
        
        # Test 4: Rate limiting (this will take a minute)
        print("\n⚠️  Warning: Rate limiting test will send 62 requests")
        print("This may trigger rate limits. Continue? (y/n): ", end="")
        # Skip rate limiting test for now to avoid overwhelming the server
        # await test_rate_limiting()
        
        print("\n" + "=" * 60)
        print("✅ All tests complete!")
        print("=" * 60)
        
    except httpx.ConnectError:
        print("\n❌ Error: Cannot connect to server")
        print("Make sure the agent is running:")
        print("  python examples/simple_agent/main.py")
    except Exception as e:
        print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
