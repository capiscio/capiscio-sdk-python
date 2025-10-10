"""
Simple A2A Agent with CapiscIO Security

This is a complete, runnable example showing how to integrate CapiscIO A2A Security
with a real A2A agent. This agent responds to greetings and demonstrates all
security features.
"""

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.utils import new_agent_text_message


class SimpleAgent:
    """A simple agent that responds to greetings."""
    
    async def invoke(self, message: str) -> str:
        """Process the user's message and return a response."""
        message_lower = message.lower()
        
        if "hello" in message_lower or "hi" in message_lower:
            return "Hello! I'm a secured A2A agent. How can I help you today?"
        elif "help" in message_lower:
            return "I can respond to greetings and demonstrate security features. Try saying 'hello'!"
        elif "security" in message_lower:
            return "I'm protected by CapiscIO A2A Security, which validates all requests and prevents attacks!"
        else:
            return f"You said: {message}. I'm a simple demo agent protected by security middleware."


class SimpleAgentExecutor(AgentExecutor):
    """
    Agent Executor implementing the A2A protocol.
    
    This executor handles:
    - Incoming requests via execute()
    - Task cancellation via cancel()
    """
    
    def __init__(self):
        """Initialize the agent executor."""
        self.agent = SimpleAgent()
    
    async def execute(
        self,
        context: RequestContext,
        event_queue: EventQueue,
    ) -> None:
        """
        Handle incoming A2A requests.
        
        Args:
            context: Request context containing the message and task info
            event_queue: Queue for sending events back to the client
        """
        # Extract the user's message
        message = context.message
        
        # Get the text from the message parts
        text = ""
        if message.parts and len(message.parts) > 0:
            part = message.parts[0]
            if "root" in part and "parts" in part["root"]:
                root_parts = part["root"]["parts"]
                if root_parts and len(root_parts) > 0 and "text" in root_parts[0]:
                    text = root_parts[0]["text"]
        
        # Process the message
        result = await self.agent.invoke(text or "hello")
        
        # Send response back to client
        await event_queue.enqueue_event(new_agent_text_message(result))
    
    async def cancel(
        self,
        context: RequestContext,
        event_queue: EventQueue,
    ) -> None:
        """
        Handle task cancellation requests.
        
        Args:
            context: Request context
            event_queue: Queue for sending events
        """
        # This simple agent doesn't support cancellation
        await event_queue.enqueue_event(
            new_agent_text_message("Task cancellation not supported by this simple agent.")
        )
