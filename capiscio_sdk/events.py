"""
Event emission for CapiscIO agents.

Provides a simple interface for emitting events to the CapiscIO registry.
Events are used for observability, auditing, and real-time monitoring.

Example:
    from capiscio_sdk.events import EventEmitter
    
    emitter = EventEmitter(
        server_url="https://registry.capisc.io",
        api_key="sk_live_...",
        agent_id="my-agent-id",
    )
    
    emitter.emit("task_started", {"task_id": "123", "input": "..."})
    emitter.emit("tool_call", {"tool": "search", "query": "AI news"})
    emitter.emit("task_completed", {"task_id": "123", "output": "..."})
"""

import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)


class EventEmitter:
    """
    Emits events to the CapiscIO registry.
    
    Events provide visibility into agent behavior for:
    - Real-time monitoring in the dashboard
    - Audit trails for compliance
    - Analytics and debugging
    
    Attributes:
        server_url: Registry server URL
        api_key: API key for authentication
        agent_id: Agent ID for event attribution
    """
    
    # Standard event types
    EVENT_TASK_STARTED = "task_started"
    EVENT_TASK_COMPLETED = "task_completed"
    EVENT_TASK_FAILED = "task_failed"
    EVENT_TOOL_CALL = "tool_call"
    EVENT_TOOL_RESULT = "tool_result"
    EVENT_LLM_CALL = "llm_call"
    EVENT_LLM_RESPONSE = "llm_response"
    EVENT_AGENT_STARTED = "agent_started"
    EVENT_AGENT_STOPPED = "agent_stopped"
    EVENT_ERROR = "error"
    EVENT_WARNING = "warning"
    EVENT_INFO = "info"

    # Middleware auto-event types (emitted automatically by CapiscioMiddleware)
    EVENT_REQUEST_RECEIVED = "request.received"
    EVENT_REQUEST_COMPLETED = "request.completed"
    EVENT_REQUEST_FAILED = "request.failed"
    EVENT_VERIFICATION_SUCCESS = "verification.success"
    EVENT_VERIFICATION_FAILED = "verification.failed"
    
    def __init__(
        self,
        server_url: str = "https://registry.capisc.io",
        api_key: Optional[str] = None,
        agent_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        batch_size: int = 10,
        flush_interval: float = 5.0,
        enabled: bool = True,
    ):
        """
        Initialize the event emitter.
        
        Args:
            server_url: Registry server URL (default: production)
            api_key: API key for authentication
            agent_id: Agent ID for event attribution
            agent_name: Human-readable agent name (for logging)
            batch_size: Number of events to batch before sending
            flush_interval: Max seconds between flushes
            enabled: Whether to actually send events (for testing)
        """
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.agent_id = agent_id
        self.agent_name = agent_name or agent_id
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.enabled = enabled
        
        self._client = httpx.Client(timeout=10.0)
        self._batch: list = []
        self._batch_lock = threading.Lock()
        self._last_flush = time.time()
        
        # Validate config
        if enabled and not api_key:
            logger.warning("EventEmitter: No API key provided, events will not be sent")
            self.enabled = False
    
    def emit(
        self,
        event_type: str,
        data: Optional[Dict[str, Any]] = None,
        *,
        task_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        flush: bool = False,
    ) -> bool:
        """
        Emit an event to the registry.
        
        Args:
            event_type: Type of event (e.g., "task_started", "tool_call")
            data: Event-specific data
            task_id: Optional task ID for correlation
            correlation_id: Optional correlation ID for tracing
            flush: Whether to flush immediately (default: batch)
            
        Returns:
            True if event was queued/sent successfully
            
        Example:
            emitter.emit("task_started", {
                "task_id": "abc123",
                "input": "Research AI trends",
            })
        """
        if not self.enabled:
            return False
        
        event = {
            "id": str(uuid.uuid4()),
            "type": event_type,
            "agentId": self.agent_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data or {},
        }
        
        if task_id:
            event["taskId"] = task_id
        if correlation_id:
            event["correlationId"] = correlation_id
        
        with self._batch_lock:
            self._batch.append(event)
            should_flush = flush or len(self._batch) >= self.batch_size
        
        # Flush if batch is full or flush requested
        if should_flush:
            return self.flush()
        
        # Flush if interval exceeded
        if time.time() - self._last_flush > self.flush_interval:
            return self.flush()
        
        return True
    
    def flush(self) -> bool:
        """
        Send all batched events to the registry.
        
        Returns:
            True if flush was successful
        """
        if not self._batch:
            return True
        
        if not self.enabled:
            with self._batch_lock:
                self._batch.clear()
            return False
        
        with self._batch_lock:
            events_to_send = self._batch.copy()
            self._batch.clear()
        self._last_flush = time.time()
        
        try:
            headers = {
                "Content-Type": "application/json",
                "X-Capiscio-Registry-Key": self.api_key,
            }
            
            # Send batch
            response = self._client.post(
                f"{self.server_url}/v1/events",
                headers=headers,
                json={"events": events_to_send},
            )
            
            if response.status_code in (200, 201, 202):
                logger.debug(f"Sent {len(events_to_send)} events")
                return True
            else:
                logger.warning(f"Failed to send events: {response.status_code} {response.text}")
                # Re-queue events on failure
                with self._batch_lock:
                    self._batch.extend(events_to_send)
                return False
                
        except Exception as e:
            logger.error(f"Error sending events: {e}")
            # Re-queue events on failure
            with self._batch_lock:
                self._batch.extend(events_to_send)
            return False
    
    def task_started(self, task_id: str, input_text: str, **kwargs) -> bool:
        """Convenience method for task_started events."""
        return self.emit(
            self.EVENT_TASK_STARTED,
            {"input": input_text, **kwargs},
            task_id=task_id,
            flush=True,
        )
    
    def task_completed(self, task_id: str, output: str, **kwargs) -> bool:
        """Convenience method for task_completed events."""
        return self.emit(
            self.EVENT_TASK_COMPLETED,
            {"output": output, **kwargs},
            task_id=task_id,
            flush=True,
        )
    
    def task_failed(self, task_id: str, error: str, **kwargs) -> bool:
        """Convenience method for task_failed events."""
        return self.emit(
            self.EVENT_TASK_FAILED,
            {"error": error, **kwargs},
            task_id=task_id,
            flush=True,
        )
    
    def tool_call(self, tool_name: str, arguments: Dict[str, Any], task_id: Optional[str] = None, **kwargs) -> bool:
        """Convenience method for tool_call events."""
        return self.emit(
            self.EVENT_TOOL_CALL,
            {"tool": tool_name, "arguments": arguments, **kwargs},
            task_id=task_id,
        )
    
    def tool_result(self, tool_name: str, result: Any, task_id: Optional[str] = None, **kwargs) -> bool:
        """Convenience method for tool_result events."""
        return self.emit(
            self.EVENT_TOOL_RESULT,
            {"tool": tool_name, "result": result, **kwargs},
            task_id=task_id,
        )
    
    def close(self) -> None:
        """Flush remaining events and close the client."""
        self.flush()
        self._client.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


# Global emitter for simple usage
_global_emitter: Optional[EventEmitter] = None


def init(
    api_key: str,
    agent_id: str,
    server_url: str = "https://registry.capisc.io",
    **kwargs,
) -> EventEmitter:
    """
    Initialize the global event emitter.
    
    Args:
        api_key: API key for authentication
        agent_id: Agent ID for event attribution
        server_url: Registry server URL
        
    Returns:
        The global EventEmitter instance
        
    Example:
        from capiscio_sdk import events
        
        events.init(api_key="sk_live_...", agent_id="my-agent")
        events.emit("task_started", {"task_id": "123"})
    """
    global _global_emitter
    _global_emitter = EventEmitter(
        server_url=server_url,
        api_key=api_key,
        agent_id=agent_id,
        **kwargs,
    )
    return _global_emitter


def emit(event_type: str, data: Optional[Dict[str, Any]] = None, **kwargs) -> bool:
    """
    Emit an event using the global emitter.
    
    Must call `init()` first.
    
    Args:
        event_type: Type of event
        data: Event data
        **kwargs: Additional arguments passed to EventEmitter.emit()
        
    Returns:
        True if event was queued/sent
    """
    if _global_emitter is None:
        raise RuntimeError("Event emitter not initialized. Call events.init() first.")
    return _global_emitter.emit(event_type, data, **kwargs)


def flush() -> bool:
    """Flush all pending events."""
    if _global_emitter is None:
        return False
    return _global_emitter.flush()
