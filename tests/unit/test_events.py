"""Unit tests for capiscio_sdk.events module."""

import pytest
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from capiscio_sdk.events import (
    EventEmitter,
    init,
    emit,
    flush,
    _global_emitter,
)


class TestEventEmitter:
    """Tests for EventEmitter class."""

    def test_init_basic(self):
        """Test basic initialization."""
        emitter = EventEmitter(
            server_url="https://registry.capisc.io",
            api_key="sk_test_abc",
            agent_id="test-agent-123",
        )
        
        assert emitter.server_url == "https://registry.capisc.io"
        assert emitter.api_key == "sk_test_abc"
        assert emitter.agent_id == "test-agent-123"
        assert emitter.enabled is True
        assert emitter.batch_size == 10
        assert emitter.flush_interval == 5.0

    def test_init_strips_trailing_slash(self):
        """Test that trailing slash is stripped from server_url."""
        emitter = EventEmitter(
            server_url="https://registry.capisc.io/",
            api_key="sk_test",
            agent_id="test",
        )
        
        assert emitter.server_url == "https://registry.capisc.io"

    def test_init_disabled_without_api_key(self):
        """Test that emitter is disabled without API key."""
        emitter = EventEmitter(
            server_url="https://registry.capisc.io",
            api_key=None,
            agent_id="test",
        )
        
        assert emitter.enabled is False

    def test_init_custom_settings(self):
        """Test initialization with custom settings."""
        emitter = EventEmitter(
            server_url="https://custom.server.com",
            api_key="sk_test",
            agent_id="test",
            agent_name="Custom Agent",
            batch_size=5,
            flush_interval=10.0,
            enabled=False,
        )
        
        assert emitter.batch_size == 5
        assert emitter.flush_interval == 10.0
        assert emitter.enabled is False
        assert emitter.agent_name == "Custom Agent"

    def test_emit_disabled_returns_false(self):
        """Test that emit returns False when disabled."""
        emitter = EventEmitter(
            server_url="https://registry.capisc.io",
            api_key="sk_test",
            agent_id="test",
            enabled=False,
        )
        
        result = emitter.emit("test_event", {"key": "value"})
        
        assert result is False
        assert len(emitter._batch) == 0

    def test_emit_adds_to_batch(self):
        """Test that emit adds event to batch."""
        emitter = EventEmitter(
            server_url="https://registry.capisc.io",
            api_key="sk_test",
            agent_id="test-agent",
            batch_size=10,
        )
        
        result = emitter.emit("test_event", {"key": "value"})
        
        assert result is True
        assert len(emitter._batch) == 1
        
        event = emitter._batch[0]
        assert event["type"] == "test_event"
        assert event["agentId"] == "test-agent"
        assert event["data"] == {"key": "value"}
        assert "id" in event
        assert "timestamp" in event

    def test_emit_with_task_id(self):
        """Test emit with task_id."""
        emitter = EventEmitter(
            server_url="https://registry.capisc.io",
            api_key="sk_test",
            agent_id="test-agent",
        )
        
        emitter.emit("test_event", {}, task_id="task-123")
        
        assert emitter._batch[0]["taskId"] == "task-123"

    def test_emit_with_correlation_id(self):
        """Test emit with correlation_id."""
        emitter = EventEmitter(
            server_url="https://registry.capisc.io",
            api_key="sk_test",
            agent_id="test-agent",
        )
        
        emitter.emit("test_event", {}, correlation_id="corr-456")
        
        assert emitter._batch[0]["correlationId"] == "corr-456"

    def test_emit_flushes_when_batch_full(self):
        """Test that emit flushes when batch is full."""
        emitter = EventEmitter(
            server_url="https://registry.capisc.io",
            api_key="sk_test",
            agent_id="test-agent",
            batch_size=2,
        )
        
        with patch.object(emitter, "flush", return_value=True) as mock_flush:
            emitter.emit("event1", {})
            mock_flush.assert_not_called()
            
            emitter.emit("event2", {})
            mock_flush.assert_called_once()

    def test_emit_with_flush_flag(self):
        """Test emit with flush=True."""
        emitter = EventEmitter(
            server_url="https://registry.capisc.io",
            api_key="sk_test",
            agent_id="test-agent",
        )
        
        with patch.object(emitter, "flush", return_value=True) as mock_flush:
            emitter.emit("test_event", {}, flush=True)
            mock_flush.assert_called_once()

    def test_flush_empty_batch(self):
        """Test flush with empty batch."""
        emitter = EventEmitter(
            server_url="https://registry.capisc.io",
            api_key="sk_test",
            agent_id="test-agent",
        )
        
        result = emitter.flush()
        
        assert result is True

    def test_flush_sends_events(self):
        """Test flush sends events to server."""
        emitter = EventEmitter(
            server_url="https://registry.capisc.io",
            api_key="sk_test",
            agent_id="test-agent",
        )
        
        # Add events directly to batch
        emitter._batch = [
            {"id": "1", "type": "event1", "data": {}},
            {"id": "2", "type": "event2", "data": {}},
        ]
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        
        with patch.object(emitter._client, "post", return_value=mock_response) as mock_post:
            result = emitter.flush()
            
            assert result is True
            assert len(emitter._batch) == 0
            mock_post.assert_called_once()
            
            call_kwargs = mock_post.call_args[1]
            assert call_kwargs["json"]["events"] == [
                {"id": "1", "type": "event1", "data": {}},
                {"id": "2", "type": "event2", "data": {}},
            ]
            assert call_kwargs["headers"]["X-Capiscio-Registry-Key"] == "sk_test"

    def test_flush_requeues_on_failure(self):
        """Test that flush requeues events on server error."""
        emitter = EventEmitter(
            server_url="https://registry.capisc.io",
            api_key="sk_test",
            agent_id="test-agent",
        )
        
        events = [{"id": "1", "type": "event1", "data": {}}]
        emitter._batch = events.copy()
        
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        
        with patch.object(emitter._client, "post", return_value=mock_response):
            result = emitter.flush()
            
            assert result is False
            assert len(emitter._batch) == 1  # Events requeued

    def test_flush_requeues_on_exception(self):
        """Test that flush requeues events on exception."""
        emitter = EventEmitter(
            server_url="https://registry.capisc.io",
            api_key="sk_test",
            agent_id="test-agent",
        )
        
        emitter._batch = [{"id": "1", "type": "event1", "data": {}}]
        
        with patch.object(emitter._client, "post", side_effect=Exception("Network error")):
            result = emitter.flush()
            
            assert result is False
            assert len(emitter._batch) == 1

    def test_flush_disabled(self):
        """Test flush when disabled clears batch."""
        emitter = EventEmitter(
            server_url="https://registry.capisc.io",
            api_key="sk_test",
            agent_id="test-agent",
            enabled=False,
        )
        
        # Manually add event (bypassing emit's disabled check)
        emitter._batch = [{"id": "1", "type": "event1", "data": {}}]
        
        result = emitter.flush()
        
        assert result is False
        assert len(emitter._batch) == 0

    def test_task_started(self):
        """Test task_started convenience method."""
        emitter = EventEmitter(
            server_url="https://registry.capisc.io",
            api_key="sk_test",
            agent_id="test-agent",
        )
        
        with patch.object(emitter, "emit", return_value=True) as mock_emit:
            emitter.task_started("task-123", "Process data", extra="info")
            
            mock_emit.assert_called_once_with(
                EventEmitter.EVENT_TASK_STARTED,
                {"input": "Process data", "extra": "info"},
                task_id="task-123",
                flush=True,
            )

    def test_task_completed(self):
        """Test task_completed convenience method."""
        emitter = EventEmitter(
            server_url="https://registry.capisc.io",
            api_key="sk_test",
            agent_id="test-agent",
        )
        
        with patch.object(emitter, "emit", return_value=True) as mock_emit:
            emitter.task_completed("task-123", "Result data")
            
            mock_emit.assert_called_once_with(
                EventEmitter.EVENT_TASK_COMPLETED,
                {"output": "Result data"},
                task_id="task-123",
                flush=True,
            )

    def test_task_failed(self):
        """Test task_failed convenience method."""
        emitter = EventEmitter(
            server_url="https://registry.capisc.io",
            api_key="sk_test",
            agent_id="test-agent",
        )
        
        with patch.object(emitter, "emit", return_value=True) as mock_emit:
            emitter.task_failed("task-123", "Error message")
            
            mock_emit.assert_called_once_with(
                EventEmitter.EVENT_TASK_FAILED,
                {"error": "Error message"},
                task_id="task-123",
                flush=True,
            )

    def test_tool_call(self):
        """Test tool_call convenience method."""
        emitter = EventEmitter(
            server_url="https://registry.capisc.io",
            api_key="sk_test",
            agent_id="test-agent",
        )
        
        with patch.object(emitter, "emit", return_value=True) as mock_emit:
            emitter.tool_call("search", {"query": "test"}, task_id="task-123")
            
            mock_emit.assert_called_once_with(
                EventEmitter.EVENT_TOOL_CALL,
                {"tool": "search", "arguments": {"query": "test"}},
                task_id="task-123",
            )

    def test_tool_result(self):
        """Test tool_result convenience method."""
        emitter = EventEmitter(
            server_url="https://registry.capisc.io",
            api_key="sk_test",
            agent_id="test-agent",
        )
        
        with patch.object(emitter, "emit", return_value=True) as mock_emit:
            emitter.tool_result("search", ["result1", "result2"])
            
            mock_emit.assert_called_once_with(
                EventEmitter.EVENT_TOOL_RESULT,
                {"tool": "search", "result": ["result1", "result2"]},
                task_id=None,
            )

    def test_close_flushes_and_closes(self):
        """Test close flushes and closes client."""
        emitter = EventEmitter(
            server_url="https://registry.capisc.io",
            api_key="sk_test",
            agent_id="test-agent",
        )
        
        with patch.object(emitter, "flush") as mock_flush:
            with patch.object(emitter._client, "close") as mock_close:
                emitter.close()
                
                mock_flush.assert_called_once()
                mock_close.assert_called_once()

    def test_context_manager(self):
        """Test context manager usage."""
        with patch("capiscio_sdk.events.httpx.Client"):
            emitter = EventEmitter(
                server_url="https://registry.capisc.io",
                api_key="sk_test",
                agent_id="test-agent",
            )
            
            with patch.object(emitter, "close") as mock_close:
                with emitter as e:
                    assert e is emitter
                
                mock_close.assert_called_once()

    def test_event_type_constants(self):
        """Test event type constants."""
        assert EventEmitter.EVENT_TASK_STARTED == "task_started"
        assert EventEmitter.EVENT_TASK_COMPLETED == "task_completed"
        assert EventEmitter.EVENT_TASK_FAILED == "task_failed"
        assert EventEmitter.EVENT_TOOL_CALL == "tool_call"
        assert EventEmitter.EVENT_TOOL_RESULT == "tool_result"
        assert EventEmitter.EVENT_LLM_CALL == "llm_call"
        assert EventEmitter.EVENT_LLM_RESPONSE == "llm_response"
        assert EventEmitter.EVENT_AGENT_STARTED == "agent_started"
        assert EventEmitter.EVENT_AGENT_STOPPED == "agent_stopped"
        assert EventEmitter.EVENT_ERROR == "error"
        assert EventEmitter.EVENT_WARNING == "warning"
        assert EventEmitter.EVENT_INFO == "info"


class TestGlobalFunctions:
    """Tests for global event functions."""

    def test_init_creates_global_emitter(self):
        """Test init creates global emitter."""
        import capiscio_sdk.events as events_module
        
        # Reset global emitter
        events_module._global_emitter = None
        
        result = init(
            api_key="sk_test",
            agent_id="test-agent",
            server_url="https://test.server.com",
        )
        
        assert result is events_module._global_emitter
        assert isinstance(result, EventEmitter)
        assert result.api_key == "sk_test"
        assert result.agent_id == "test-agent"
        
        # Cleanup
        events_module._global_emitter = None

    def test_emit_without_init_raises(self):
        """Test emit raises without init."""
        import capiscio_sdk.events as events_module
        
        # Reset global emitter
        events_module._global_emitter = None
        
        with pytest.raises(RuntimeError, match="Event emitter not initialized"):
            emit("test_event", {})

    def test_emit_with_init(self):
        """Test emit works after init."""
        import capiscio_sdk.events as events_module
        
        # Initialize
        events_module._global_emitter = None
        init(api_key="sk_test", agent_id="test-agent", enabled=False)
        
        # Should not raise (even though disabled)
        result = emit("test_event", {"key": "value"})
        
        assert result is False  # Disabled, so returns False
        
        # Cleanup
        events_module._global_emitter = None

    def test_flush_without_init(self):
        """Test flush returns False without init."""
        import capiscio_sdk.events as events_module
        
        events_module._global_emitter = None
        
        result = flush()
        
        assert result is False

    def test_flush_with_init(self):
        """Test flush works after init."""
        import capiscio_sdk.events as events_module
        
        events_module._global_emitter = None
        emitter = init(api_key="sk_test", agent_id="test-agent")
        
        with patch.object(emitter, "flush", return_value=True) as mock_flush:
            result = flush()
            
            mock_flush.assert_called_once()
            assert result is True
        
        # Cleanup
        events_module._global_emitter = None
