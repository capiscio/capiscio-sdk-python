"""Tests for security executor.

NOTE: These unit tests need to be updated for the new AgentExecutor interface.
The integration tests (test_real_executor.py) validate the actual behavior.
These are temporarily skipped pending refactor.
"""
import pytest
from unittest.mock import Mock
from capiscio_a2a_security.executor import (
    CapiscioSecurityExecutor,
    secure,
    secure_agent,
)
from capiscio_a2a_security.config import SecurityConfig
from capiscio_a2a_security.errors import (
    CapiscioValidationError,
    CapiscioRateLimitError,
)

pytest.skip("Executor unit tests need refactoring for AgentExecutor interface - see integration tests", allow_module_level=True)


@pytest.fixture
def valid_message():
    """Create a valid test message."""
    return {
        "id": "msg_123",
        "sender": {"id": "agent_1", "url": "https://agent1.example.com"},
        "recipient": {"id": "agent_2", "url": "https://agent2.example.com"},
        "timestamp": 1234567890.0,
        "parts": [{"type": "text", "content": "Hello, world!"}],
    }


@pytest.fixture
def invalid_message():
    """Create an invalid test message."""
    return {"id": "msg_456"}  # Missing required fields


@pytest.fixture
def mock_agent():
    """Create a mock agent executor."""
    agent = Mock()
    agent.execute.return_value = {"status": "success"}
    return agent


def test_executor_wraps_agent(mock_agent, valid_message):
    """Test that executor wraps agent correctly."""
    executor = CapiscioSecurityExecutor(mock_agent)
    result = executor.execute(valid_message)
    
    assert result == {"status": "success"}
    mock_agent.execute.assert_called_once()


def test_executor_validates_message(mock_agent, invalid_message):
    """Test that executor validates messages."""
    config = SecurityConfig(fail_mode="block")
    executor = CapiscioSecurityExecutor(mock_agent, config)
    
    with pytest.raises(CapiscioValidationError):
        executor.execute(invalid_message)


def test_executor_monitor_mode(mock_agent, invalid_message):
    """Test executor in monitor mode (logs but doesn't block)."""
    config = SecurityConfig(fail_mode="monitor")
    executor = CapiscioSecurityExecutor(mock_agent, config)
    
    # Should not raise, but should log warning
    result = executor.execute(invalid_message)
    assert result == {"status": "success"}


def test_executor_log_mode(mock_agent, invalid_message):
    """Test executor in log mode."""
    config = SecurityConfig(fail_mode="log")
    executor = CapiscioSecurityExecutor(mock_agent, config)
    
    # Should not raise, just log
    result = executor.execute(invalid_message)
    assert result == {"status": "success"}


def test_executor_rate_limiting(mock_agent, valid_message):
    """Test rate limiting functionality."""
    config = SecurityConfig.production()
    config.downstream.enable_rate_limiting = True
    config.downstream.rate_limit_requests_per_minute = 2
    config.fail_mode = "block"
    
    executor = CapiscioSecurityExecutor(mock_agent, config)
    
    # First two requests should succeed
    executor.execute(valid_message)
    executor.execute(valid_message)
    
    # Third should fail
    with pytest.raises(CapiscioRateLimitError):
        executor.execute(valid_message)


def test_executor_caching(mock_agent, valid_message):
    """Test validation result caching."""
    config = SecurityConfig.production()
    config.upstream.cache_validation = True
    
    executor = CapiscioSecurityExecutor(mock_agent, config)
    
    # Execute same message twice
    executor.execute(valid_message)
    executor.execute(valid_message)
    
    # Should have cached the validation result
    assert executor._cache.size() > 0


def test_executor_no_validation(mock_agent, invalid_message):
    """Test executor with validation disabled."""
    config = SecurityConfig.development()
    config.downstream.validate_schema = False
    
    executor = CapiscioSecurityExecutor(mock_agent, config)
    
    # Should not validate, so invalid message passes through
    result = executor.execute(invalid_message)
    assert result == {"status": "success"}


def test_secure_helper(mock_agent, valid_message):
    """Test the secure() helper function."""
    executor = secure(mock_agent)
    result = executor.execute(valid_message)
    
    assert result == {"status": "success"}
    assert isinstance(executor, CapiscioSecurityExecutor)


def test_secure_helper_with_config(mock_agent, invalid_message):
    """Test secure() helper with custom config."""
    config = SecurityConfig(fail_mode="block")
    executor = secure(mock_agent, config)
    
    with pytest.raises(CapiscioValidationError):
        executor.execute(invalid_message)


def test_secure_agent_decorator(valid_message):
    """Test the @secure_agent decorator."""
    @secure_agent()
    class TestAgent:
        def execute(self, message):
            return {"status": "success"}
    
    agent = TestAgent()
    result = agent.execute(valid_message)
    
    assert result == {"status": "success"}
    assert isinstance(agent, CapiscioSecurityExecutor)


def test_secure_agent_decorator_with_config(invalid_message):
    """Test @secure_agent decorator with config."""
    @secure_agent(config=SecurityConfig(fail_mode="block"))
    class TestAgent:
        def execute(self, message):
            return {"status": "success"}
    
    agent = TestAgent()
    
    with pytest.raises(CapiscioValidationError):
        agent.execute(invalid_message)


def test_executor_delegates_attributes(mock_agent):
    """Test that executor delegates attribute access."""
    mock_agent.custom_method = Mock(return_value="custom_result")
    
    executor = CapiscioSecurityExecutor(mock_agent)
    result = executor.custom_method()
    
    assert result == "custom_result"
