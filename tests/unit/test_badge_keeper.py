"""
Unit tests for BadgeKeeper class.

These tests verify BadgeKeeper behavior without requiring external services.
They test configuration, API contracts, and basic lifecycle management.
"""

import pytest
import threading
import time
from unittest.mock import Mock, patch, MagicMock
from capiscio_sdk.badge_keeper import BadgeKeeper, BadgeKeeperConfig


class TestBadgeKeeperConfig:
    """Test BadgeKeeperConfig dataclass."""

    def test_config_defaults(self):
        """Test default configuration values."""
        config = BadgeKeeperConfig(
            api_url="https://registry.capisc.io",
            api_key="test-key",
            agent_id="test-agent",
        )
        
        assert config.mode == "ca"
        assert config.output_file == "badge.jwt"
        assert config.ttl_seconds == 300
        assert config.renewal_threshold == 10
        assert config.check_interval == 5
        assert config.trust_level == 1
        assert config.rpc_address is None
        assert config.on_renew is None
        assert config.max_retries == 3
        assert config.retry_backoff == 2

    def test_config_custom_values(self):
        """Test configuration with custom values."""
        def callback(token):
            pass
        
        config = BadgeKeeperConfig(
            api_url="https://custom.example.com",
            api_key="custom-key",
            agent_id="custom-agent",
            mode="pop",
            output_file="custom.jwt",
            ttl_seconds=600,
            renewal_threshold=30,
            check_interval=10,
            trust_level=2,
            rpc_address="unix:///custom.sock",
            on_renew=callback,
            max_retries=5,
            retry_backoff=4,
        )
        
        assert config.api_url == "https://custom.example.com"
        assert config.mode == "pop"
        assert config.renewal_threshold == 30
        assert config.on_renew == callback


class TestBadgeKeeperLifecycle:
    """Test BadgeKeeper lifecycle management."""

    def test_initial_state(self):
        """Test BadgeKeeper initial state."""
        keeper = BadgeKeeper(
            api_url="https://test.example.com",
            api_key="test",
            agent_id="test",
        )
        
        assert not keeper.is_running()
        assert keeper.get_current_badge() is None

    def test_cannot_start_twice(self):
        """Test that starting an already running keeper raises error."""
        from capiscio_sdk.errors import CapiscioSecurityError
        
        keeper = BadgeKeeper(
            api_url="https://test.example.com",
            api_key="test",
            agent_id="test",
        )
        
        with patch.object(keeper, '_run_keeper'):
            keeper.start()
            
            with pytest.raises(CapiscioSecurityError, match="already running"):
                keeper.start()
            
            keeper.stop()

    def test_stop_when_not_running(self):
        """Test that stopping a non-running keeper is safe."""
        keeper = BadgeKeeper(
            api_url="https://test.example.com",
            api_key="test",
            agent_id="test",
        )
        
        # Should not raise
        keeper.stop()
        assert not keeper.is_running()

    def test_context_manager_lifecycle(self):
        """Test context manager starts and stops keeper."""
        keeper = BadgeKeeper(
            api_url="https://test.example.com",
            api_key="test",
            agent_id="test",
        )
        
        with patch.object(keeper, '_run_keeper'):
            assert not keeper.is_running()
            
            with keeper:
                assert keeper.is_running()
            
            assert not keeper.is_running()


class TestBadgeKeeperConfiguration:
    """Test BadgeKeeper configuration handling."""

    def test_configuration_stored(self):
        """Test that configuration is stored correctly."""
        keeper = BadgeKeeper(
            api_url="https://test.example.com",
            api_key="test-key",
            agent_id="test-agent",
            mode="pop",
            renewal_threshold=20,
        )
        
        assert keeper.config.api_url == "https://test.example.com"
        assert keeper.config.api_key == "test-key"
        assert keeper.config.agent_id == "test-agent"
        assert keeper.config.mode == "pop"
        assert keeper.config.renewal_threshold == 20

    def test_callback_configuration(self):
        """Test on_renew callback is stored."""
        callback = Mock()
        
        keeper = BadgeKeeper(
            api_url="https://test.example.com",
            api_key="test",
            agent_id="test",
            on_renew=callback,
        )
        
        assert keeper.config.on_renew == callback


class TestBadgeKeeperAPI:
    """Test BadgeKeeper public API."""

    def test_has_required_methods(self):
        """Test that BadgeKeeper has required public methods."""
        keeper = BadgeKeeper(
            api_url="https://test.example.com",
            api_key="test",
            agent_id="test",
        )
        
        assert hasattr(keeper, 'start')
        assert hasattr(keeper, 'stop')
        assert hasattr(keeper, 'get_current_badge')
        assert hasattr(keeper, 'is_running')
        assert callable(keeper.start)
        assert callable(keeper.stop)
        assert callable(keeper.get_current_badge)
        assert callable(keeper.is_running)

    def test_get_current_badge_returns_none_initially(self):
        """Test get_current_badge returns None before any badge."""
        keeper = BadgeKeeper(
            api_url="https://test.example.com",
            api_key="test",
            agent_id="test",
        )
        
        assert keeper.get_current_badge() is None

    def test_get_current_badge_thread_safe(self):
        """Test get_current_badge is thread-safe."""
        keeper = BadgeKeeper(
            api_url="https://test.example.com",
            api_key="test",
            agent_id="test",
        )
        
        # Access from multiple threads
        results = []
        
        def access_badge():
            results.append(keeper.get_current_badge())
        
        threads = [threading.Thread(target=access_badge) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # All should return None without error
        assert all(r is None for r in results)


class TestBadgeKeeperEventHandling:
    """Test BadgeKeeper event handling."""

    def test_on_renew_callback_called(self):
        """Test that on_renew callback is called when badge renews."""
        callback = Mock()
        keeper = BadgeKeeper(
            api_url="https://test.example.com",
            api_key="test",
            agent_id="test",
            on_renew=callback,
        )
        
        # Simulate renewal event
        event = {
            "type": "renewed",
            "token": "new-badge-token",
            "badge_jti": "test-jti",
            "expires_at": 1234567890,
        }
        
        keeper._handle_keeper_event(event)
        
        callback.assert_called_once_with("new-badge-token")
        assert keeper.get_current_badge() == "new-badge-token"

    def test_on_renew_callback_error_handled(self):
        """Test that errors in on_renew callback don't crash keeper."""
        def bad_callback(token):
            raise Exception("Callback error")
        
        keeper = BadgeKeeper(
            api_url="https://test.example.com",
            api_key="test",
            agent_id="test",
            on_renew=bad_callback,
        )
        
        event = {
            "type": "renewed",
            "token": "new-badge-token",
            "badge_jti": "test-jti",
            "expires_at": 1234567890,
        }
        
        # Should not raise
        keeper._handle_keeper_event(event)
        
        # Badge should still be updated
        assert keeper.get_current_badge() == "new-badge-token"

    def test_started_event_handled(self):
        """Test started event is logged."""
        keeper = BadgeKeeper(
            api_url="https://test.example.com",
            api_key="test",
            agent_id="test",
        )
        
        event = {"type": "started"}
        
        # Should not raise
        keeper._handle_keeper_event(event)

    def test_error_event_handled(self):
        """Test error event is logged."""
        keeper = BadgeKeeper(
            api_url="https://test.example.com",
            api_key="test",
            agent_id="test",
        )
        
        event = {
            "type": "error",
            "error": "Test error",
            "error_code": "test_error",
        }
        
        # Should not raise
        keeper._handle_keeper_event(event)

    def test_stopped_event_sets_stop_flag(self):
        """Test stopped event sets the stop event."""
        keeper = BadgeKeeper(
            api_url="https://test.example.com",
            api_key="test",
            agent_id="test",
        )
        
        event = {"type": "stopped"}
        
        keeper._handle_keeper_event(event)
        
        assert keeper._stop_event.is_set()


class TestBadgeKeeperModes:
    """Test BadgeKeeper mode configurations."""

    def test_ca_mode(self):
        """Test CA mode configuration."""
        keeper = BadgeKeeper(
            api_url="https://test.example.com",
            api_key="test",
            agent_id="test",
            mode="ca",
        )
        
        assert keeper.config.mode == "ca"

    def test_pop_mode(self):
        """Test PoP mode configuration (RFC-003)."""
        keeper = BadgeKeeper(
            api_url="https://test.example.com",
            api_key="test",
            agent_id="test",
            mode="pop",
        )
        
        assert keeper.config.mode == "pop"

    def test_trust_levels(self):
        """Test different trust levels can be configured."""
        for level in [1, 2, 3, 4]:
            keeper = BadgeKeeper(
                api_url="https://test.example.com",
                api_key="test",
                agent_id="test",
                trust_level=level,
            )
            
            assert keeper.config.trust_level == level
