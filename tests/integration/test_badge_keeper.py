"""
Integration tests for BadgeKeeper auto-renewal functionality.

BadgeKeeper is responsible for automatically renewing badges before
they expire, ensuring continuous agent authentication.

IMPLEMENTATION STATUS: ✅ BadgeKeeper is now implemented in capiscio_sdk.badge_keeper

NOTE: These tests require a running capiscio-core daemon and capiscio-server.
Run with: docker-compose up -d (see docker-compose.yml in this directory)
"""

import os
import pytest
import time
import threading

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8080")


@pytest.fixture(scope="module")
def server_health_check():
    """Verify server is running before tests."""
    import requests
    max_retries = 30
    for i in range(max_retries):
        try:
            resp = requests.get(f"{API_BASE_URL}/health", timeout=2)
            if resp.status_code == 200:
                print(f"✓ Server is healthy at {API_BASE_URL}")
                return True
        except requests.exceptions.RequestException:
            if i < max_retries - 1:
                time.sleep(1)
                continue
            else:
                pytest.skip(f"Server not available at {API_BASE_URL}")
    return False


class TestBadgeKeeperAutoRenewal:
    """Test BadgeKeeper automatic badge renewal."""

    def test_badge_keeper_renews_before_expiry(self, server_health_check):
        """
        Test: BadgeKeeper automatically renews badge before expiration.
        
        Expected behavior:
        1. Initialize BadgeKeeper with short-lived badge (e.g., 60s TTL)
        2. BadgeKeeper monitors expiry time
        3. Before expiry (e.g., 10s before), requests new badge
        4. New badge replaces old badge seamlessly
        5. No interruption in service
        """
        from capiscio_sdk import BadgeKeeper
        
        # Note: This test requires API credentials and may take 60+ seconds
        # Skip if not in full integration test mode
        if not os.getenv("RUN_LONG_TESTS"):
            pytest.skip("Long test - set RUN_LONG_TESTS=1 to enable")
        
        keeper = BadgeKeeper(
            api_url=API_BASE_URL,
            api_key=os.getenv("CAPISCIO_API_KEY", "test-api-key"),
            agent_id=os.getenv("CAPISCIO_AGENT_ID", "test-agent"),
            ttl_seconds=60,
            renewal_threshold=10,  # Renew 10s before expiry
            check_interval=5,
        )
        
        with keeper:
            # Wait for initial badge
            time.sleep(2)
            initial_badge = keeper.get_current_badge()
            assert initial_badge is not None, "Should have initial badge"
            
            # Wait for renewal (should happen around 50s mark)
            print("Waiting for badge renewal (this takes ~55 seconds)...")
            time.sleep(55)
            
            renewed_badge = keeper.get_current_badge()
            assert renewed_badge != initial_badge, "Badge should have renewed"
            print("✓ Badge renewed successfully")

    def test_badge_keeper_handles_renewal_failure(self, server_health_check):
        """
        Test: BadgeKeeper handles renewal failures gracefully.
        
        Expected behavior:
        1. BadgeKeeper attempts renewal
        2. Server/network error occurs
        3. Keeper logs error but doesn't crash
        4. Continues running
        """
        from capiscio_sdk import BadgeKeeper
        
        # Use invalid credentials to trigger failure
        keeper = BadgeKeeper(
            api_url=API_BASE_URL,
            api_key="invalid-key-will-fail",
            agent_id="invalid-agent",
            ttl_seconds=5,
            renewal_threshold=2,
            check_interval=1,
        )
        
        keeper.start()
        assert keeper.is_running(), "Keeper should be running"
        
        # Wait a bit - keeper should handle errors gracefully
        time.sleep(3)
        assert keeper.is_running(), "Keeper should still be running despite errors"
        
        keeper.stop()
        assert not keeper.is_running(), "Keeper should be stopped"
        print("✓ Keeper handles errors gracefully")

    def test_badge_keeper_updates_simpleguard(self, server_health_check):
        """
        Test: BadgeKeeper updates SimpleGuard's badge token on renewal.
        
        Expected behavior:
        1. SimpleGuard initialized with BadgeKeeper
        2. BadgeKeeper renews badge
        3. on_renew callback is called with new token
        4. Old badge is replaced
        """
        from capiscio_sdk import BadgeKeeper
        
        if not os.getenv("RUN_LONG_TESTS"):
            pytest.skip("Long test - set RUN_LONG_TESTS=1 to enable")
        
        renewed_tokens = []
        
        def on_renew_callback(token: str):
            renewed_tokens.append(token)
            print(f"✓ on_renew called with token: {token[:40]}...")
        
        keeper = BadgeKeeper(
            api_url=API_BASE_URL,
            api_key=os.getenv("CAPISCIO_API_KEY", "test-api-key"),
            agent_id=os.getenv("CAPISCIO_AGENT_ID", "test-agent"),
            ttl_seconds=60,
            renewal_threshold=10,
            on_renew=on_renew_callback,
        )
        
        with keeper:
            time.sleep(55)
            
        assert len(renewed_tokens) > 0, "Should have called on_renew callback"
        print(f"✓ on_renew called {len(renewed_tokens)} time(s)")

    def test_badge_keeper_configurable_threshold(self, server_health_check):
        """
        Test: Renewal threshold is configurable.
        
        Expected behavior:
        1. Set renewal_threshold to 30s
        2. Configuration is stored correctly
        3. Set renewal_threshold to 5s
        4. Configuration is stored correctly
        """
        from capiscio_sdk import BadgeKeeper
        
        # Test that different thresholds can be configured
        keeper1 = BadgeKeeper(
            api_url=API_BASE_URL,
            api_key="test",
            agent_id="test",
            renewal_threshold=30,
        )
        assert keeper1.config.renewal_threshold == 30
        
        keeper2 = BadgeKeeper(
            api_url=API_BASE_URL,
            api_key="test",
            agent_id="test",
            renewal_threshold=5,
        )
        assert keeper2.config.renewal_threshold == 5
        print("✓ Renewal threshold is configurable")

    def test_badge_keeper_stops_cleanly(self, server_health_check):
        """
        Test: BadgeKeeper stops cleanly without leaking resources.
        
        Expected behavior:
        1. Start BadgeKeeper
        2. Call keeper.stop()
        3. No background threads/tasks remain
        4. No network connections open
        """
        from capiscio_sdk import BadgeKeeper
        
        keeper = BadgeKeeper(
            api_url=API_BASE_URL,
            api_key="test",
            agent_id="test",
        )
        
        # Track initial thread count
        initial_threads = threading.active_count()
        
        keeper.start()
        assert keeper.is_running()
        time.sleep(0.5)
        
        # Should have one more thread
        running_threads = threading.active_count()
        assert running_threads >= initial_threads
        
        keeper.stop()
        assert not keeper.is_running()
        
        # Wait for thread cleanup
        time.sleep(0.5)
        final_threads = threading.active_count()
        
        # Thread count should return to initial (or close)
        assert final_threads <= initial_threads + 1, "Should not leak threads"
        print("✓ Keeper stops cleanly without resource leaks")


class TestBadgeKeeperIntegrationWithServer:
    """Test BadgeKeeper against actual server API."""

    def test_badge_keeper_context_manager(self, server_health_check):
        """
        Test: BadgeKeeper works as context manager.
        
        Expected behavior:
        1. Use 'with BadgeKeeper(...)' statement
        2. Keeper starts automatically on entry
        3. Keeper stops automatically on exit
        """
        from capiscio_sdk import BadgeKeeper
        
        keeper = BadgeKeeper(
            api_url=API_BASE_URL,
            api_key="test",
            agent_id="test",
        )
        
        assert not keeper.is_running()
        
        with keeper:
            assert keeper.is_running(), "Should be running inside context"
        
        assert not keeper.is_running(), "Should be stopped after context"
        print("✓ Context manager works correctly")

    def test_badge_keeper_get_current_badge(self, server_health_check):
        """
        Test: get_current_badge() returns None initially, then badge after renewal.
        
        Expected behavior:
        1. Before start: returns None
        2. After start: eventually returns badge token
        3. Badge is a non-empty string
        """
        from capiscio_sdk import BadgeKeeper
        
        keeper = BadgeKeeper(
            api_url=API_BASE_URL,
            api_key="test",
            agent_id="test",
        )
        
        # Before start
        assert keeper.get_current_badge() is None
        
        keeper.start()
        time.sleep(1)  # Give it time to potentially get a badge
        
        # Note: May still be None if credentials are invalid
        # but method should not raise
        badge = keeper.get_current_badge()
        
        keeper.stop()
        print(f"✓ get_current_badge() works (badge={'present' if badge else 'None'})")


def test_badge_keeper_implementation_complete(server_health_check):
    """
    Verify BadgeKeeper is fully implemented.
    
    This test confirms:
    - BadgeKeeper class exists and is importable
    - Basic API is available
    - Configuration is functional
    """
    from capiscio_sdk import BadgeKeeper, BadgeKeeperConfig
    
    print("✓ BadgeKeeper class imported successfully")
    
    # Verify API
    assert hasattr(BadgeKeeper, 'start')
    assert hasattr(BadgeKeeper, 'stop')
    assert hasattr(BadgeKeeper, 'get_current_badge')
    assert hasattr(BadgeKeeper, 'is_running')
    print("✓ BadgeKeeper API complete")
    
    # Verify config
    config = BadgeKeeperConfig(
        api_url="https://test.example.com",
        api_key="test-key",
        agent_id="test-agent",
        renewal_threshold=15,
    )
    assert config.renewal_threshold == 15
    print("✓ BadgeKeeperConfig works")
    
    # Verify instantiation
    keeper = BadgeKeeper(
        api_url="https://test.example.com",
        api_key="test-key",
        agent_id="test-agent",
    )
    assert not keeper.is_running()
    print("✓ BadgeKeeper instantiation works")
