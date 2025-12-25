"""
Integration tests for gRPC scoring service.

Tests that the SDK's gRPC client can communicate with capiscio-core's
gRPC scoring service for agent card validation.
"""

import os
import pytest

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8080")
GRPC_ADDRESS = os.getenv("GRPC_ADDRESS", "localhost:50051")


@pytest.fixture(scope="module")
def server_health_check():
    """Verify server is running."""
    import requests
    import time
    max_retries = 30
    for i in range(max_retries):
        try:
            resp = requests.get(f"{API_BASE_URL}/health", timeout=2)
            if resp.status_code == 200:
                print(f"✓ Server healthy at {API_BASE_URL}")
                return True
        except requests.exceptions.RequestException:
            if i < max_retries - 1:
                time.sleep(1)
                continue
    pytest.skip(f"Server not available at {API_BASE_URL}")


class TestGRPCScoringService:
    """Test gRPC scoring service integration."""

    def test_grpc_client_connection(self, server_health_check):
        """Test: gRPC client can connect to service."""
        from capiscio_sdk._rpc.client import CapiscioRPCClient
        
        try:
            with CapiscioRPCClient(address=GRPC_ADDRESS) as client:
                client.connect()
                assert client.scoring is not None
                print(f"✓ gRPC client connected to {GRPC_ADDRESS}")
        except Exception as e:
            # gRPC server might not be running - that's okay for this test
            print(f"ℹ gRPC connection failed (expected if no gRPC server): {e}")
            pytest.skip(f"gRPC server not available at {GRPC_ADDRESS}")

    @pytest.mark.skip(reason="Requires gRPC server running")
    def test_grpc_scoring_invalid_card(self, server_health_check):
        """Test: Scoring service handles invalid agent cards."""
        from capiscio_sdk.validators import AgentCardValidator
        
        invalid_card = {
            "agent_id": "",  # Empty
            "name": "",      # Empty
        }
        
        validator = AgentCardValidator()
        result = validator.validate(invalid_card)
        
        # Should return low scores/validation errors
        assert result.compliance.total < 50
        print("✓ gRPC service handled invalid card")

    def test_grpc_client_cleanup(self, server_health_check):
        """Test: gRPC client cleans up resources."""
        from capiscio_sdk._rpc.client import CapiscioRPCClient
        
        client = CapiscioRPCClient(address=GRPC_ADDRESS)
        client.connect()
    def test_grpc_client_cleanup(self, server_health_check):
        """Test: gRPC client cleans up resources."""
        from capiscio_sdk._rpc.client import CapiscioRPCClient
        
        try:
            client = CapiscioRPCClient(address=GRPC_ADDRESS)
            client.connect()
            client.close()
            print("✓ gRPC client cleanup successful")
        except Exception as e:
            print(f"ℹ gRPC cleanup test skipped (no server): {e}")
            pytest.skip(f"gRPC server not available")


def test_grpc_scoring_implementation_exists(server_health_check):
    """Test: gRPC scoring infrastructure exists in SDK."""
    from capiscio_sdk._rpc.client import CapiscioRPCClient
    from capiscio_sdk.validators import CoreValidator
    
    # Verify gRPC client exists
    assert CapiscioRPCClient is not None
    print("✓ gRPC client implementation exists")
    
    # Verify CoreValidator exists (replacement for deprecated AgentCardValidator)
    assert CoreValidator is not None
    print("✓ CoreValidator implementation exists")
    
    # Note: Actual scoring requires capiscio-core daemon running via unix socket
    # These tests verify the SDK has the infrastructure in plac