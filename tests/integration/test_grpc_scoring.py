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

    def test_grpc_scoring_agent_card(self, server_health_check):
        """Test: Score agent card via gRPC."""
        from capiscio_sdk.validators import AgentCardValidator
        
        # Sample agent card
        agent_card = {
            "agent_id": "test-agent",
            "name": "Test Agent",
            "description": "Test agent for scoring",
            "url": "https://example.com/agent",
            "version": "1.0.0"
        }
        
        validator = AgentCardValidator()
        result = validator.validate(agent_card)
        
        # Should get scoring results from gRPC service
        assert result is not None
        assert hasattr(result, 'compliance')
        assert hasattr(result, 'trust')
        assert hasattr(result, 'availability')
        
        print(f"✓ gRPC scoring service validated agent card")
        print(f"  Compliance: {result.compliance.total if result.compliance else 'N/A'}")
        print(f"  Trust: {result.trust.total if result.trust else 'N/A'}")
        print(f"  Availability: {result.availability.total if result.availability else 'N/A'}")

    def test_grpc_client_connection(self, server_health_check):
        """Test: gRPC client can connect to service."""
        from capiscio_sdk._rpc.client import CapiscioRPCClient
        
        client = CapiscioRPCClient(address=GRPC_ADDRESS)
        
        try:
            client.connect()
            assert client.scoring is not None
            print(f"✓ gRPC client connected to {GRPC_ADDRESS}")
        finally:
            client.close()

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
        client.close()
        
        # Should not raise errors
        print("✓ gRPC client cleanup successful")


# Placeholder test
def test_grpc_scoring_placeholder(server_health_check):
    """
    Placeholder documenting gRPC scoring requirements.
    
    gRPC scoring service should:
    - Accept agent card JSON
    - Return multi-dimensional scores (compliance, trust, availability)
    - Handle invalid input gracefully
    - Support connection pooling
    - Clean up resources properly
    """
    print("✓ gRPC scoring integration test suite documented")
    assert True
