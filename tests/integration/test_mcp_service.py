"""
Integration tests for MCP (Model Context Protocol) service against live server.

Tests RFC-006 Tool Authority and RFC-007 Server Identity verification
via the Python SDK MCPClient against the capiscio-core gRPC server.

These tests validate the full flow:
  Python SDK MCPClient → gRPC → capiscio-core MCPService
"""

import os
import pytest
import grpc
from capiscio_sdk._rpc.client import CapiscioRPCClient, MCPClient
from capiscio_sdk._rpc.gen.capiscio.v1 import mcp_pb2

# gRPC server address (capiscio-core)
GRPC_ADDRESS = os.getenv("GRPC_ADDRESS", "localhost:50051")


@pytest.fixture(scope="module")
def grpc_client() -> CapiscioRPCClient:
    """Create and connect gRPC client to server."""
    client = CapiscioRPCClient(address=GRPC_ADDRESS, auto_start=False)
    try:
        client.connect()
        yield client
    except grpc.RpcError as e:
        pytest.skip(f"gRPC server not available at {GRPC_ADDRESS}: {e}")
    finally:
        client.close()


@pytest.fixture(scope="module")
def mcp_client(grpc_client: CapiscioRPCClient) -> MCPClient:
    """Get the MCP client from the gRPC client."""
    return grpc_client.mcp


class TestMCPHealth:
    """Test MCPService health endpoint."""

    def test_health_check_basic(self, mcp_client: MCPClient):
        """Test: Health check returns service status."""
        result = mcp_client.health()
        
        assert "healthy" in result
        assert result["healthy"] is True
        assert "core_version" in result
        assert result["core_version"] != ""
        print(f"✓ MCP service healthy, version: {result['core_version']}")

    def test_health_check_with_client_version(self, mcp_client: MCPClient):
        """Test: Health check accepts client version."""
        result = mcp_client.health(client_version="capiscio-sdk-python/1.0.0")
        
        assert result["healthy"] is True
        print("✓ Health check with client version succeeded")


class TestMCPToolAccessEvaluation:
    """Test RFC-006 Tool Authority evaluation (§6.2-6.4)."""

    def test_evaluate_tool_access_with_badge(self, mcp_client: MCPClient):
        """Test: Tool access evaluation with a badge."""
        # Mock badge JWS for testing
        mock_badge = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkaWQ6a2V5Ono2TWtoYVhnQlpEdm90RGtMNTI1N2ZhaXp0aUdpQzJRdEtMR3Bibm5FR3RhMmRvSyIsImlzcyI6ImRpZDp3ZWI6Y2FwaXNjaW8uaW8iLCJpYXQiOjE3MTcxNjMwMDAsImV4cCI6MTcxNzI0OTQwMH0.sig"
        
        result = mcp_client.evaluate_tool_access(
            tool_name="read_file",
            params_hash="abc123",
            server_origin="https://example.com",
            badge_jws=mock_badge,
        )
        
        assert "decision" in result
        assert result["decision"] in ["allow", "deny"]
        assert "timestamp" in result
        print(f"✓ Tool access decision: {result['decision']}")

    def test_evaluate_tool_access_with_minimal_params(self, mcp_client: MCPClient):
        """Test: Tool access with minimal required parameters."""
        result = mcp_client.evaluate_tool_access(
            tool_name="test_tool",
        )
        
        assert "decision" in result
        assert "auth_level" in result
        print(f"✓ Minimal tool access result: decision={result['decision']}, auth_level={result['auth_level']}")

    def test_evaluate_tool_access_with_api_key(self, mcp_client: MCPClient):
        """Test: Tool access with API key authentication."""
        result = mcp_client.evaluate_tool_access(
            tool_name="write_file",
            api_key="test-api-key-12345",
            server_origin="https://files.example.com",
        )
        
        # Should deny (invalid API key) or allow (in dev mode)
        assert result["decision"] in ["allow", "deny"]
        print(f"✓ API key tool access: {result['decision']}")

    def test_evaluate_tool_access_with_trust_requirements(self, mcp_client: MCPClient):
        """Test: Tool access with minimum trust level requirement."""
        result = mcp_client.evaluate_tool_access(
            tool_name="dangerous_tool",
            min_trust_level=2,  # Require OV or higher
            accept_level_zero=False,
        )
        
        # Should deny without proper authentication
        assert result["decision"] == "deny"
        assert "deny_reason" in result
        print(f"✓ Trust-required tool access denied: {result.get('deny_reason', 'N/A')}")

    def test_evaluate_tool_access_with_allowed_tools(self, mcp_client: MCPClient):
        """Test: Tool access with explicit allowed tools list."""
        result = mcp_client.evaluate_tool_access(
            tool_name="read_file",
            allowed_tools=["read_file", "list_dir"],
            accept_level_zero=True,
        )
        
        assert "decision" in result
        print(f"✓ Allowed tools check: {result['decision']}")

    def test_evaluate_tool_access_not_in_allowed_list(self, mcp_client: MCPClient):
        """Test: Tool access denied when not in allowed list."""
        result = mcp_client.evaluate_tool_access(
            tool_name="delete_file",
            allowed_tools=["read_file", "list_dir"],  # delete not allowed
        )
        
        assert result["decision"] == "deny"
        print("✓ Tool correctly denied (not in allowed list)")


class TestMCPServerIdentityVerification:
    """Test RFC-007 Server Identity verification (§7.2)."""

    def test_verify_server_identity_valid_did(self, mcp_client: MCPClient):
        """Test: Verify server identity with valid DID."""
        result = mcp_client.verify_server_identity(
            server_did="did:web:example.com:servers:main",
        )
        
        assert "state" in result
        assert result["state"] in [
            "verified_principal", "declared_principal", "unverified_origin"
        ]
        assert "trust_level" in result
        print(f"✓ Server identity state: {result['state']}, trust: {result['trust_level']}")

    def test_verify_server_identity_with_badge(self, mcp_client: MCPClient):
        """Test: Verify server with badge."""
        mock_badge = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJkaWQ6d2ViOmV4YW1wbGUuY29tOnNlcnZlcnM6bWFpbiJ9.sig"
        
        result = mcp_client.verify_server_identity(
            server_did="did:web:example.com:servers:main",
            server_badge=mock_badge,
            transport_origin="https://example.com",
        )
        
        assert "state" in result
        print(f"✓ Server with badge: state={result['state']}")

    def test_verify_server_identity_with_trust_requirements(self, mcp_client: MCPClient):
        """Test: Server verification with trust requirements."""
        result = mcp_client.verify_server_identity(
            server_did="did:web:untrusted.example.com",
            min_trust_level=2,  # Require OV
            accept_level_zero=False,
        )
        
        # Should fail to verify at level 2 without proper badge
        assert result["state"] in ["declared_principal", "unverified_origin"]
        print(f"✓ Trust requirements enforced: {result['state']}")

    def test_verify_server_identity_did_key(self, mcp_client: MCPClient):
        """Test: Verify did:key server (self-signed)."""
        result = mcp_client.verify_server_identity(
            server_did="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            accept_level_zero=True,
        )
        
        assert "state" in result
        assert result["trust_level"] == 0  # did:key is always level 0
        print(f"✓ did:key server verified at level 0")

    def test_verify_server_identity_offline_mode(self, mcp_client: MCPClient):
        """Test: Server verification in offline mode."""
        result = mcp_client.verify_server_identity(
            server_did="did:web:example.com:server",
            offline_mode=True,
        )
        
        assert "state" in result
        print(f"✓ Offline verification: {result['state']}")


class TestMCPServerIdentityParsing:
    """Test RFC-007 Server Identity parsing from protocol messages."""

    def test_parse_server_identity_http_headers(self, mcp_client: MCPClient):
        """Test: Parse server identity from HTTP headers."""
        result = mcp_client.parse_server_identity_http(
            capiscio_server_did="did:web:example.com:servers:main",
            capiscio_server_badge="eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.sig",
        )
        
        assert "server_did" in result
        assert result["server_did"] == "did:web:example.com:servers:main"
        assert "identity_present" in result
        assert result["identity_present"] is True
        print(f"✓ Parsed HTTP headers: {result['server_did']}")

    def test_parse_server_identity_http_minimal(self, mcp_client: MCPClient):
        """Test: Parse with only DID header."""
        result = mcp_client.parse_server_identity_http(
            capiscio_server_did="did:web:minimal.example.com",
        )
        
        assert "server_did" in result
        assert result["server_did"] == "did:web:minimal.example.com"
        print("✓ Parsed minimal HTTP headers")

    def test_parse_server_identity_http_empty(self, mcp_client: MCPClient):
        """Test: Parse with no headers."""
        result = mcp_client.parse_server_identity_http()
        
        assert "identity_present" in result
        assert result["identity_present"] is False
        print("✓ Empty headers correctly detected")

    def test_parse_server_identity_jsonrpc_meta(self, mcp_client: MCPClient):
        """Test: Parse server identity from JSON-RPC meta."""
        import json
        meta = json.dumps({
            "_meta": {
                "serverDid": "did:web:jsonrpc.example.com",
                "serverBadge": "eyJhbGciOiJFZERTQSJ9.sig"
            }
        })
        
        result = mcp_client.parse_server_identity_jsonrpc(meta_json=meta)
        
        assert "server_did" in result
        print(f"✓ Parsed JSON-RPC meta: {result.get('server_did', 'N/A')}")

    def test_parse_server_identity_jsonrpc_initialize_response(self, mcp_client: MCPClient):
        """Test: Parse from MCP initialize response format."""
        import json
        meta = json.dumps({
            "serverInfo": {
                "name": "Official MCP Server",
                "version": "0.1.0"
            },
            "protocolVersion": "0.1",
            "_meta": {
                "serverDid": "did:web:mcp.example.com:server",
            }
        })
        
        result = mcp_client.parse_server_identity_jsonrpc(meta_json=meta)
        
        assert "identity_present" in result
        print(f"✓ Parsed MCP initialize response")


class TestMCPDecisionEnums:
    """Test MCP decision and state enums are properly returned."""

    def test_decision_values(self, mcp_client: MCPClient):
        """Test: Decision values are returned correctly."""
        result = mcp_client.evaluate_tool_access(
            tool_name="test_tool",
        )
        
        assert result["decision"] in ["allow", "deny"]
        print(f"✓ Decision value: {result['decision']}")

    def test_auth_level_values(self, mcp_client: MCPClient):
        """Test: Auth level is returned correctly."""
        result = mcp_client.evaluate_tool_access(
            tool_name="test_tool",
        )
        
        assert "auth_level" in result
        assert result["auth_level"] in ["anonymous", "api_key", "badge"]
        print(f"✓ Auth level: {result['auth_level']}")

    def test_server_state_values(self, mcp_client: MCPClient):
        """Test: Server state is returned correctly."""
        result = mcp_client.verify_server_identity(
            server_did="did:web:example.com:test"
        )
        
        assert result["state"] in [
            "verified_principal", "declared_principal", "unverified_origin"
        ]
        print(f"✓ Server state: {result['state']}")


class TestMCPErrorHandling:
    """Test MCP service error handling."""

    def test_empty_tool_name_handled(self, mcp_client: MCPClient):
        """Test: Empty tool name is handled gracefully."""
        try:
            result = mcp_client.evaluate_tool_access(
                tool_name="",
            )
            # Empty tool name may allow or deny depending on policy
            assert result["decision"] in ["allow", "deny"]
            print(f"✓ Empty tool name handled: {result['decision']}")
        except grpc.RpcError as e:
            # RPC error is acceptable for invalid input
            assert e.code() in [grpc.StatusCode.INVALID_ARGUMENT, grpc.StatusCode.INTERNAL]
            print(f"✓ Empty tool name raised gRPC error: {e.code()}")

    def test_invalid_did_handled(self, mcp_client: MCPClient):
        """Test: Invalid DID format is handled."""
        result = mcp_client.verify_server_identity(
            server_did="not-a-valid-did"
        )
        
        # Should return an error state, not crash
        assert "state" in result or "error_code" in result
        print(f"✓ Invalid DID handled gracefully")


class TestMCPIntegrationScenarios:
    """End-to-end integration scenarios."""

    def test_full_mcp_flow_http_headers(self, mcp_client: MCPClient):
        """Test: Full MCP flow - parse HTTP headers, verify, then evaluate."""
        # 1. Parse server identity from HTTP headers
        parsed = mcp_client.parse_server_identity_http(
            capiscio_server_did="did:web:production.example.com:mcp",
            capiscio_server_badge="",
        )
        
        server_did = parsed["server_did"]
        
        # 2. Verify server identity
        verification = mcp_client.verify_server_identity(
            server_did=server_did,
            accept_level_zero=True,
        )
        
        # 3. Evaluate tool access
        access = mcp_client.evaluate_tool_access(
            tool_name="read_file",
            server_origin="https://production.example.com",
        )
        
        print(f"✓ Full MCP flow completed:")
        print(f"  Server DID: {server_did}")
        print(f"  Server state: {verification['state']}")
        print(f"  Tool access: {access['decision']}")

    def test_mcp_flow_with_badge(self, mcp_client: MCPClient):
        """Test: MCP flow including badge verification."""
        mock_badge = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkaWQ6a2V5Ono2TWtoYVhnQlpEdm90RGtMNTI1N2ZhaXp0aUdpQzJRdEtMR3Bibm5FR3RhMmRvSyJ9.sig"
        
        result = mcp_client.evaluate_tool_access(
            tool_name="read_file",
            badge_jws=mock_badge,
            server_origin="https://example.com",
        )
        
        assert "decision" in result
        print(f"✓ MCP flow with badge: {result['decision']}")


# Skip markers for when server is not available
pytestmark = pytest.mark.integration
