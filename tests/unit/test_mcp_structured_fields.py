"""Unit tests for structured rejection fields in MCPClient.evaluate_tool_access()."""

from unittest.mock import MagicMock

from google.protobuf.timestamp_pb2 import Timestamp

from capiscio_sdk._rpc.client import MCPClient, _ensure_mcp_protos
from capiscio_sdk._rpc.gen.capiscio.v1 import mcp_pb2


# Ensure the lazy-loaded module-level mcp_pb2 is populated before tests run
_ensure_mcp_protos()


class TestEvaluateToolAccessStructuredFields:
    """Verify RFC-008 structured rejection fields are surfaced in the return dict."""

    def _make_mock_response(self, **overrides):
        """Build a mock EvaluateToolAccessResponse."""
        defaults = {
            "decision": mcp_pb2.MCP_DECISION_DENY,
            "deny_reason": mcp_pb2.MCP_DENY_REASON_SCOPE_INSUFFICIENT,
            "deny_detail": "capability mismatch",
            "agent_did": "did:key:z6Mktest",
            "badge_jti": "jti-abc",
            "auth_level": mcp_pb2.MCP_AUTH_LEVEL_BADGE,
            "trust_level": 2,
            "evidence_json": "{}",
            "evidence_id": "ev-001",
            "timestamp": Timestamp(seconds=1700000000),
            "error_code": "SCOPE_MISMATCH",
            "rejection_detail": "requested read:sensitive but badge grants read:public",
            "requested_capability": "read:sensitive",
            "presented_capability": "read:public",
            "policy_decision_id": "",
            "policy_decision": "",
            "enforcement_mode": "",
            "obligations": [],
        }
        defaults.update(overrides)
        resp = MagicMock(**defaults)
        return resp

    def test_deny_response_includes_structured_fields(self):
        stub = MagicMock()
        stub.EvaluateToolAccess.return_value = self._make_mock_response()
        client = MCPClient(stub)

        result = client.evaluate_tool_access(
            tool_name="read_file",
            params_hash="h123",
        )

        assert result["decision"] == "deny"
        assert result["deny_reason"] == "scope_insufficient"
        assert result["error_code"] == "SCOPE_MISMATCH"
        assert result["rejection_detail"] == "requested read:sensitive but badge grants read:public"
        assert result["requested_capability"] == "read:sensitive"
        assert result["presented_capability"] == "read:public"

    def test_allow_response_has_empty_structured_fields(self):
        stub = MagicMock()
        stub.EvaluateToolAccess.return_value = self._make_mock_response(
            decision=mcp_pb2.MCP_DECISION_ALLOW,
            deny_reason=mcp_pb2.MCP_DENY_REASON_UNSPECIFIED,
            deny_detail="",
            error_code="",
            rejection_detail="",
            requested_capability="",
            presented_capability="",
        )
        client = MCPClient(stub)

        result = client.evaluate_tool_access(tool_name="list_files")

        assert result["decision"] == "allow"
        assert result["error_code"] == ""
        assert result["rejection_detail"] == ""
        assert result["requested_capability"] == ""
        assert result["presented_capability"] == ""

    def test_all_expected_keys_present(self):
        stub = MagicMock()
        stub.EvaluateToolAccess.return_value = self._make_mock_response()
        client = MCPClient(stub)

        result = client.evaluate_tool_access(tool_name="any_tool")

        expected_keys = {
            "decision", "deny_reason", "deny_detail",
            "agent_did", "badge_jti", "auth_level",
            "trust_level", "evidence_json", "evidence_id",
            "timestamp", "error_code", "rejection_detail",
            "requested_capability", "presented_capability",
        }
        assert expected_keys.issubset(result.keys()), (
            f"Missing keys: {expected_keys - result.keys()}"
        )
