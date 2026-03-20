"""Tests for capiscio_sdk.pip — RFC-005 PIP request builder types."""

import json
import os
from unittest import mock

import pytest

from capiscio_sdk.pip import (
    DECISION_ALLOW,
    DECISION_DENY,
    DECISION_OBSERVE,
    PIP_VERSION,
    ActionAttributes,
    ContextAttributes,
    EnforcementMode,
    EnvironmentAttributes,
    Obligation,
    PIPRequest,
    PIPResponse,
    ResourceAttributes,
    SubjectAttributes,
)


# ---------------------------------------------------------------------------
# PIP_VERSION constant
# ---------------------------------------------------------------------------


class TestPIPVersion:
    def test_value(self) -> None:
        assert PIP_VERSION == "capiscio.pip.v1"


# ---------------------------------------------------------------------------
# Decision constants
# ---------------------------------------------------------------------------


class TestDecisionConstants:
    def test_allow(self) -> None:
        assert DECISION_ALLOW == "ALLOW"

    def test_deny(self) -> None:
        assert DECISION_DENY == "DENY"

    def test_observe(self) -> None:
        assert DECISION_OBSERVE == "ALLOW_OBSERVE"


# ---------------------------------------------------------------------------
# EnforcementMode
# ---------------------------------------------------------------------------


class TestEnforcementMode:
    def test_values_match_rfc(self) -> None:
        assert EnforcementMode.OBSERVE.value == "EM-OBSERVE"
        assert EnforcementMode.GUARD.value == "EM-GUARD"
        assert EnforcementMode.DELEGATE.value == "EM-DELEGATE"
        assert EnforcementMode.STRICT.value == "EM-STRICT"

    def test_from_string(self) -> None:
        assert EnforcementMode("EM-OBSERVE") == EnforcementMode.OBSERVE
        assert EnforcementMode("EM-STRICT") == EnforcementMode.STRICT

    def test_from_string_invalid(self) -> None:
        with pytest.raises(ValueError):
            EnforcementMode("INVALID")

    def test_stricter_than_ordering(self) -> None:
        assert EnforcementMode.STRICT.stricter_than(EnforcementMode.OBSERVE)
        assert EnforcementMode.DELEGATE.stricter_than(EnforcementMode.GUARD)
        assert EnforcementMode.GUARD.stricter_than(EnforcementMode.OBSERVE)
        assert not EnforcementMode.OBSERVE.stricter_than(EnforcementMode.STRICT)
        assert not EnforcementMode.OBSERVE.stricter_than(EnforcementMode.OBSERVE)

    def test_from_env_default(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            # Remove the key entirely if present
            os.environ.pop("CAPISCIO_ENFORCEMENT_MODE", None)
            assert EnforcementMode.from_env() == EnforcementMode.OBSERVE

    def test_from_env_empty_string(self) -> None:
        with mock.patch.dict(os.environ, {"CAPISCIO_ENFORCEMENT_MODE": ""}):
            assert EnforcementMode.from_env() == EnforcementMode.OBSERVE

    def test_from_env_valid(self) -> None:
        with mock.patch.dict(os.environ, {"CAPISCIO_ENFORCEMENT_MODE": "EM-STRICT"}):
            assert EnforcementMode.from_env() == EnforcementMode.STRICT

    def test_from_env_invalid(self) -> None:
        with mock.patch.dict(os.environ, {"CAPISCIO_ENFORCEMENT_MODE": "BOGUS"}):
            with pytest.raises(ValueError, match="Unknown enforcement mode"):
                EnforcementMode.from_env()

    def test_all_four_modes_exist(self) -> None:
        assert len(EnforcementMode) == 4


# ---------------------------------------------------------------------------
# SubjectAttributes
# ---------------------------------------------------------------------------


class TestSubjectAttributes:
    def test_to_dict(self) -> None:
        s = SubjectAttributes(
            did="did:web:example.com:agents:bot",
            badge_jti="badge-123",
            ial="IAL-1",
            trust_level="2",
        )
        d = s.to_dict()
        assert d == {
            "did": "did:web:example.com:agents:bot",
            "badge_jti": "badge-123",
            "ial": "IAL-1",
            "trust_level": "2",
        }

    def test_defaults_are_empty_strings(self) -> None:
        s = SubjectAttributes()
        assert s.did == ""
        assert s.badge_jti == ""
        assert s.ial == ""
        assert s.trust_level == ""


# ---------------------------------------------------------------------------
# ActionAttributes
# ---------------------------------------------------------------------------


class TestActionAttributes:
    def test_to_dict_badge_only(self) -> None:
        a = ActionAttributes(operation="tools/call")
        d = a.to_dict()
        assert d["operation"] == "tools/call"
        assert d["capability_class"] is None

    def test_to_dict_with_capability(self) -> None:
        a = ActionAttributes(operation="GET /v1/agents", capability_class="read")
        d = a.to_dict()
        assert d["capability_class"] == "read"


# ---------------------------------------------------------------------------
# ResourceAttributes
# ---------------------------------------------------------------------------


class TestResourceAttributes:
    def test_to_dict(self) -> None:
        r = ResourceAttributes(identifier="database://prod/users")
        assert r.to_dict() == {"identifier": "database://prod/users"}


# ---------------------------------------------------------------------------
# ContextAttributes
# ---------------------------------------------------------------------------


class TestContextAttributes:
    def test_to_dict_badge_only_nulls(self) -> None:
        """Envelope fields MUST serialize as null, not absent."""
        c = ContextAttributes(txn_id="txn-1", enforcement_mode="EM-OBSERVE")
        d = c.to_dict()
        assert d["txn_id"] == "txn-1"
        assert d["enforcement_mode"] == "EM-OBSERVE"
        # Envelope fields present as None (→ JSON null)
        assert "envelope_id" in d
        assert d["envelope_id"] is None
        assert "delegation_depth" in d
        assert d["delegation_depth"] is None
        assert "constraints" in d
        assert d["constraints"] is None
        assert "parent_constraints" in d
        assert d["parent_constraints"] is None

    def test_enforcement_mode_enum_normalised(self) -> None:
        """EnforcementMode enum should be normalised to its string value."""
        c = ContextAttributes(
            txn_id="txn-enum",
            enforcement_mode=EnforcementMode.STRICT,
        )
        assert c.enforcement_mode == "EM-STRICT"
        d = c.to_dict()
        assert d["enforcement_mode"] == "EM-STRICT"
        # Must be JSON-serialisable
        j = json.dumps(d)
        assert '"EM-STRICT"' in j

    def test_json_null_serialisation(self) -> None:
        """Verify JSON output has explicit null values for envelope fields."""
        c = ContextAttributes(txn_id="t")
        j = json.dumps(c.to_dict())
        parsed = json.loads(j)
        assert parsed["envelope_id"] is None
        assert parsed["constraints"] is None
        assert parsed["parent_constraints"] is None


# ---------------------------------------------------------------------------
# EnvironmentAttributes
# ---------------------------------------------------------------------------


class TestEnvironmentAttributes:
    def test_to_dict_all_set(self) -> None:
        e = EnvironmentAttributes(workspace="prod", pep_id="pep-1", time="2026-03-20T10:00:00Z")
        d = e.to_dict()
        assert d == {"workspace": "prod", "pep_id": "pep-1", "time": "2026-03-20T10:00:00Z"}

    def test_to_dict_omits_none(self) -> None:
        """Optional fields are omitted when None (not serialised as null)."""
        e = EnvironmentAttributes()
        d = e.to_dict()
        assert "workspace" not in d
        assert "pep_id" not in d
        assert "time" not in d

    def test_to_dict_partial(self) -> None:
        e = EnvironmentAttributes(workspace="staging")
        d = e.to_dict()
        assert d == {"workspace": "staging"}
        assert "pep_id" not in d


# ---------------------------------------------------------------------------
# PIPRequest
# ---------------------------------------------------------------------------


class TestPIPRequest:
    def test_default_pip_version(self) -> None:
        r = PIPRequest()
        assert r.pip_version == PIP_VERSION

    def test_to_dict_auto_populates_txn_id(self) -> None:
        r = PIPRequest(
            subject=SubjectAttributes(did="did:web:x"),
            action=ActionAttributes(operation="GET /"),
            resource=ResourceAttributes(identifier="/"),
            context=ContextAttributes(enforcement_mode="EM-GUARD"),
        )
        d = r.to_dict()
        assert d["context"]["txn_id"], "txn_id should be auto-populated"
        assert len(d["context"]["txn_id"]) == 36  # UUID format

    def test_to_dict_preserves_txn_id(self) -> None:
        """If txn_id is already set, do not overwrite it."""
        r = PIPRequest(
            context=ContextAttributes(txn_id="existing-txn-id"),
        )
        d = r.to_dict()
        assert d["context"]["txn_id"] == "existing-txn-id"

    def test_to_dict_auto_populates_time(self) -> None:
        r = PIPRequest()
        d = r.to_dict()
        assert d["environment"]["time"] is not None
        assert d["environment"]["time"].endswith("Z")

    def test_to_dict_preserves_time(self) -> None:
        r = PIPRequest(
            environment=EnvironmentAttributes(time="2026-01-01T00:00:00Z"),
        )
        d = r.to_dict()
        assert d["environment"]["time"] == "2026-01-01T00:00:00Z"

    def test_full_roundtrip(self) -> None:
        """Full request → dict → JSON → dict matches structure."""
        r = PIPRequest(
            subject=SubjectAttributes(
                did="did:web:example.com:agents:bot",
                badge_jti="badge-123",
                ial="IAL-1",
                trust_level="2",
            ),
            action=ActionAttributes(operation="tools/call"),
            resource=ResourceAttributes(identifier="db://users"),
            context=ContextAttributes(
                txn_id="fixed-txn",
                enforcement_mode="EM-DELEGATE",
            ),
            environment=EnvironmentAttributes(
                workspace="prod",
                pep_id="pep-1",
                time="2026-03-20T12:00:00Z",
            ),
        )
        d = r.to_dict()
        j = json.dumps(d)
        parsed = json.loads(j)

        assert parsed["pip_version"] == PIP_VERSION
        assert parsed["subject"]["did"] == "did:web:example.com:agents:bot"
        assert parsed["action"]["capability_class"] is None
        assert parsed["context"]["envelope_id"] is None
        assert parsed["environment"]["workspace"] == "prod"

    def test_to_dict_idempotent(self) -> None:
        """Calling to_dict() twice produces the same result."""
        r = PIPRequest(
            context=ContextAttributes(txn_id="txn-fixed"),
            environment=EnvironmentAttributes(time="2026-01-01T00:00:00Z"),
        )
        d1 = r.to_dict()
        d2 = r.to_dict()
        assert d1 == d2


# ---------------------------------------------------------------------------
# Obligation
# ---------------------------------------------------------------------------


class TestObligation:
    def test_to_dict(self) -> None:
        o = Obligation(type="rate_limit", params={"max_rps": 100})
        d = o.to_dict()
        assert d == {"type": "rate_limit", "params": {"max_rps": 100}}

    def test_to_dict_null_params(self) -> None:
        o = Obligation(type="audit_log")
        d = o.to_dict()
        assert d["params"] is None

    def test_from_dict(self) -> None:
        o = Obligation.from_dict({"type": "audit_log", "params": {"level": "full"}})
        assert o.type == "audit_log"
        assert o.params == {"level": "full"}

    def test_from_dict_no_params(self) -> None:
        o = Obligation.from_dict({"type": "log"})
        assert o.type == "log"
        assert o.params is None

    def test_from_dict_invalid_params_type(self) -> None:
        """params must be a dict; non-dict values are dropped to None."""
        o = Obligation.from_dict({"type": "x", "params": "not-a-dict"})
        assert o.params is None

    def test_from_dict_empty(self) -> None:
        o = Obligation.from_dict({})
        assert o.type == ""
        assert o.params is None


# ---------------------------------------------------------------------------
# PIPResponse
# ---------------------------------------------------------------------------


class TestPIPResponse:
    def test_is_allow(self) -> None:
        r = PIPResponse(decision="ALLOW", decision_id="d1")
        assert r.is_allow
        assert not r.is_deny

    def test_is_deny(self) -> None:
        r = PIPResponse(decision="DENY", decision_id="d2")
        assert r.is_deny
        assert not r.is_allow

    def test_to_dict(self) -> None:
        r = PIPResponse(
            decision="ALLOW",
            decision_id="d1",
            obligations=[Obligation(type="log")],
            reason="ok",
            ttl=60,
        )
        d = r.to_dict()
        assert d["decision"] == "ALLOW"
        assert d["decision_id"] == "d1"
        assert len(d["obligations"]) == 1
        assert d["reason"] == "ok"
        assert d["ttl"] == 60

    def test_to_dict_omits_empty_reason_and_ttl(self) -> None:
        r = PIPResponse(decision="DENY", decision_id="d2")
        d = r.to_dict()
        assert "reason" not in d
        assert "ttl" not in d

    def test_from_dict(self) -> None:
        raw = {
            "decision": "ALLOW",
            "decision_id": "pdp-1",
            "obligations": [
                {"type": "rate_limit", "params": {"max": 10}},
                {"type": "audit"},
            ],
            "reason": "approved",
            "ttl": 120,
        }
        r = PIPResponse.from_dict(raw)
        assert r.decision == "ALLOW"
        assert r.decision_id == "pdp-1"
        assert len(r.obligations) == 2
        assert r.obligations[0].type == "rate_limit"
        assert r.obligations[0].params == {"max": 10}
        assert r.obligations[1].type == "audit"
        assert r.reason == "approved"
        assert r.ttl == 120

    def test_from_dict_minimal(self) -> None:
        r = PIPResponse.from_dict({"decision": "DENY", "decision_id": "x"})
        assert r.is_deny
        assert r.obligations == []
        assert r.reason == ""
        assert r.ttl is None

    def test_from_dict_rejects_non_dict_obligations(self) -> None:
        """Non-dict entries in obligations list are skipped."""
        r = PIPResponse.from_dict({
            "decision": "ALLOW",
            "decision_id": "y",
            "obligations": [{"type": "ok"}, "bad", 42],
        })
        assert len(r.obligations) == 1
        assert r.obligations[0].type == "ok"

    def test_roundtrip(self) -> None:
        """PIPResponse → to_dict → JSON → from_dict roundtrip."""
        original = PIPResponse(
            decision="ALLOW",
            decision_id="d1",
            obligations=[Obligation(type="rl", params={"rps": 100})],
            reason="test",
            ttl=300,
        )
        j = json.dumps(original.to_dict())
        restored = PIPResponse.from_dict(json.loads(j))
        assert restored.decision == original.decision
        assert restored.decision_id == original.decision_id
        assert len(restored.obligations) == 1
        assert restored.obligations[0].type == "rl"
        assert restored.obligations[0].params == {"rps": 100}
        assert restored.reason == original.reason
        assert restored.ttl == original.ttl
