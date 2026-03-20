"""RFC-005: PIP Request Builder — SDK convenience types.

Provides dataclasses for constructing PDP Integration Profile (PIP) requests
and interpreting responses. These are thin data structures with serialization —
no business logic, no PDP client, no enforcement. Intended for SDK consumers
building custom PEP integrations.

For the thin PDP client (Option B, delegating to Go core), see
``capiscio_mcp.pip.PolicyClient``.

Usage::

    from capiscio_sdk.pip import (
        PIPRequest, SubjectAttributes, ActionAttributes,
        ResourceAttributes, ContextAttributes, EnvironmentAttributes,
        PIPResponse, Obligation, EnforcementMode,
    )

    request = PIPRequest(
        subject=SubjectAttributes(
            did="did:web:example.com:agents:bot",
            badge_jti="badge-session-id",
            ial="IAL-1",
            trust_level="2",
        ),
        action=ActionAttributes(operation="tools/call"),
        resource=ResourceAttributes(identifier="database://prod/users"),
        context=ContextAttributes(
            txn_id="019471a2-...",
            enforcement_mode="EM-OBSERVE",
        ),
    )
    payload = request.to_dict()
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PIP_VERSION = "capiscio.pip.v1"
"""Protocol version identifier. PEPs MUST include this in every request."""

DECISION_ALLOW = "ALLOW"
DECISION_DENY = "DENY"
DECISION_OBSERVE = "ALLOW_OBSERVE"
"""PEP-only telemetry value for EM-OBSERVE fallback on PDP unavailability."""


# ---------------------------------------------------------------------------
# Enforcement Mode
# ---------------------------------------------------------------------------


class EnforcementMode(Enum):
    """PEP enforcement strictness level (RFC-008 §10.5 total order).

    Values:
        OBSERVE: Log only, never block.
        GUARD: Block on verification failure, log PDP denials.
        DELEGATE: Block on verification + PDP deny, best-effort obligations.
        STRICT: Block on everything including obligation failures.
    """

    OBSERVE = "EM-OBSERVE"
    GUARD = "EM-GUARD"
    DELEGATE = "EM-DELEGATE"
    STRICT = "EM-STRICT"

    def stricter_than(self, other: EnforcementMode) -> bool:
        """Return True if this mode is stricter than *other*."""
        order = list(EnforcementMode)
        return order.index(self) > order.index(other)

    @classmethod
    def from_env(cls) -> EnforcementMode:
        """Read enforcement mode from ``CAPISCIO_ENFORCEMENT_MODE``.

        Returns ``OBSERVE`` (the safe rollout default) when the variable
        is unset or empty.

        Raises:
            ValueError: If the variable is set but not a recognised mode.
        """
        val = os.environ.get("CAPISCIO_ENFORCEMENT_MODE", "")
        if not val:
            return cls.OBSERVE
        try:
            return cls(val)
        except ValueError:
            valid = ", ".join(m.value for m in cls)
            raise ValueError(
                f"Unknown enforcement mode: {val!r} (valid: {valid})"
            ) from None


# ---------------------------------------------------------------------------
# Request types (RFC-005 §5)
# ---------------------------------------------------------------------------


@dataclass
class SubjectAttributes:
    """Identifies the acting agent (RFC-005 §5.1).

    Attributes:
        did: Agent DID from badge ``sub`` claim.
        badge_jti: Badge ``jti`` claim.
        ial: Identity Assurance Level (e.g. ``"IAL-1"``).
        trust_level: Badge trust level string (e.g. ``"1"``, ``"2"``, ``"3"``).
    """

    did: str = ""
    badge_jti: str = ""
    ial: str = ""
    trust_level: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "did": self.did,
            "badge_jti": self.badge_jti,
            "ial": self.ial,
            "trust_level": self.trust_level,
        }


@dataclass
class ActionAttributes:
    """Identifies what is being attempted (RFC-005 §5.1).

    Attributes:
        operation: Tool name, HTTP method+route, etc.
        capability_class: ``None`` in badge-only mode (RFC-008).
    """

    operation: str = ""
    capability_class: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability_class": self.capability_class,
            "operation": self.operation,
        }


@dataclass
class ResourceAttributes:
    """Identifies the target resource (RFC-005 §5.1).

    Attributes:
        identifier: Target resource URI.
    """

    identifier: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {"identifier": self.identifier}


@dataclass
class ContextAttributes:
    """Correlation and authority context (RFC-005 §5.1).

    Envelope-sourced fields (``envelope_id``, ``delegation_depth``,
    ``constraints``, ``parent_constraints``) MUST be ``None`` in
    badge-only mode. They serialise as JSON ``null``, not absent keys.

    Attributes:
        txn_id: Transaction correlation ID (UUID v7 recommended).
        enforcement_mode: PEP-level enforcement mode string.
        hop_id: Optional hop attestation ID.
        envelope_id: ``None`` until RFC-008.
        delegation_depth: ``None`` until RFC-008.
        constraints: ``None`` until RFC-008.
        parent_constraints: ``None`` until RFC-008.
    """

    txn_id: str = ""
    enforcement_mode: Union[str, EnforcementMode] = "EM-OBSERVE"
    hop_id: Optional[str] = None
    envelope_id: Optional[str] = None
    delegation_depth: Optional[int] = None
    constraints: Optional[Any] = None
    parent_constraints: Optional[Any] = None

    def __post_init__(self) -> None:
        if isinstance(self.enforcement_mode, EnforcementMode):
            self.enforcement_mode = self.enforcement_mode.value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "txn_id": self.txn_id,
            "hop_id": self.hop_id,
            "envelope_id": self.envelope_id,
            "delegation_depth": self.delegation_depth,
            "constraints": self.constraints,
            "parent_constraints": self.parent_constraints,
            "enforcement_mode": self.enforcement_mode,
        }


@dataclass
class EnvironmentAttributes:
    """PEP runtime context (RFC-005 §5.1).

    Attributes:
        workspace: Optional workspace / tenant identifier.
        pep_id: Optional PEP instance identifier.
        time: ISO 8601 timestamp (RECOMMENDED). Auto-populated by
            :meth:`PIPRequest.to_dict` if not set.
    """

    workspace: Optional[str] = None
    pep_id: Optional[str] = None
    time: Optional[str] = None

    def to_dict(self) -> Dict[str, Optional[str]]:
        d: Dict[str, Optional[str]] = {}
        if self.workspace is not None:
            d["workspace"] = self.workspace
        if self.pep_id is not None:
            d["pep_id"] = self.pep_id
        if self.time is not None:
            d["time"] = self.time
        return d


@dataclass
class PIPRequest:
    """RFC-005 §5 Decision Request.

    Attributes:
        subject: Agent identity attributes.
        action: Attempted operation.
        resource: Target resource.
        context: Correlation / authority context.
        environment: PEP runtime context.
        pip_version: Protocol version (auto-set).
    """

    subject: SubjectAttributes = field(default_factory=SubjectAttributes)
    action: ActionAttributes = field(default_factory=ActionAttributes)
    resource: ResourceAttributes = field(default_factory=ResourceAttributes)
    context: ContextAttributes = field(default_factory=ContextAttributes)
    environment: EnvironmentAttributes = field(default_factory=EnvironmentAttributes)
    pip_version: str = PIP_VERSION

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to PIP wire format (JSON-compatible dict).

        Automatically populates ``context.txn_id`` (UUID v7 via
        :func:`uuid.uuid7` when available, else :func:`uuid.uuid4`)
        and ``environment.time`` (ISO 8601 UTC) if not already set.
        """
        # Auto-populate txn_id if empty
        ctx = self.context
        if not ctx.txn_id:
            ctx.txn_id = _generate_uuid7()

        # Auto-populate environment time if missing
        env = self.environment
        if env.time is None:
            env.time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        return {
            "pip_version": self.pip_version,
            "subject": self.subject.to_dict(),
            "action": self.action.to_dict(),
            "resource": self.resource.to_dict(),
            "context": ctx.to_dict(),
            "environment": env.to_dict(),
        }


# ---------------------------------------------------------------------------
# Response types (RFC-005 §6)
# ---------------------------------------------------------------------------


@dataclass
class Obligation:
    """A conditional contract returned by the PDP (RFC-005 §7.1).

    Attributes:
        type: Obligation type (e.g. ``"rate_limit"``, ``"audit_log"``).
        params: Opaque parameters dictionary. ``None`` serialises as
            JSON ``null``.
    """

    type: str = ""
    params: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "params": self.params,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> Obligation:
        params = d.get("params")
        if params is not None and not isinstance(params, dict):
            params = None
        return cls(type=d.get("type", ""), params=params)


@dataclass
class PIPResponse:
    """RFC-005 §6.1 Decision Response.

    Attributes:
        decision: ``"ALLOW"`` or ``"DENY"`` (PDP values only).
        decision_id: Globally unique decision identifier.
        obligations: List of obligations to enforce.
        reason: Optional human-readable explanation.
        ttl: Optional cache lifetime in seconds.
    """

    decision: str = ""
    decision_id: str = ""
    obligations: List[Obligation] = field(default_factory=list)
    reason: str = ""
    ttl: Optional[int] = None

    @property
    def is_allow(self) -> bool:
        return self.decision == DECISION_ALLOW

    @property
    def is_deny(self) -> bool:
        return self.decision == DECISION_DENY

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "decision": self.decision,
            "decision_id": self.decision_id,
            "obligations": [o.to_dict() for o in self.obligations],
        }
        if self.reason:
            d["reason"] = self.reason
        if self.ttl is not None:
            d["ttl"] = self.ttl
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> PIPResponse:
        obligations_raw = d.get("obligations") or []
        obligations = [Obligation.from_dict(o) for o in obligations_raw if isinstance(o, dict)]
        return cls(
            decision=d.get("decision", ""),
            decision_id=d.get("decision_id", ""),
            obligations=obligations,
            reason=d.get("reason", ""),
            ttl=d.get("ttl"),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generate_uuid7() -> str:
    """Generate a UUID v7 string if available, falling back to UUID v4."""
    # Python 3.14+ has uuid.uuid7(), earlier versions need fallback
    if hasattr(uuid, "uuid7"):
        return str(uuid.uuid7())  # type: ignore[attr-defined]
    return str(uuid.uuid4())
