"""Domain Validation (DV) Badge API for CapiscIO agents.

This module provides high-level API for DV badge orders (RFC-002 v1.2).
DV badges provide Level 1 trust with domain ownership verification.

Uses the capiscio-core gRPC service for all operations, following the
established RPC pattern.

Example usage:

    from capiscio_sdk.dv import create_dv_order, get_dv_order, finalize_dv_order
    import json

    # Load agent's public key
    with open("public.jwk") as f:
        jwk = json.load(f)

    # Create a DV order
    order = create_dv_order(
        domain="example.com",
        challenge_type="http-01",
        jwk=jwk,
    )

    print(f"Order ID: {order.order_id}")
    print(f"Place this token at: {order.validation_url}")
    print(f"Token: {order.challenge_token}")

    # After completing the challenge, finalize the order
    grant = finalize_dv_order(order.order_id)
    print(f"Grant JWT: {grant.grant}")

    # Save the grant for later use
    with open("grant.jwt", "w") as f:
        f.write(grant.grant)
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
import json

from capiscio_sdk._rpc.client import CapiscioRPCClient


@dataclass
class DVOrder:
    """Domain Validation badge order.

    Attributes:
        order_id: Unique order identifier (UUID).
        domain: Domain being validated.
        challenge_type: Type of challenge (http-01 or dns-01).
        challenge_token: Token to place for validation.
        status: Order status (pending, valid, invalid, expired).
        validation_url: URL where token should be placed (http-01).
        dns_record: DNS record to create (dns-01).
        expires_at: When the order expires.
        finalized_at: When the order was finalized (if applicable).
    """

    order_id: str
    domain: str
    challenge_type: str
    challenge_token: str
    status: str
    validation_url: str = ""
    dns_record: str = ""
    expires_at: Optional[datetime] = None
    finalized_at: Optional[datetime] = None


@dataclass
class DVGrant:
    """Domain Validation grant JWT.

    Attributes:
        grant: The signed grant JWT token.
        expires_at: When the grant expires.
    """

    grant: str
    expires_at: Optional[datetime] = None


# Module-level client (lazy initialization)
_client: Optional[CapiscioRPCClient] = None


def _get_client() -> CapiscioRPCClient:
    """Get or create the module-level gRPC client."""
    global _client
    if _client is None:
        _client = CapiscioRPCClient()
        _client.connect()
    return _client


def _parse_timestamp(ts: str) -> Optional[datetime]:
    """Parse ISO 8601 timestamp string to datetime."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def create_dv_order(
    domain: str,
    challenge_type: str,
    jwk: dict,
    ca_url: str = "https://registry.capisc.io",
) -> DVOrder:
    """Create a new DV badge order.

    Uses the capiscio-core gRPC service to create the order.

    Args:
        domain: Domain to validate (e.g., "example.com").
        challenge_type: Challenge type ("http-01" or "dns-01").
        jwk: Agent's public key in JWK format (dict).
        ca_url: Certificate Authority URL.

    Returns:
        DVOrder with challenge details.

    Raises:
        ValueError: If the CA returns an error.

    Example:
        import json

        with open("public.jwk") as f:
            jwk = json.load(f)

        order = create_dv_order(
            domain="example.com",
            challenge_type="http-01",
            jwk=jwk,
        )

        print(f"Place token at: {order.validation_url}")
    """
    if challenge_type not in ("http-01", "dns-01"):
        raise ValueError(
            f"Invalid challenge_type: {challenge_type}. Must be 'http-01' or 'dns-01'"
        )

    try:
        client = _get_client()

        # Convert JWK dict to JSON string
        jwk_str = json.dumps(jwk)

        success, order_dict, error = client.badge.create_dv_order(
            domain=domain,
            challenge_type=challenge_type,
            jwk=jwk_str,
            ca_url=ca_url,
        )

        if not success:
            raise ValueError(f"CA rejected DV order: {error}")

        if not order_dict:
            raise ValueError("CA response missing order data")

        return DVOrder(
            order_id=order_dict["order_id"],
            domain=order_dict["domain"],
            challenge_type=order_dict["challenge_type"],
            challenge_token=order_dict["challenge_token"],
            status=order_dict["status"],
            validation_url=order_dict.get("validation_url", ""),
            dns_record=order_dict.get("dns_record", ""),
            expires_at=_parse_timestamp(order_dict.get("expires_at", "")),
        )

    except Exception as e:
        if isinstance(e, ValueError):
            raise
        raise ValueError(f"Failed to create DV order: {e}") from e


def get_dv_order(
    order_id: str,
    ca_url: str = "https://registry.capisc.io",
) -> DVOrder:
    """Get the status of a DV badge order.

    Uses the capiscio-core gRPC service to check order status.

    Args:
        order_id: Order ID from create_dv_order.
        ca_url: Certificate Authority URL.

    Returns:
        DVOrder with current status.

    Raises:
        ValueError: If the CA returns an error.

    Example:
        order = get_dv_order("550e8400-e29b-41d4-a716-446655440000")
        print(f"Status: {order.status}")
    """
    try:
        client = _get_client()

        success, order_dict, error = client.badge.get_dv_order(
            order_id=order_id,
            ca_url=ca_url,
        )

        if not success:
            raise ValueError(f"Failed to get DV order: {error}")

        if not order_dict:
            raise ValueError("CA response missing order data")

        return DVOrder(
            order_id=order_dict["order_id"],
            domain=order_dict["domain"],
            challenge_type=order_dict["challenge_type"],
            challenge_token=order_dict["challenge_token"],
            status=order_dict["status"],
            validation_url=order_dict.get("validation_url", ""),
            dns_record=order_dict.get("dns_record", ""),
            expires_at=_parse_timestamp(order_dict.get("expires_at", "")),
            finalized_at=_parse_timestamp(order_dict.get("finalized_at", "")),
        )

    except Exception as e:
        if isinstance(e, ValueError):
            raise
        raise ValueError(f"Failed to get DV order: {e}") from e


def finalize_dv_order(
    order_id: str,
    ca_url: str = "https://registry.capisc.io",
) -> DVGrant:
    """Finalize a DV badge order and receive a grant.

    Uses the capiscio-core gRPC service to finalize the order.

    Args:
        order_id: Order ID from create_dv_order.
        ca_url: Certificate Authority URL.

    Returns:
        DVGrant with the signed grant JWT.

    Raises:
        ValueError: If the CA returns an error.

    Example:
        grant = finalize_dv_order("550e8400-e29b-41d4-a716-446655440000")

        # Save grant
        with open("grant.jwt", "w") as f:
            f.write(grant.grant)
    """
    try:
        client = _get_client()

        success, grant_dict, error = client.badge.finalize_dv_order(
            order_id=order_id,
            ca_url=ca_url,
        )

        if not success:
            raise ValueError(f"Failed to finalize DV order: {error}")

        if not grant_dict:
            raise ValueError("CA response missing grant data")

        return DVGrant(
            grant=grant_dict["grant"],
            expires_at=_parse_timestamp(grant_dict.get("expires_at", "")),
        )

    except Exception as e:
        if isinstance(e, ValueError):
            raise
        raise ValueError(f"Failed to finalize DV order: {e}") from e


__all__ = [
    "DVOrder",
    "DVGrant",
    "create_dv_order",
    "get_dv_order",
    "finalize_dv_order",
]
