"""Trust Badge API for CapiscIO agents.

This module provides a user-friendly API for working with Trust Badges,
which are signed JWS tokens that provide portable, verifiable identity
for agents. See RFC-002 for the full specification.

Example usage:

    from capiscio_sdk.badge import verify_badge, parse_badge, VerifyOptions

    # Verify a badge with full validation
    result = verify_badge(
        token,
        trusted_issuers=["https://registry.capisc.io"],
        audience="https://my-service.example.com",
    )

    if result.valid:
        print(f"Badge valid for agent: {result.claims.agent_id}")
        print(f"Trust level: {result.claims.trust_level}")
    else:
        print(f"Verification failed: {result.error}")

    # Parse without verification (for inspection)
    claims = parse_badge(token)
    print(f"Issuer: {claims.issuer}")
    print(f"Expires: {claims.expires_at}")
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Union

from capiscio_sdk._rpc.client import CapiscioRPCClient


def _utc_now() -> datetime:
    """Get current UTC time as naive datetime (for comparison with JWT timestamps)."""
    # JWT timestamps are typically naive UTC, so we compare with naive UTC
    from datetime import timezone

    return datetime.now(timezone.utc).replace(tzinfo=None)


def _from_utc_timestamp(ts: float) -> datetime:
    """Convert UTC timestamp to naive datetime."""
    from datetime import timezone

    return datetime.fromtimestamp(ts, timezone.utc).replace(tzinfo=None)


class VerifyMode(Enum):
    """Badge verification mode."""

    ONLINE = "online"
    """Perform real-time checks against the registry (revocation, agent status)."""

    OFFLINE = "offline"
    """Use only local trust store and revocation cache."""

    HYBRID = "hybrid"
    """Try online checks, fall back to cache if unavailable."""


class TrustLevel(Enum):
    """Trust level as defined in RFC-002."""

    LEVEL_1 = "1"
    """Domain Validated (DV) - Basic verification."""

    LEVEL_2 = "2"
    """Organization Validated (OV) - Business verification."""

    LEVEL_3 = "3"
    """Extended Validation (EV) - Rigorous vetting."""

    @classmethod
    def from_string(cls, value: str) -> "TrustLevel":
        """Create TrustLevel from string value."""
        for level in cls:
            if level.value == value:
                return level
        raise ValueError(f"Unknown trust level: {value}")


@dataclass
class BadgeClaims:
    """Parsed badge claims from a Trust Badge token.

    Attributes:
        jti: Unique badge identifier (UUID).
        issuer: Badge issuer URL (CA).
        subject: Agent DID (did:web format).
        audience: Optional list of intended audience URLs.
        issued_at: When the badge was issued.
        expires_at: When the badge expires.
        trust_level: Trust level (1=DV, 2=OV, 3=EV).
        domain: Agent's verified domain.
        agent_name: Human-readable agent name.
        agent_id: Extracted agent ID from subject DID.
    """

    jti: str
    issuer: str
    subject: str
    issued_at: datetime
    expires_at: datetime
    trust_level: TrustLevel
    domain: str
    agent_name: str = ""
    audience: List[str] = field(default_factory=list)

    @property
    def agent_id(self) -> str:
        """Extract agent ID from subject DID."""
        # did:web:registry.capisc.io:agents:my-agent -> my-agent
        parts = self.subject.split(":")
        if len(parts) >= 5 and parts[3] == "agents":
            return parts[4]
        return ""

    @property
    def is_expired(self) -> bool:
        """Check if the badge has expired."""
        return _utc_now() > self.expires_at

    @property
    def is_not_yet_valid(self) -> bool:
        """Check if the badge is not yet valid."""
        return _utc_now() < self.issued_at

    @classmethod
    def from_dict(cls, data: dict) -> "BadgeClaims":
        """Create BadgeClaims from a dictionary."""
        return cls(
            jti=data.get("jti", ""),
            issuer=data.get("iss", ""),
            subject=data.get("sub", ""),
            issued_at=_from_utc_timestamp(data.get("iat", 0)),
            expires_at=_from_utc_timestamp(data.get("exp", 0)),
            trust_level=TrustLevel.from_string(data.get("trust_level", "1")),
            domain=data.get("domain", ""),
            agent_name=data.get("agent_name", ""),
            audience=data.get("aud", []),
        )

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "jti": self.jti,
            "iss": self.issuer,
            "sub": self.subject,
            "iat": int(self.issued_at.timestamp()),
            "exp": int(self.expires_at.timestamp()),
            "trust_level": self.trust_level.value,
            "domain": self.domain,
            "agent_name": self.agent_name,
            "aud": self.audience,
        }


@dataclass
class VerifyOptions:
    """Options for badge verification.

    Attributes:
        mode: Verification mode (online, offline, hybrid).
        trusted_issuers: List of trusted issuer URLs.
        audience: Expected audience (your service URL).
        skip_revocation_check: Skip revocation check (testing only).
        skip_agent_status_check: Skip agent status check (testing only).
        public_key_jwk: Override public key (for offline verification).
    """

    mode: VerifyMode = VerifyMode.ONLINE
    trusted_issuers: List[str] = field(default_factory=list)
    audience: Optional[str] = None
    skip_revocation_check: bool = False
    skip_agent_status_check: bool = False
    public_key_jwk: Optional[str] = None


@dataclass
class VerifyResult:
    """Result of badge verification.

    Attributes:
        valid: Whether the badge is valid.
        claims: Parsed badge claims (if valid or parseable).
        error: Error message if verification failed.
        error_code: RFC-002 error code if applicable.
        warnings: Non-fatal issues encountered.
        mode: Verification mode that was used.
    """

    valid: bool
    claims: Optional[BadgeClaims] = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    mode: VerifyMode = VerifyMode.ONLINE


# Module-level client (lazy initialization)
_client: Optional[CapiscioRPCClient] = None


def _get_client() -> CapiscioRPCClient:
    """Get or create the module-level gRPC client."""
    global _client
    if _client is None:
        _client = CapiscioRPCClient()
        _client.connect()
    return _client


def verify_badge(
    token: str,
    *,
    trusted_issuers: Optional[List[str]] = None,
    audience: Optional[str] = None,
    mode: Union[VerifyMode, str] = VerifyMode.ONLINE,
    skip_revocation_check: bool = False,
    skip_agent_status_check: bool = False,
    public_key_jwk: Optional[str] = None,
    options: Optional[VerifyOptions] = None,
) -> VerifyResult:
    """Verify a Trust Badge token.

    Performs full RFC-002 verification including:
    - JWS signature verification
    - Claims validation (exp, iat, iss, sub, aud)
    - Revocation check (online/hybrid modes)
    - Agent status check (online/hybrid modes)

    Args:
        token: The badge JWT/JWS token to verify.
        trusted_issuers: List of trusted issuer URLs. If empty, all issuers accepted.
        audience: Your service URL for audience validation.
        mode: Verification mode (online, offline, hybrid).
        skip_revocation_check: Skip revocation check (testing only).
        skip_agent_status_check: Skip agent status check (testing only).
        public_key_jwk: Override public key JWK for offline verification.
        options: VerifyOptions object (alternative to individual args).

    Returns:
        VerifyResult with validation status and claims.

    Example:
        result = verify_badge(
            token,
            trusted_issuers=["https://registry.capisc.io"],
            audience="https://my-service.example.com",
        )

        if result.valid:
            print(f"Agent {result.claims.agent_id} verified at level {result.claims.trust_level}")
    """
    # Build options from individual args or use provided options
    if options is None:
        if isinstance(mode, str):
            mode = VerifyMode(mode)
        options = VerifyOptions(
            mode=mode,
            trusted_issuers=trusted_issuers or [],
            audience=audience,
            skip_revocation_check=skip_revocation_check,
            skip_agent_status_check=skip_agent_status_check,
            public_key_jwk=public_key_jwk,
        )

    try:
        client = _get_client()

        # Use the gRPC BadgeClient to verify
        valid, claims_dict, error = client.badge.verify_badge(
            token=token,
            public_key_jwk=options.public_key_jwk or "",
        )

        # Convert claims if available
        claims = None
        if claims_dict:
            claims = BadgeClaims.from_dict(claims_dict)

        # Build result
        if valid:
            # Additional client-side validation
            warnings = []

            # Check trusted issuers
            if options.trusted_issuers and claims:
                if claims.issuer not in options.trusted_issuers:
                    return VerifyResult(
                        valid=False,
                        claims=claims,
                        error=f"Issuer {claims.issuer} not in trusted list",
                        error_code="BADGE_ISSUER_UNTRUSTED",
                        mode=options.mode,
                    )

            # Check audience
            if options.audience and claims and claims.audience:
                if options.audience not in claims.audience:
                    return VerifyResult(
                        valid=False,
                        claims=claims,
                        error=f"Audience {options.audience} not in badge audience",
                        error_code="BADGE_AUDIENCE_MISMATCH",
                        mode=options.mode,
                    )

            return VerifyResult(
                valid=True,
                claims=claims,
                warnings=warnings,
                mode=options.mode,
            )
        else:
            # Verification failed
            error_code = None
            if error:
                # Extract error code from message if present
                for code in [
                    "BADGE_MALFORMED",
                    "BADGE_SIGNATURE_INVALID",
                    "BADGE_EXPIRED",
                    "BADGE_NOT_YET_VALID",
                    "BADGE_ISSUER_UNTRUSTED",
                    "BADGE_AUDIENCE_MISMATCH",
                    "BADGE_REVOKED",
                    "BADGE_CLAIMS_INVALID",
                    "BADGE_AGENT_DISABLED",
                ]:
                    if code in error:
                        error_code = code
                        break

            return VerifyResult(
                valid=False,
                claims=claims,
                error=error,
                error_code=error_code,
                mode=options.mode,
            )

    except Exception as e:
        return VerifyResult(
            valid=False,
            error=str(e),
            mode=options.mode if options else VerifyMode.ONLINE,
        )


def parse_badge(token: str) -> BadgeClaims:
    """Parse badge claims without verification.

    Use this to inspect badge contents before full verification,
    or to extract claims for display purposes.

    Args:
        token: The badge JWT/JWS token to parse.

    Returns:
        BadgeClaims object with parsed claims.

    Raises:
        ValueError: If the token cannot be parsed.

    Example:
        claims = parse_badge(token)
        print(f"Badge for: {claims.agent_id}")
        print(f"Issued by: {claims.issuer}")
        print(f"Expires: {claims.expires_at}")
    """
    try:
        client = _get_client()
        claims_dict, error = client.badge.parse_badge(token)

        if error:
            raise ValueError(f"Failed to parse badge: {error}")

        if claims_dict is None:
            raise ValueError("No claims returned from parser")

        return BadgeClaims.from_dict(claims_dict)

    except Exception as e:
        if isinstance(e, ValueError):
            raise
        raise ValueError(f"Failed to parse badge: {e}") from e


async def request_badge(
    agent_id: str,
    *,
    ca_url: str = "https://registry.capisc.io",
    api_key: Optional[str] = None,
    domain: Optional[str] = None,
    trust_level: Union[TrustLevel, str] = TrustLevel.LEVEL_1,
    audience: Optional[List[str]] = None,
    timeout: float = 30.0,
) -> str:
    """Request a new Trust Badge from a Certificate Authority.

    This sends a request to the CA to issue a new badge for the agent.
    The CA will verify the agent's identity based on the trust level
    and return a signed badge token.
    
    Uses the capiscio-core gRPC service for the actual request.

    Args:
        agent_id: The agent identifier to request a badge for.
        ca_url: Certificate Authority URL (default: CapiscIO registry).
        api_key: API key for authentication with the CA.
        domain: Agent's domain (required for verification).
        trust_level: Requested trust level (1=DV, 2=OV, 3=EV).
        audience: Optional audience restrictions for the badge.
        timeout: Request timeout in seconds (not used with gRPC).

    Returns:
        The signed badge JWT token.

    Raises:
        ValueError: If the CA returns an error.

    Example:
        token = await request_badge(
            agent_id="my-agent",
            ca_url="https://registry.capisc.io",
            api_key=os.environ["CAPISCIO_API_KEY"],
            domain="example.com",
        )

        # Save the token for later use
        with open("badge.jwt", "w") as f:
            f.write(token)
    """
    # Use sync version since gRPC client is sync
    return request_badge_sync(
        agent_id,
        ca_url=ca_url,
        api_key=api_key,
        domain=domain,
        trust_level=trust_level,
        audience=audience,
        timeout=timeout,
    )


def request_badge_sync(
    agent_id: str,
    *,
    ca_url: str = "https://registry.capisc.io",
    api_key: Optional[str] = None,
    domain: Optional[str] = None,
    trust_level: Union[TrustLevel, str] = TrustLevel.LEVEL_1,
    audience: Optional[List[str]] = None,
    timeout: float = 30.0,
) -> str:
    """Synchronous version of request_badge.

    Uses the capiscio-core gRPC service for the actual request.
    See request_badge for full documentation.
    """
    if isinstance(trust_level, str):
        trust_level = TrustLevel.from_string(trust_level)

    # Convert TrustLevel enum to int for gRPC
    trust_level_int = int(trust_level.value)

    try:
        client = _get_client()
        success, result, error = client.badge.request_badge(
            agent_id=agent_id,
            api_key=api_key or "",
            ca_url=ca_url,
            domain=domain or "",
            ttl_seconds=300,  # Default per RFC-002
            trust_level=trust_level_int,
            audience=audience,
        )

        if not success:
            raise ValueError(f"CA rejected badge request: {error}")

        token = result.get("token")
        if not token:
            raise ValueError("CA response missing token")

        return token

    except Exception as e:
        if isinstance(e, ValueError):
            raise
        raise ValueError(f"Failed to request badge: {e}") from e


async def request_pop_badge(
    agent_did: str,
    private_key_jwk: str,
    *,
    ca_url: str = "https://registry.capisc.io",
    api_key: Optional[str] = None,
    ttl_seconds: int = 300,
    audience: Optional[List[str]] = None,
    timeout: float = 30.0,
) -> str:
    """Request a Trust Badge using Proof of Possession (RFC-003).

    This requests a badge using the PoP challenge-response protocol,
    providing IAL-1 assurance with cryptographic key binding. The agent
    must prove possession of the private key associated with their DID.

    Uses the capiscio-core gRPC service for the actual PoP flow.

    Args:
        agent_did: The agent DID (did:web:... or did:key:...).
        private_key_jwk: Private key in JWK format (JSON string).
        ca_url: Certificate Authority URL (default: CapiscIO registry).
        api_key: API key for authentication with the CA.
        ttl_seconds: Requested badge TTL in seconds (default: 300).
        audience: Optional audience restrictions for the badge.
        timeout: Request timeout in seconds (not used with gRPC).

    Returns:
        The signed badge JWT token with IAL-1 assurance.

    Raises:
        ValueError: If the CA returns an error or PoP verification fails.

    Example:
        import json
        
        # Load private key
        with open("private.jwk") as f:
            private_key_jwk = json.dumps(json.load(f))
        
        token = await request_pop_badge(
            agent_did="did:web:registry.capisc.io:agents:my-agent",
            private_key_jwk=private_key_jwk,
            ca_url="https://registry.capisc.io",
            api_key=os.environ["CAPISCIO_API_KEY"],
        )

        # Verify the badge has IAL-1
        claims = parse_badge(token)
        # Note: IAL-1 badges have a 'cnf' claim with key binding
    """
    # Use sync version since gRPC client is sync
    return request_pop_badge_sync(
        agent_did,
        private_key_jwk,
        ca_url=ca_url,
        api_key=api_key,
        ttl_seconds=ttl_seconds,
        audience=audience,
        timeout=timeout,
    )


def request_pop_badge_sync(
    agent_did: str,
    private_key_jwk: str,
    *,
    ca_url: str = "https://registry.capisc.io",
    api_key: Optional[str] = None,
    ttl_seconds: int = 300,
    audience: Optional[List[str]] = None,
    timeout: float = 30.0,
) -> str:
    """Synchronous version of request_pop_badge.

    Uses the capiscio-core gRPC service for the actual PoP flow.
    See request_pop_badge for full documentation.
    """
    try:
        client = _get_client()
        success, result, error = client.badge.request_pop_badge(
            agent_did=agent_did,
            private_key_jwk=private_key_jwk,
            api_key=api_key or "",
            ca_url=ca_url,
            ttl_seconds=ttl_seconds,
            audience=audience,
        )

        if not success:
            raise ValueError(f"PoP badge request failed: {error}")

        token = result.get("token")
        if not token:
            raise ValueError("CA response missing token")

        return token
    except Exception as e:
        if isinstance(e, ValueError):
            raise
        raise ValueError(f"Failed to request PoP badge: {e}") from e


def start_badge_keeper(
    mode: str,
    *,
    agent_id: str = "",
    api_key: str = "",
    ca_url: str = "https://registry.capisc.io",
    private_key_path: str = "",
    output_file: str = "badge.jwt",
    domain: str = "",
    ttl_seconds: int = 300,
    renew_before_seconds: int = 60,
    check_interval_seconds: int = 30,
    trust_level: Union[TrustLevel, str, int] = TrustLevel.LEVEL_1,
):
    """Start a badge keeper daemon (RFC-002 §7.3).
    
    The keeper automatically renews badges before they expire, ensuring
    continuous operation. Returns a generator of keeper events.
    
    Args:
        mode: 'ca' for CA mode, 'self-sign' for development
        agent_id: Agent UUID (required for CA mode)
        api_key: API key (required for CA mode)
        ca_url: CA URL (default: https://registry.capisc.io)
        private_key_path: Path to private key JWK (required for self-sign)
        output_file: Path to write badge file
        domain: Agent domain
        ttl_seconds: Badge TTL (default: 300)
        renew_before_seconds: Renew this many seconds before expiry (default: 60)
        check_interval_seconds: Check interval (default: 30)
        trust_level: Trust level for CA mode (1-4, default: 1)
        
    Yields:
        KeeperEvent dicts with: type, badge_jti, subject, trust_level,
        expires_at, error, error_code, timestamp, token
        
    Example:
        # CA mode - production
        for event in start_badge_keeper(
            mode="ca",
            agent_id="my-agent-uuid",
            api_key=os.environ["CAPISCIO_API_KEY"],
        ):
            if event["type"] == "renewed":
                print(f"Badge renewed: {event['badge_jti']}")
            elif event["type"] == "error":
                print(f"Error: {event['error']}")
                
        # Self-sign mode - development
        for event in start_badge_keeper(
            mode="self-sign",
            private_key_path="private.jwk",
        ):
            print(f"Event: {event['type']}")
    """
    # Convert trust level to int if needed
    if isinstance(trust_level, TrustLevel):
        trust_level_int = int(trust_level.value)
    elif isinstance(trust_level, str):
        trust_level_int = int(TrustLevel.from_string(trust_level).value)
    else:
        trust_level_int = trust_level

    client = _get_client()
    yield from client.badge.start_keeper(
        mode=mode,
        agent_id=agent_id,
        api_key=api_key,
        ca_url=ca_url,
        private_key_path=private_key_path,
        output_file=output_file,
        domain=domain,
        ttl_seconds=ttl_seconds,
        renew_before_seconds=renew_before_seconds,
        check_interval_seconds=check_interval_seconds,
        trust_level=trust_level_int,
    )


# Export public API
__all__ = [
    # Types
    "BadgeClaims",
    "VerifyOptions",
    "VerifyResult",
    "VerifyMode",
    "TrustLevel",
    # Functions
    "verify_badge",
    "parse_badge",
    "request_badge",
    "request_badge_sync",
    "start_badge_keeper",
]
