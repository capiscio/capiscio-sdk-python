"""SimpleGuard: Local, zero-config security for A2A agents."""
import os
import json
import logging
import base64
import hashlib
import time
from pathlib import Path
from typing import Optional, Dict, Any, Union

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .errors import ConfigurationError, VerificationError

logger = logging.getLogger(__name__)

MAX_TOKEN_AGE = 60
CLOCK_SKEW_LEEWAY = 5

class SimpleGuard:
    """
    The "Customs Officer" for your Agent.
    
    Enforces Identity (JWS) and Protocol (A2A) validation locally.
    Prioritizes local utility and zero-configuration.
    """

    def __init__(
        self, 
        base_dir: Optional[Union[str, Path]] = None, 
        dev_mode: bool = False
    ):
        """
        Initialize SimpleGuard.

        Args:
            base_dir: Starting directory to search for config (defaults to cwd).
            dev_mode: If True, auto-generates keys and agent-card.json.
        """
        self.dev_mode = dev_mode
        
        # 1. Safety Check
        if self.dev_mode and os.getenv("CAPISCIO_ENV") == "prod":
            logger.critical(
                "CRITICAL: SimpleGuard initialized in dev_mode=True but CAPISCIO_ENV=prod. "
                "This is insecure! Disable dev_mode in production."
            )

        # 2. Resolve base_dir (Walk up logic)
        self.project_root = self._resolve_project_root(base_dir)
        self.keys_dir = self.project_root / "capiscio_keys"
        self.trusted_dir = self.keys_dir / "trusted"
        self.agent_card_path = self.project_root / "agent-card.json"
        self.private_key_path = self.keys_dir / "private.pem"
        self.public_key_path = self.keys_dir / "public.pem"

        # 3. Load or Generate agent-card.json
        self.agent_id: str
        self.signing_kid: str
        self._load_or_generate_card()

        # 4. Load or Generate Keys
        self._private_key: ed25519.Ed25519PrivateKey
        self._load_or_generate_keys()

        # 5. Load Trust Store (and self-trust in dev mode)
        self._setup_trust_store()

    def sign_outbound(self, payload: Dict[str, Any], body: Optional[bytes] = None) -> str:
        """
        Sign a payload for outbound transmission.

        Args:
            payload: The JSON payload to sign.
            body: Optional HTTP body bytes to bind to the signature.

        Returns:
            Compact JWS string.
        """
        # Inject issuer if missing
        if "iss" not in payload:
            payload["iss"] = self.agent_id
        
        # Replay Protection: Inject timestamps
        now = int(time.time())
        if "iat" not in payload:
            payload["iat"] = now
        if "exp" not in payload:
            payload["exp"] = now + MAX_TOKEN_AGE
        
        # Integrity: Calculate Body Hash if body is provided
        if body is not None:
            # SHA-256 hash
            sha256_hash = hashlib.sha256(body).digest()
            # Base64Url encode (no padding)
            bh = base64.urlsafe_b64encode(sha256_hash).decode('utf-8').rstrip('=')
            payload["bh"] = bh

        # Prepare headers
        headers = {
            "kid": self.signing_kid,
            "typ": "JWT",
            "alg": "EdDSA"
        }

        # Sign
        try:
            token = jwt.encode(
                payload,
                self._private_key,
                algorithm="EdDSA",
                headers=headers
            )
            return token
        except Exception as e:
            raise ConfigurationError(f"Failed to sign payload: {e}")

    def verify_inbound(self, jws: str, body: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Verify an inbound JWS.

        Args:
            jws: The compact JWS string.
            body: Optional HTTP body bytes to verify against 'bh' claim.

        Returns:
            The verified payload.

        Raises:
            VerificationError: If signature is invalid, key is untrusted, or integrity check fails.
        """
        try:
            # 1. Parse Header to get kid (without verifying yet)
            header = jwt.get_unverified_header(jws)
            kid = header.get("kid")
            
            if not kid:
                raise VerificationError("Missing 'kid' in JWS header.")

            # 2. Resolution: Look for trusted key
            trusted_key_path = self.trusted_dir / f"{kid}.pem"
            if not trusted_key_path.exists():
                logger.warning(f'{{"event": "agent_call_denied", "kid": "{kid}", "reason": "untrusted_key"}}')
                raise VerificationError(f"Untrusted key ID: {kid}")

            # Load the trusted public key
            with open(trusted_key_path, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())

            # 3. Verify Signature
            payload = jwt.decode(
                jws,
                public_key,
                algorithms=["EdDSA"],
                options={"verify_aud": False} # Audience verification depends on context, skipping for generic guard
            )

            # 4. Integrity Check (Body Hash)
            if "bh" in payload:
                if body is None:
                    raise VerificationError("JWS contains 'bh' claim but no body provided for verification.")
                
                # Calculate hash of received body
                sha256_hash = hashlib.sha256(body).digest()
                calculated_bh = base64.urlsafe_b64encode(sha256_hash).decode('utf-8').rstrip('=')
                
                if calculated_bh != payload["bh"]:
                    logger.warning(f'{{"event": "agent_call_denied", "kid": "{kid}", "reason": "integrity_check_failed"}}')
                    raise VerificationError("Integrity Check Failed: Body modified")

            # 5. Replay Protection (Timestamp Enforcement)
            now = int(time.time())
            exp = payload.get("exp")
            iat = payload.get("iat")

            if exp is None or iat is None:
                 raise VerificationError("Missing timestamp claims (exp, iat).")

            if now > (exp + CLOCK_SKEW_LEEWAY):
                 logger.warning(f'{{"event": "agent_call_denied", "kid": "{kid}", "reason": "token_expired"}}')
                 raise VerificationError("Token expired.")
            
            if now < (iat - CLOCK_SKEW_LEEWAY):
                 logger.warning(f'{{"event": "agent_call_denied", "kid": "{kid}", "reason": "clock_skew"}}')
                 raise VerificationError("Token not yet valid (Clock skew).")

            # 6. Observability
            iss = payload.get("iss", "unknown")
            logger.info(f'{{"event": "agent_call_allowed", "iss": "{iss}", "kid": "{kid}"}}')

            return payload

        except jwt.InvalidSignatureError:
            logger.warning(f'{{"event": "agent_call_denied", "kid": "{kid}", "reason": "invalid_signature"}}')
            raise VerificationError("Invalid signature.")
        except jwt.ExpiredSignatureError:
            logger.warning(f'{{"event": "agent_call_denied", "kid": "{kid}", "reason": "token_expired"}}')
            raise VerificationError("Token expired.")
        except jwt.DecodeError:
            raise VerificationError("Invalid JWS format.")
        except Exception as e:
            if isinstance(e, VerificationError):
                raise
            raise VerificationError(f"Verification failed: {e}")

    def make_headers(self, payload: Dict[str, Any], body: Optional[bytes] = None) -> Dict[str, str]:
        """Helper to generate the headers containing the JWS."""
        token = self.sign_outbound(payload, body=body)
        return {"X-Capiscio-JWS": token}

    def _resolve_project_root(self, base_dir: Optional[Union[str, Path]]) -> Path:
        """Walk up the directory tree to find agent-card.json or stop at root."""
        current = Path(base_dir or os.getcwd()).resolve()
        
        # If we are in dev mode and nothing exists, we might just use cwd
        # But let's try to find an existing project structure first
        search_path = current
        while search_path != search_path.parent:
            if (search_path / "agent-card.json").exists():
                return search_path
            search_path = search_path.parent
        
        # If not found, default to cwd
        return current

    def _load_or_generate_card(self):
        """Load agent-card.json or generate a minimal one in dev_mode."""
        if self.agent_card_path.exists():
            try:
                with open(self.agent_card_path, "r") as f:
                    data = json.load(f)
                    self.agent_id = data.get("agent_id")
                    # Assuming the first key is the signing key for now, or looking for a specific structure
                    # The mandate says: "Cache self.agent_id and self.signing_kid"
                    # We need to find the kid from the keys array.
                    keys = data.get("public_keys", [])
                    if not keys:
                         raise ConfigurationError("agent-card.json missing 'public_keys'.")
                    self.signing_kid = keys[0].get("kid")
                    
                    if not self.agent_id or not self.signing_kid:
                        raise ConfigurationError("agent-card.json missing 'agent_id' or 'public_keys[0].kid'.")
            except Exception as e:
                raise ConfigurationError(f"Failed to load agent-card.json: {e}")
        elif self.dev_mode:
            # Generate minimal card
            logger.info("Dev Mode: Generating minimal agent-card.json")
            self.agent_id = "local-dev-agent"
            self.signing_kid = "local-dev-key"
            
            # We will populate the JWK part after generating the key in the next step
            # For now, just set the basics, we'll write the file after key gen
        else:
            raise ConfigurationError(f"agent-card.json not found at {self.project_root}")

    def _load_or_generate_keys(self):
        """Load private.pem or generate it in dev_mode."""
        if not self.keys_dir.exists():
            if self.dev_mode:
                self.keys_dir.mkdir(parents=True, exist_ok=True)
                self.trusted_dir.mkdir(parents=True, exist_ok=True)
            else:
                raise ConfigurationError(f"capiscio_keys directory not found at {self.keys_dir}")

        if self.private_key_path.exists():
            try:
                with open(self.private_key_path, "rb") as f:
                    self._private_key = serialization.load_pem_private_key(
                        f.read(), password=None
                    )
            except Exception as e:
                raise ConfigurationError(f"Failed to load private.pem: {e}")
        elif self.dev_mode:
            logger.info("Dev Mode: Generating Ed25519 keypair")
            self._private_key = ed25519.Ed25519PrivateKey.generate()
            
            # Save Private Key
            with open(self.private_key_path, "wb") as f:
                f.write(self._private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Save Public Key
            public_key = self._private_key.public_key()
            pem_public = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(self.public_key_path, "wb") as f:
                f.write(pem_public)
                
            # Now update agent-card.json with the JWK
            self._update_agent_card_with_jwk(public_key)
        else:
            raise ConfigurationError(f"private.pem not found at {self.private_key_path}")

    def _update_agent_card_with_jwk(self, public_key: ed25519.Ed25519PublicKey):
        """Helper to write the agent-card.json with the generated key."""
        # Convert Ed25519 public key to JWK parameters
        # Ed25519 keys are simple: x is the raw bytes
        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        x_b64 = base64.urlsafe_b64encode(raw_bytes).decode('utf-8').rstrip('=')
        
        jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x_b64,
            "kid": self.signing_kid,
            "use": "sig"
        }
        
        card_data = {
            "agent_id": self.agent_id,
            "public_keys": [jwk],
            "protocolVersion": "0.3.0",
            "name": "Local Dev Agent",
            "description": "Auto-generated by SimpleGuard",
            "url": "http://localhost:8000",
            "version": "0.1.0",
            "provider": {
                "organization": "Local Dev"
            }
        }
        
        with open(self.agent_card_path, "w") as f:
            json.dump(card_data, f, indent=2)
        logger.info(f"Created agent-card.json at {self.agent_card_path}")

    def _setup_trust_store(self):
        """Ensure trust store exists and add self-trust in dev_mode."""
        if not self.trusted_dir.exists() and self.dev_mode:
            self.trusted_dir.mkdir(parents=True, exist_ok=True)
            
        if self.dev_mode:
            # Self-Trust: Copy public.pem to trusted/{kid}.pem
            self_trust_path = self.trusted_dir / f"{self.signing_kid}.pem"
            if not self_trust_path.exists() and self.public_key_path.exists():
                import shutil
                shutil.copy(self.public_key_path, self_trust_path)
                logger.info(f"Dev Mode: Added self-trust for kid {self.signing_kid}")
