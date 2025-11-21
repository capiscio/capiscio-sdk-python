"""Signature verification for A2A protocol."""
import logging
from typing import Any, Dict, List, Optional

from ..types import ValidationResult, ValidationIssue, ValidationSeverity, create_simple_validation_result

logger = logging.getLogger(__name__)


class SignatureValidator:
    """Validates JWS signatures on A2A messages and agent cards."""

    def __init__(self) -> None:
        """Initialize signature validator."""
        self._crypto_available = self._check_crypto_availability()

    def _check_crypto_availability(self) -> bool:
        """Check if cryptography library is available."""
        try:
            import jwt  # PyJWT for JWS validation  # noqa: F401
            return True
        except ImportError:
            logger.warning(
                "PyJWT not installed. Signature verification will be limited. "
                "Install with: pip install pyjwt cryptography"
            )
            return False

    def validate_signature(
        self, 
        payload: Dict[str, Any], 
        signature: str,
        public_key: Optional[str] = None,
    ) -> ValidationResult:
        """
        Validate a JWS signature.

        Args:
            payload: The data that was signed
            signature: The JWS signature to verify
            public_key: Optional public key for verification

        Returns:
            ValidationResult with signature validation results
        """
        issues: List[ValidationIssue] = []
        score = 100

        if not self._crypto_available:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="CRYPTO_NOT_AVAILABLE",
                    message="Cryptography library not available for signature verification",
                    path="signatures",
                )
            )
            return create_simple_validation_result(
                success=False,
                issues=issues,
                simple_score=0,
                dimension="trust"
            )

        # Check signature format
        if not signature or not isinstance(signature, str):
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="INVALID_SIGNATURE_FORMAT",
                    message="Signature must be a non-empty string",
                    path="signatures",
                )
            )
            return create_simple_validation_result(
                success=False,
                issues=issues,
                simple_score=0,
                dimension="trust"
            )

        # JWS signatures should have 3 parts separated by dots
        parts = signature.split('.')
        if len(parts) != 3:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="INVALID_JWS_FORMAT",
                    message=f"JWS signature must have 3 parts (header.payload.signature), found {len(parts)}",
                    path="signatures",
                )
            )
            score -= 50

        # Attempt verification if public key provided
        if public_key:
            try:
                import jwt
                
                # Verify signature
                jwt.decode(
                    signature,
                    public_key,
                    algorithms=['RS256', 'ES256', 'PS256'],
                    options={"verify_signature": True}
                )
                
                # Signature is valid
                logger.debug("Signature verified successfully")
                
            except jwt.InvalidSignatureError:
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        code="SIGNATURE_VERIFICATION_FAILED",
                        message="Signature verification failed - signature is invalid",
                        path="signatures",
                    )
                )
                score = 0
                
            except jwt.ExpiredSignatureError:
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        code="SIGNATURE_EXPIRED",
                        message="Signature has expired",
                        path="signatures",
                    )
                )
                score -= 40
                
            except jwt.DecodeError as e:
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        code="SIGNATURE_DECODE_ERROR",
                        message=f"Failed to decode signature: {str(e)}",
                        path="signatures",
                    )
                )
                score -= 30
                
            except Exception as e:
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        code="SIGNATURE_VERIFICATION_ERROR",
                        message=f"Signature verification error: {str(e)}",
                        path="signatures",
                    )
                )
                score = 0
        else:
            # No public key provided - can't verify, just validate format
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="NO_PUBLIC_KEY",
                    message="Signature format valid but no public key provided for verification",
                    path="signatures",
                )
            )
            score = 70  # Format is OK but not verified

        # Ensure score doesn't go negative
        score = max(0, score)

        return create_simple_validation_result(
            success=score >= 60 and not any(i.severity == ValidationSeverity.ERROR for i in issues),
            issues=issues,
            simple_score=score,
            dimension="trust"
        )

    def validate_signatures(
        self,
        payload: Dict[str, Any],
        signatures: List[str],
    ) -> ValidationResult:
        """
        Validate multiple JWS signatures.

        Args:
            payload: The data that was signed
            signatures: List of JWS signatures to verify

        Returns:
            Aggregated ValidationResult
        """
        all_issues: List[ValidationIssue] = []
        total_score = 0
        valid_count = 0

        if not signatures or len(signatures) == 0:
            all_issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="NO_SIGNATURES",
                    message="No signatures found to validate",
                    path="signatures",
                )
            )
            return create_simple_validation_result(
                success=False,
                issues=all_issues,
                simple_score=50,
                dimension="trust"
            )

        for i, sig in enumerate(signatures):
            result = self.validate_signature(payload, sig)
            all_issues.extend(result.issues)
            # Use trust.total since signature validation is trust-related
            total_score += result.trust.total if result.trust else 0
            
            if result.success:
                valid_count += 1

        # Calculate average score
        avg_score = total_score // len(signatures) if signatures else 0

        result = create_simple_validation_result(
            success=valid_count > 0,
            issues=all_issues,
            simple_score=avg_score,
            dimension="trust"
        )
        result.metadata = {
            "total_signatures": len(signatures),
            "valid_signatures": valid_count,
            "failed_signatures": len(signatures) - valid_count,
        }
        return result
