# Using Scoring in Python

> **Learn how to use the three-dimensional scoring system in A2A Security** - For the full scoring system reference, see the [**Scoring System Concepts**](https://docs.capisc.io/concepts/scoring/)

## Quick Overview

A2A Security uses a three-dimensional scoring system to evaluate agent cards:

- **📄 Compliance (0-100)** - Protocol adherence and format validation
- **🔐 Trust (0-100)** - Security practices and cryptographic verification  
- **🚀 Availability (0-100)** - Operational readiness *(optional with live testing)*

!!! tip "Complete Scoring Details"
    This page focuses on **Python usage**. For the complete scoring system explanation, breakdowns, and calculations, see the [**Scoring System Concepts**](https://docs.capisc.io/concepts/scoring/).

---

## Basic Usage

### Accessing Scores

```python
from capiscio_sdk import secure, SecurityConfig

# Wrap your agent with security
agent = secure(MyAgentExecutor(), SecurityConfig.production())

# Validate an agent card
result = await agent.validate_agent_card("https://partner.example.com")

# Access the three score dimensions
print(f"Compliance: {result.compliance.total}/100")  
print(f"Trust: {result.trust.total}/100")
print(f"Availability: {result.availability.total or 'Not tested'}")

# Use rating enums for decisions
from capiscio_sdk.types import TrustRating, ComplianceRating

if result.trust.rating == TrustRating.HIGHLY_TRUSTED:
    print("✅ Cryptographically verified agent")
elif result.trust.rating == TrustRating.TRUSTED:
    print("✅ Good security practices")
else:
    print("⚠️  Unverified agent - use with caution")
```

### Accessing Detailed Breakdowns

```python
# Compliance breakdown
print(f"Core fields: {result.compliance.breakdown.core_fields.score}/60")
print(f"Skills quality: {result.compliance.breakdown.skills_quality.score}/20")
print(f"Format: {result.compliance.breakdown.format_compliance.score}/15")
print(f"Data quality: {result.compliance.breakdown.data_quality.score}/5")

# Trust breakdown  
print(f"Signatures: {result.trust.breakdown.signatures.score}/40")
print(f"Provider: {result.trust.breakdown.provider.score}/25")
print(f"Security: {result.trust.breakdown.security.score}/20")
print(f"Documentation: {result.trust.breakdown.documentation.score}/15")
print(f"Confidence multiplier: {result.trust.confidence_multiplier}x")

# Availability breakdown (if tested)
if result.availability.total is not None:
    print(f"Primary endpoint: {result.availability.breakdown.primary_endpoint.score}/50")
    print(f"Transport support: {result.availability.breakdown.transport_support.score}/30")
    print(f"Response quality: {result.availability.breakdown.response_quality.score}/20")
```

---

## Production Decision Patterns

### Pattern 1: Financial Transactions

Require high trust AND compliance for sensitive operations:

```python
async def should_process_payment(partner_url: str) -> bool:
    """Determine if an agent is trustworthy enough for payments."""
    result = await agent.validate_agent_card(partner_url)
    
    # Financial transactions need BOTH high trust and compliance
    if result.trust.rating == TrustRating.HIGHLY_TRUSTED and \
       result.compliance.total >= 90:
        return True
    
    # Log why we rejected
    if result.trust.rating != TrustRating.HIGHLY_TRUSTED:
        log.warning(f"Partner {partner_url} lacks signature verification")
    if result.compliance.total < 90:
        log.warning(f"Partner {partner_url} has compliance issues: {result.issues}")
    
    return False
```

### Pattern 2: Monitoring and Alerting

Alert on score degradation:

```python
async def monitor_partner_health(partner_url: str):
    """Monitor partner agent health and alert on issues."""
    result = await agent.validate_agent_card(partner_url)
    
    # Alert on trust degradation
    if result.trust.total < 70:
        alert(
            "Partner trust score dropped",
            severity="HIGH",
            details={
                "partner": partner_url,
                "trust_score": result.trust.total,
                "issues": result.issues
            }
        )
        # Possible causes: expired signatures, provider changes
    
    # Alert on availability issues  
    if result.availability and result.availability.rating == AvailabilityRating.UNAVAILABLE:
        alert(
            "Partner unreachable",
            severity="MEDIUM",
            details={"partner": partner_url}
        )
        await failover_to_backup(partner_url)
    
    # Log compliance warnings
    if result.compliance.total < 80:
        log.warning(
            f"Partner {partner_url} has protocol compliance issues",
            extra={"issues": result.issues}
        )
```

### Pattern 3: Progressive Rollout

Gradually tighten security requirements:

```python
class SecurityPolicy:
    """Progressive security policy enforcement."""
    
    def __init__(self, phase: int):
        self.phase = phase
    
    async def should_allow(self, result: ValidationResult) -> tuple[bool, str]:
        """Check if agent meets current phase requirements."""
        
        if self.phase == 1:
            # Phase 1: Monitor only - collect data
            return True, "monitoring"
        
        elif self.phase == 2:
            # Phase 2: Block poor compliance
            if result.compliance.rating == ComplianceRating.POOR:
                return False, "poor_compliance"
            return True, "allowed"
        
        elif self.phase == 3:
            # Phase 3: Require minimum trust
            if result.trust.total < 70:
                return False, "insufficient_trust"
            return True, "allowed"
        
        else:  # Phase 4+
            # Phase 4: Full strict mode
            if result.compliance.total < 95 or result.trust.total < 80:
                return False, "strict_mode"
            return True, "allowed"

# Usage
policy = SecurityPolicy(phase=2)
result = await agent.validate_agent_card(partner_url)
allowed, reason = await policy.should_allow(result)

if not allowed:
    raise SecurityError(f"Agent rejected: {reason}")
```

### Pattern 4: Agent Selection

Choose the best agent from multiple candidates:

```python
async def select_best_agent(
    candidate_urls: list[str],
    use_case: str = "general"
) -> str:
    """Select the best agent for a specific use case."""
    
    # Validate all candidates
    results = await asyncio.gather(*[
        agent.validate_agent_card(url)
        for url in candidate_urls
    ])
    
    # Define use-case-specific scoring functions
    def score_for_payments(result: ValidationResult) -> float:
        return (
            result.trust.total * 0.5 +           # Trust matters most
            result.compliance.total * 0.3 +      # Compliance important
            (result.availability.total or 0) * 0.2  # Availability nice-to-have
        )
    
    def score_for_realtime(result: ValidationResult) -> float:
        return (
            (result.availability.total or 0) * 0.5 +  # Availability critical
            result.compliance.total * 0.3 +           # Compliance matters
            result.trust.total * 0.2                  # Trust nice-to-have
        )
    
    # Choose scoring function based on use case
    scorer = {
        "payments": score_for_payments,
        "realtime": score_for_realtime,
        "general": lambda r: (r.compliance.total + r.trust.total) / 2
    }.get(use_case, lambda r: r.compliance.total)
    
    # Find best candidate
    best_result = max(results, key=scorer)
    best_idx = results.index(best_result)
    
    log.info(
        f"Selected {candidate_urls[best_idx]} "
        f"(compliance: {best_result.compliance.total}, "
        f"trust: {best_result.trust.total})"
    )
    
    return candidate_urls[best_idx]
```

---

## Configuration Impact on Scoring

Different security configurations affect what gets scored:

```python
# Development: Permissive scoring
config = SecurityConfig.development()
# - Signature verification: optional
# - Rate limiting: disabled
# - Trust scores may be lower but still pass validation

# Production: Balanced scoring  
config = SecurityConfig.production()
# - Signature verification: optional but encouraged
# - Rate limiting: enabled
# - Trust scores reflect actual security posture

# Strict: Maximum security
config = SecurityConfig.strict()
# - Signature verification: REQUIRED
# - Agents without signatures fail validation
# - Only highly trusted agents pass
```

---

## Migration from Legacy Single Score

If you're upgrading from an older version:

### Old API (Deprecated)

```python
result = await agent.validate_agent_card(partner_url)

# Deprecated: Single score
if result.score >= 80:
    await call_partner(partner_url)
```

### New API (Recommended)

```python
result = await agent.validate_agent_card(partner_url)

# New: Three-dimensional - be specific about what matters
if result.compliance.total >= 90 and result.trust.total >= 80:
    await call_partner(partner_url)
```

The old `result.score` property still exists but returns `compliance.total` and is deprecated. Migrate to three-dimensional scoring for better decision-making.

---

## Type Definitions

For type hints and IDE support:

```python
from capiscio_sdk.types import (
    ValidationResult,
    ComplianceScore,
    TrustScore,
    AvailabilityScore,
    ComplianceRating,
    TrustRating,
    AvailabilityRating,
)

async def evaluate_agent(url: str) -> ValidationResult:
    """Evaluate an agent card and return detailed scores."""
    return await agent.validate_agent_card(url)

def is_production_ready(result: ValidationResult) -> bool:
    """Check if agent meets production thresholds."""
    return (
        result.compliance.total >= 95 and
        result.trust.total >= 60 and
        (result.availability.total is None or result.availability.total >= 80)
    )
```

---

## See Also

<div class="grid cards" markdown>

-   **📚 Unified Scoring Guide**

    ---

    Complete scoring system reference with all breakdowns, calculations, and rating thresholds.

    [:octicons-arrow-right-24: View Complete Guide](https://docs.capisc.io/concepts/scoring/)

-   **🔧 CapiscIO CLI Scoring**

    ---

    Command-line usage with `--detailed-scores` flag and JSON output.

    [:octicons-arrow-right-24: CLI Usage](https://docs.capisc.io/reference/cli/#validate)

-   **📖 Core Concepts**

    ---

    Understand the validation architecture and security model.

    [:octicons-arrow-right-24: Learn Concepts](../getting-started/concepts.md)

-   **⚡ Quick Start**

    ---

    Get started with A2A Security in 5 minutes.

    [:octicons-arrow-right-24: Quick Start](../getting-started/quickstart.md)

</div>

---

**For complete scoring details**, see the [**Scoring System Concepts**](https://docs.capisc.io/concepts/scoring/).
