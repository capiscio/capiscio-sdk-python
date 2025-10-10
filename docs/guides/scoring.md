# Scoring Guide: Compliance, Trust, Availability

CapiscIO A2A Security uses a **three-dimensional scoring system** to provide deep insight into agent quality, security, and operational readiness.

## Why Three Dimensions?

**The Problem with Single Scores:**

Imagine you get a score of `75` for an agent. What does that mean?
- Is it compliant with the protocol but untrusted?
- Is it trusted but often unavailable?
- Is it a security risk or just poorly configured?

**You can't tell. And you can't make smart decisions.**

**Real-World Scenario:**

You're building a payment processing agent. You discover two potential partner agents:

- **Agent A**: Compliance: 95, Trust: 45, Availability: 90
  - *Translation:* Perfectly follows the protocol, always up, but no signature verification, missing provider info. **Don't use for payments.**

- **Agent B**: Compliance: 80, Trust: 95, Availability: 80  
  - *Translation:* Minor protocol quirks, occasionally slow, but fully signed, verified provider, excellent security. **Good for payments.**

**Single score would say they're both ~75. Three dimensions tell you the REAL story.**

---

## Overview

Every validation returns a `ValidationResult` with three score dimensions:

- **Compliance (0-100):** Protocol specification adherence
- **Trust (0-100):** Security and authenticity signals
- **Availability (0-100):** Operational readiness (optional)

Each dimension has its own breakdown and rating enum.

## Example

```python
result = await agent.validate_agent_card(card_url)
print(result.compliance.total)      # 0-100
print(result.trust.total)           # 0-100
print(result.availability.total)    # 0-100 or None
print(result.compliance.rating)     # ComplianceRating enum
print(result.trust.rating)          # TrustRating enum
print(result.availability.rating)   # AvailabilityRating enum
```

## Dimension Details

### Compliance
- **Measures:** Protocol adherence, required fields, format validation
- **Breakdown:**
  - Core fields (60 pts)
  - Skills quality (20 pts)
  - Format compliance (15 pts)
  - Data quality (5 pts)
- **Rating Enum:** Perfect, Excellent, Good, Fair, Poor

### Trust
- **Measures:** Security, signatures, provider info, documentation
- **Breakdown:**
  - Signatures (40 pts, confidence multiplier)
  - Provider (25 pts)
  - Security config (20 pts)
  - Documentation (15 pts)
- **Rating Enum:** Highly Trusted, Trusted, Untrusted

### Availability
- **Measures:** Endpoint health, transport support, response quality
- **Breakdown:**
  - Primary endpoint (50 pts)
  - Transport support (30 pts)
  - Response quality (20 pts)
- **Rating Enum:** Fully Available, Available, Unavailable

## Migration Guide

- **Old:** `result.score` (deprecated)
- **New:** `result.compliance.total`, `result.trust.total`, `result.availability.total`

**Example:**
```python
# Old
if result.score >= 80:
    deploy_agent()

# New
if result.compliance.total >= 90 and result.trust.total >= 80:
    deploy_agent()
```

## Decision Examples

### Production Deployment Decisions

**Scenario: Should I call this agent in production?**

```python
result = await agent.validate_agent_card(candidate_url)

# Financial transactions: Require high trust AND compliance
if result.trust.rating == TrustRating.HIGHLY_TRUSTED and \
   result.compliance.total >= 90:
    await process_payment(candidate_url)
else:
    log_rejection(candidate_url, "Insufficient trust/compliance for payments")

# Data sync: Prioritize availability
if result.availability.rating == AvailabilityRating.FULLY_AVAILABLE:
    await sync_data(candidate_url)
else:
    schedule_retry(candidate_url)

# Public API calls: Block low compliance
if result.compliance.rating == ComplianceRating.POOR:
    block_agent(candidate_url)
    alert_security_team(result.issues)
```

### Monitoring and Alerting

**Scenario: What should trigger alerts?**

```python
result = await agent.validate_agent_card(partner_url)

# Alert on trust degradation
if result.trust.total < 70:
    alert("Partner agent trust score dropped", severity="HIGH")
    # Possible causes: expired signatures, provider changes
    
# Alert on availability issues  
if result.availability.rating == AvailabilityRating.UNAVAILABLE:
    alert("Partner agent unreachable", severity="MEDIUM")
    failover_to_backup()

# Log compliance warnings
if result.compliance.total < 80:
    log_warning("Partner agent has protocol compliance issues", result.issues)
```

### Progressive Rollout

**Scenario: Gradually tightening security**

```python
# Week 1: Monitor mode - collect data
config.fail_mode = "monitor"
# All agents allowed, score patterns observed

# Week 2: Block poor compliance
if result.compliance.rating == ComplianceRating.POOR:
    reject_request()
    
# Week 3: Require minimum trust
if result.trust.total < 70:
    reject_request()
    
# Week 4: Full strict mode
config = SecurityConfig.strict()
```

### Agent Discovery and Selection

**Scenario: Choosing between multiple agents**

```python
candidates = [
    await validate_agent_card(url) for url in discovered_agents
]

# Rank by combined score (weighted by your priorities)
def score_for_use_case(result):
    return (
        result.trust.total * 0.5 +           # Trust matters most
        result.compliance.total * 0.3 +      # Compliance important
        (result.availability.total or 0) * 0.2  # Availability nice-to-have
    )

best_agent = max(candidates, key=score_for_use_case)
```

## Real-World Use Cases by Dimension

### When Compliance Matters Most

- **Protocol testing tools**: Need agents that perfectly follow specs
- **Compliance auditing**: Verifying agent implementations
- **Interoperability testing**: Ensuring cross-vendor compatibility

### When Trust Matters Most

- **Financial transactions**: Payment processing, invoicing
- **Identity verification**: KYC, authentication
- **Sensitive data handling**: PII, health records, legal documents

### When Availability Matters Most

- **Real-time systems**: Chat, live updates, streaming
- **Critical path operations**: Task dependencies, workflows
- **High-volume APIs**: Data sync, batch processing

## When to Use Each Dimension

- **Compliance:** For protocol correctness, spec adherence, format validation
- **Trust:** For security, authenticity, cryptographic verification
- **Availability:** For operational readiness, endpoint health, transport support

## Rating Thresholds

- **Compliance:**
  - Perfect: 100
  - Excellent: 90+
  - Good: 80+
  - Fair: 60+
  - Poor: <60
- **Trust:**
  - Highly Trusted: 90+
  - Trusted: 70+
  - Untrusted: <70
- **Availability:**
  - Fully Available: 90+
  - Available: 70+
  - Unavailable: <70

## FAQ

**Q: Is the legacy `score` property still available?**
A: Yes, but it returns `compliance.total` and is deprecated. Use the new dimensions for all new code.

**Q: How do I access breakdowns?**
A: Each dimension has a `.breakdown` property with detailed scoring info.

**Q: How do I migrate my tests?**
A: Change `result.score` to `result.compliance.total`, `result.trust.total`, or `result.availability.total` as appropriate.

---

For more details, see the [core concepts](../getting-started/concepts.md) and [quickstart](../getting-started/quickstart.md).
