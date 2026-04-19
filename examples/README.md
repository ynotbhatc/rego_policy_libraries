# Examples

This directory contains sample input JSON documents that illustrate the expected
input shape for each major policy domain. Use them to:

- **Understand the input contract** before wiring a policy into your automation.
- **Test locally** with `opa eval`.
- **Validate** that a policy returns the output you expect.

---

## Quick-start

```bash
# Install OPA (v0.60+)
# https://www.openpolicyagent.org/docs/latest/#1-download-opa

# Evaluate a FedRAMP Moderate assessment against a sample compliant system
opa eval \
  --data frameworks/federal/fedramp/fedramp_main.rego \
  --input  examples/input/fedramp_moderate_compliant.json \
  'data.fedramp.fedramp_compliance_report'

# Evaluate a CIS RHEL 9 simplified check (quick subset)
opa eval \
  --data benchmarks/cis/os/linux/rhel_9_simple/cis_rhel9_test.rego \
  --input examples/input/rhel9_compliant.json \
  'data.cis.rhel9.test.summary'

# Evaluate AI governance decision
opa eval \
  --data governance/ai/ \
  --input examples/input/ai_governance_allow.json \
  'data.ai_governance.governance_response'
```

---

## Input files

| File | Policy package | Notes |
|------|---------------|-------|
| `rhel9_compliant.json` | `cis.rhel9.test` | Fully compliant CIS RHEL 9 system |
| `fedramp_moderate_compliant.json` | `fedramp` | Compliant FedRAMP Moderate cloud service |
| `ai_governance_allow.json` | `ai_governance` | AI agent requesting a read-only action |

---

## Output shape

Every policy module returns a structured report. Example (FedRAMP):

```json
{
  "standard": "FedRAMP",
  "impact_level": "moderate",
  "compliant": true,
  "compliance_score": 100,
  "total_violations": 0,
  "violations": [],
  "areas": {
    "authorization":           { "compliant": true, "violations": [] },
    "cryptography":            { "compliant": true, "violations": [] },
    "data_residency":          { "compliant": true, "violations": [] },
    "personnel_security":      { "compliant": true, "violations": [] },
    "continuous_monitoring":   { "compliant": true, "violations": [] },
    "third_party_assessment":  { "compliant": true, "violations": [] },
    "supply_chain":            { "compliant": true, "violations": [] }
  }
}
```
