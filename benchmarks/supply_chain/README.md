# Software Supply-Chain — spine substrate + framework mappings

A scaffold that expresses the major software-supply-chain frameworks in Rego on a
**shared control substrate**, so that:

- **one assessment** (the `baseline`) checks the invariant supply-chain controls — the
  "default check" any supply-chain effort runs;
- each framework (`slsa`, `ssdf`, …) **maps its requirements to the substrate** rather
  than re-implementing logic — so the count of shared substrate rules referenced across
  the frameworks is the **empirical measure of the collapse** (the supply-chain analogue
  of "2,767 STIG rules → 65 controls");
- an artifact's **spine footprint** drives an evaluation-depth triage (`coverage`).

Vendor-neutral: SLSA and SSDF are public standards; nothing here is AAC-specific.

## Layout

```
_substrate/     the 7 invariant control themes (SR/SA/CM anchors + centrality weights)
baseline/       the default check — the supply-chain spine (compliance_report)
slsa/           SLSA v1.0 build track            -> substrate
ssdf/           NIST SSDF (SP 800-218)           -> substrate
ssdf_genai/     NIST SSDF for GenAI (SP 800-218A)-> substrate + AI-contribution attestation
scrm_800_161/   NIST SP 800-161r1 (C-SCRM)       -> substrate
s2c2f/          OpenSSF S2C2F (consumption)      -> substrate
coverage/       spine-footprint -> evaluation-depth triage
metrics/        the collapse, measured (framework references vs distinct themes)
tests/          opa test — incl. the collapse tests
```

**The collapse, measured** (`data.supply_chain.metrics.collapse_report`): **5 frameworks → 20
framework-to-theme references collapsing onto 7 distinct themes.** That ratio is the supply-chain
analogue of the original spine's "2,767 rules → 65 controls".

## The seven invariant themes

| Theme | 800-53 anchor | Note |
|---|---|---|
| Component inventory / SBOM | SR-3, SR-4 | |
| Build provenance / attestation | SR-4, SA-15 | |
| Artifact & source integrity / signing | SR-11, SI-7 | |
| Source & change control | **CM-5**, CM-3 | shared "CM seam" with the OS-hardening spine |
| Dependency trust & vetting | SR-3, SR-5, SR-6 | |
| Vulnerability management | RA-5, SR-6 | |
| Build-environment hardening | **CM-6, CM-7** | shared "CM seam" |

## Input contract (supply-chain facts)

Fail-closed: any missing/unshaped fact reports its control unsatisfied.

```json
{
  "sbom":            { "present": true, "format": "cyclonedx", "components": [ ... ] },
  "provenance":      { "present": true, "signed": true, "slsa_build_level": 3, "builder": "hosted" },
  "signing":         { "artifacts_signed": true, "method": "cosign" },
  "source":          { "branch_protection": true, "required_reviews": 1, "code_owner_review": true, "signed_commits": true },
  "dependencies":    { "pinned": true, "vetted": true, "unresolved_purls": 0 },
  "vulnerabilities": { "kev_hits": 0, "osv_hits": 0, "unaddressed": 0 },
  "build":           { "hardened": true, "isolated": true, "ephemeral": true },
  "artifact":        { "name": "authlib", "capabilities": ["auth","crypto","config"] }   // for coverage/
}
```

## Run

```bash
opa test benchmarks/supply_chain/ -v
opa eval -d benchmarks/supply_chain -I 'data.supply_chain.baseline.compliance_report' < fixtures/sample_input.json
opa eval -d benchmarks/supply_chain -I 'data.supply_chain.coverage.report' < fixtures/sample_input.json
```

## Status — scaffold / proof

Five frameworks mapped (SLSA, SSDF, SSDF-GenAI, 800-161, S2C2F) + the baseline + the coverage
triage + the collapse metric. Follow-ons: fuller per-requirement mappings, and the supply-chain
**facts collectors** (SBOM, provenance/attestation, repo-governance, KEV/OSV) that produce the
input contract above.
