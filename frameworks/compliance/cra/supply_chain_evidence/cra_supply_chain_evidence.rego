package cra.supply_chain_evidence

import rego.v1
import data.supply_chain.slsa

# CRA — Supply-chain evidence integration.
#
# Re-uses findings from the SLSA supply-chain governance module
# (data.supply_chain.slsa) and re-frames them as CRA Annex I/II + Art.13
# violations. This avoids redefining SBOM / signing / provenance rules
# in CRA-native form; instead it consumes the SLSA evidence the
# organisation is already producing and emits CRA-language findings
# alongside SLSA's own output.
#
# Input shape: the SAME input the supply_chain.slsa module consumes
# (artifact metadata, provenance attestation, SBOM, dependencies,
# licenses, signing). This module performs no input reads of its
# own — only translation of upstream findings.

default compliant := false

# Helper — predicate over SLSA's violation set
slsa_finding(substr) if {
    some v in slsa.violations
    contains(v, substr)
}

# ── SBOM mapping (CRA Annex II.1 — Vulnerability handling: SBOM) ─────────

violation contains msg if {
    slsa_finding("SBOM: No SBOM attached")
    msg := "CRA Annex II.1(a) (via SLSA): No SBOM attached to the artifact — vulnerability handling cannot be effective without an inventory of components"
}

violation contains msg if {
    slsa_finding("SBOM: SBOM format not recognized")
    msg := "CRA Annex II.1(b) (via SLSA): SBOM not in a machine-readable format (SPDX-2.x or CycloneDX-1.x required)"
}

violation contains msg if {
    slsa_finding("SBOM components missing PURL")
    msg := "CRA Annex II.1(c) (via SLSA): SBOM components missing PURL (Package URL) identifiers — top-level dependencies not unambiguously documented"
}

violation contains msg if {
    slsa_finding("SBOM components missing license")
    msg := "CRA Annex II.1(c) (via SLSA): SBOM components missing license declarations — required for traceability of third-party components per Art.13(6)"
}

violation contains msg if {
    slsa_finding("SBOM contains no components")
    msg := "CRA Annex II.1(a) (via SLSA): SBOM exists but is empty — equivalent to no SBOM for CRA purposes"
}

# ── Integrity mapping (CRA Annex I.6 — code/configuration integrity) ─────

violation contains msg if {
    slsa_finding("Signing: Artifact is not signed")
    msg := "CRA Annex I.6(a) (via SLSA): Artifact is not signed — integrity of distributed code cannot be cryptographically verified"
}

violation contains msg if {
    slsa_finding("Signing: Artifact signature verification failed")
    msg := "CRA Annex I.6(a) (via SLSA): Artifact signature verification failed — distributed artifact integrity is broken"
}

violation contains msg if {
    slsa_finding("Signing: Signing identity not from an approved OIDC provider")
    msg := "CRA Annex I.6(b) (via SLSA): Signing identity not from an approved OIDC provider — tamper detection chain of trust is weakened"
}

# ── Third-party component due diligence (CRA Art.13(6)) ─────────────────

violation contains msg if {
    slsa_finding("Dependencies:")
    slsa_finding("known CVE")
    msg := "CRA Art.13(6) (via SLSA): Third-party component has a known CVE — manufacturer's vulnerability monitoring obligation triggered"
}

violation contains msg if {
    slsa_finding("Dependencies:")
    slsa_finding("critical CVE with no exemption")
    msg := "CRA Art.13(6) + Annex II.2 (via SLSA): Critical CVE in third-party component with no documented exemption — remediation process obligation triggered"
}

violation contains msg if {
    slsa_finding("Dependencies: Floating version constraint")
    msg := "CRA Art.13(6) (via SLSA): Floating version constraint in dependencies — third-party component due diligence requires reproducible builds"
}

# ── Provenance mapping (CRA Art.28 + Annex VII technical documentation) ──

violation contains msg if {
    slsa_finding("SLSA: Build provenance attestation is missing")
    msg := "CRA Annex VII.3 (via SLSA): Build provenance attestation missing — technical documentation requires evidence of how the artifact was built"
}

violation contains msg if {
    slsa_finding("Provenance: Build source URI does not match")
    msg := "CRA Annex VII.3 (via SLSA): Build provenance source URI does not match the expected repository — traceability of the technical documentation chain is broken"
}

# ── Substantial-modification interaction (CRA Art.11) ───────────────────

# If the substantial_modification module declared an SBOM change, the SLSA
# module must show the SBOM was refreshed afterwards.
violation contains msg if {
    input.substantial_modification.changes.sbom_changed
    slsa_finding("SBOM:")
    msg := "CRA Art.11 (via SLSA): A substantial-modification SBOM change was declared, but SLSA still reports SBOM defects — refresh did not produce a clean inventory"
}

# ── Compliance + report ─────────────────────────────────────────────────

compliant if { count(violation) == 0 }

# Convenience accessors for callers that want both views
slsa_violations := slsa.violations
slsa_compliant := slsa.compliant

compliance_report := {
    "family": "Supply-chain evidence integration",
    "name":   "CRA × SLSA findings bridge",
    "controls_evaluated": 14,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
    "upstream": {
        "module": "data.supply_chain.slsa",
        "slsa_violation_count": count(slsa.violations),
        "slsa_compliant": slsa.compliant,
    },
}
