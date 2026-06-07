# CIS Microsoft 365 Foundations Benchmark — Section 1 (Microsoft Entra)
#
# Evaluates the facts emitted by aac.m365.m365_identity_facts.
#
# Input shape:
#   {
#     "security_defaults_enabled": bool,
#     "global_admins": [
#       {"id": "...", "display_name": "...", "has_strong_mfa": bool, "mfa_methods": [...]}
#     ],
#     "conditional_access_policies": [
#       {"id": "...", "display_name": "...", "state": "enabled|...|disabled",
#        "conditions": {...}, "grant_controls": {...}}
#     ],
#     "user_mfa_methods": [...],
#     "pim_role_assignments": [...],
#     "pim_available": bool
#   }

package cis_m365.identity

import rego.v1

default compliant := false

# ── 1.1.1 — Security Defaults disabled when Conditional Access in use ──
#
# CIS prefers Conditional Access over Security Defaults for any tenant
# with the Entra P1+ licensing required for CA. If SD is on AND no CA
# policies exist, that's actually fine; if BOTH are on, the SD layer
# can mask CA effectiveness — flag it.

has_active_ca_policies if {
    some p in input.conditional_access_policies
    p.state == "enabled"
}

violation_1_1_1 contains msg if {
    input.security_defaults_enabled == true
    has_active_ca_policies
    msg := "CIS 1.1.1: Security Defaults is enabled AND active Conditional Access policies exist; disable Security Defaults to let CA take effect"
}

# ── 1.1.2 — Two-to-four Global Administrators designated ────────────────

violation_1_1_2 contains msg if {
    count(input.global_admins) < 2
    msg := sprintf("CIS 1.1.2: Only %d Global Administrator(s); CIS requires at least 2 for redundancy", [count(input.global_admins)])
}

violation_1_1_2 contains msg if {
    count(input.global_admins) > 4
    msg := sprintf("CIS 1.1.2: %d Global Administrators is too many; CIS requires no more than 4 to limit blast radius", [count(input.global_admins)])
}

# ── 1.1.3 — All Global Administrators have strong MFA ─────────────────

global_admins_without_strong_mfa contains admin if {
    some admin in input.global_admins
    admin.has_strong_mfa == false
}

violation_1_1_3 contains msg if {
    some admin in global_admins_without_strong_mfa
    msg := sprintf("CIS 1.1.3: Global Administrator %q lacks a strong MFA method", [admin.display_name])
}

# ── 1.1.4 — User MFA enforced via Conditional Access ─────────────────

# A "good" enforcement is at least one ENABLED policy whose grantControls
# require MFA. The conditions vary — the test is whether MFA is actually
# being demanded somewhere.

ca_policy_requires_mfa(p) if {
    p.state == "enabled"
    some control in p.grant_controls.builtInControls
    control == "mfa"
}

violation_1_1_4 contains msg if {
    not any_ca_enforces_mfa
    msg := "CIS 1.1.4: No enabled Conditional Access policy requires MFA; user MFA is not enforced"
}

any_ca_enforces_mfa if {
    some p in input.conditional_access_policies
    ca_policy_requires_mfa(p)
}

# ── 1.1.5 — Privileged Identity Management configured ────────────────

violation_1_1_5 contains msg if {
    input.pim_available == false
    msg := "CIS 1.1.5: Privileged Identity Management not detected; eligible-not-assigned roles aren't being used to limit standing privilege"
}

# ── Roll-up ─────────────────────────────────────────────────────────

violations contains v if { some v in violation_1_1_1 }
violations contains v if { some v in violation_1_1_2 }
violations contains v if { some v in violation_1_1_3 }
violations contains v if { some v in violation_1_1_4 }
violations contains v if { some v in violation_1_1_5 }

compliant if { count(violations) == 0 }

compliance_report := {
    "section": "1",
    "name": "Microsoft Entra (Identity)",
    "controls_evaluated": 5,
    "violations": violations,
    "violation_count": count(violations),
    "compliant": compliant,
}
