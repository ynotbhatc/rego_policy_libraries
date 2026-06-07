# CIS Microsoft 365 Foundations Benchmark — Section 3 (Microsoft Purview)
#
# Evaluates the facts emitted by aac.m365.m365_purview_facts.

package cis_m365.purview

import rego.v1

default compliant := false


control_implemented(control_id) if {
    input.controls_by_id[control_id] == "Implemented"
}


# 3.1.1 — unified audit log enabled
violation_3_1_1 contains msg if {
    not control_implemented("UnifiedAuditLogEnabled")
    msg := "CIS 3.1.1: unified audit log not enabled; security events aren't being captured tenant-wide"
}

# Cross-reference: if the audit log isn't accessible via Graph,
# something more fundamental is wrong (or the app reg lacks scope).
violation_3_1_1 contains msg if {
    input.audit_log_accessible == false
    msg := "CIS 3.1.1: audit log endpoint not reachable; verify app registration scope and unified audit log state"
}

# 3.1.2 — audit log retention >= 1 year
violation_3_1_2 contains msg if {
    not control_implemented("AuditLogRetention")
    msg := "CIS 3.1.2: audit log retention < 1 year (Microsoft default 90 days for non-E5); enable extended retention"
}

# 3.2.1 — alerts for malicious emails
violation_3_2_1 contains msg if {
    not control_implemented("AlertsForMaliciousEmails")
    msg := "CIS 3.2.1: malicious-email alert policy not implemented"
}

# 3.3.1 — DLP policy exists
violation_3_3_1 contains msg if {
    not control_implemented("DLPPolicy")
    msg := "CIS 3.3.1: no Data Loss Prevention policy detected; sensitive data exfiltration is unmanaged"
}

# 3.4.1 — Customer Key (or equivalent BYOK) — Implemented expected for E5
violation_3_4_1 contains msg if {
    not control_implemented("CustomerKeyEncryption")
    msg := "CIS 3.4.1: Customer Key (BYOK) not implemented; tenant data is encrypted with Microsoft-managed keys only"
}

# 3.5.1 — Insider Risk policy active
violation_3_5_1 contains msg if {
    not control_implemented("InsiderRiskPolicy")
    msg := "CIS 3.5.1: Insider Risk Management policy not active"
}

# Cross-cutting evidence: eDiscovery presence shows Purview is in
# active use. Absence alone isn't a violation but worth surfacing
# as a soft signal so operators know if their Purview footprint
# is empty.
violation_evidence_purview_inactive contains msg if {
    input.ediscovery_cases_count == 0
    msg := "Purview inactive evidence: no eDiscovery cases configured; tenant may not be actively using Purview governance"
}


violations contains v if { some v in violation_3_1_1 }
violations contains v if { some v in violation_3_1_2 }
violations contains v if { some v in violation_3_2_1 }
violations contains v if { some v in violation_3_3_1 }
violations contains v if { some v in violation_3_4_1 }
violations contains v if { some v in violation_3_5_1 }

# Soft evidence is in its own list — the customer can choose
# whether to treat it as a violation for their purposes.
soft_findings contains s if { some s in violation_evidence_purview_inactive }

compliant if { count(violations) == 0 }

compliance_report := {
    "section": "3",
    "name": "Microsoft Purview",
    "controls_evaluated": 6,
    "violations": violations,
    "soft_findings": soft_findings,
    "violation_count": count(violations),
    "compliant": compliant,
}
