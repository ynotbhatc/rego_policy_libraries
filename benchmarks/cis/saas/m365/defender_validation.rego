# CIS Microsoft 365 Foundations Benchmark — Section 2 (Microsoft Defender)
#
# Evaluates the facts emitted by aac.m365.m365_defender_facts.
# Reads the Secure Score control implementation_status as the
# primary evidence — every Defender for O365 setting Microsoft
# considers a security baseline is represented there.

package cis_m365.defender

import rego.v1

default compliant := false


# Helper — was a Secure Score control marked Implemented?
control_implemented(control_id) if {
    input.controls_by_id[control_id] == "Implemented"
}

# Reusable violation factory. Each rule below names the control id
# Microsoft uses internally and the CIS clause that depends on it.

violation_2_1_1 contains msg if {
    not control_implemented("ATPSafeAttachments")
    msg := "CIS 2.1.1: Safe Attachments policy not implemented; malware reaches inboxes before sandbox detonation"
}

violation_2_1_2 contains msg if {
    not control_implemented("ATPSafeLinks")
    msg := "CIS 2.1.2: Safe Links policy not implemented; users can click time-of-click malicious URLs"
}

violation_2_1_3 contains msg if {
    not control_implemented("AntiPhishPolicy")
    msg := "CIS 2.1.3: anti-phishing baseline policy not implemented"
}

violation_2_1_4 contains msg if {
    not control_implemented("MailboxIntelligence")
    msg := "CIS 2.1.4: mailbox intelligence (impersonation protection) not implemented"
}

violation_2_1_5 contains msg if {
    not control_implemented("ZeroHourAutoPurge")
    msg := "CIS 2.1.5: zero-hour auto-purge for malware/phish not implemented; post-delivery cleanup unavailable"
}

violation_2_1_7 contains msg if {
    not control_implemented("CommonAttachmentTypesFiltered")
    msg := "CIS 2.1.7: common attachment types (.exe, .bat, ...) not filtered"
}

violation_2_1_8 contains msg if {
    not control_implemented("AntiMalwarePolicy")
    msg := "CIS 2.1.8: anti-malware baseline policy not implemented"
}


violations contains v if { some v in violation_2_1_1 }
violations contains v if { some v in violation_2_1_2 }
violations contains v if { some v in violation_2_1_3 }
violations contains v if { some v in violation_2_1_4 }
violations contains v if { some v in violation_2_1_5 }
violations contains v if { some v in violation_2_1_7 }
violations contains v if { some v in violation_2_1_8 }

compliant if { count(violations) == 0 }

compliance_report := {
    "section": "2",
    "name": "Microsoft Defender",
    "controls_evaluated": 7,
    "violations": violations,
    "violation_count": count(violations),
    "compliant": compliant,
}
