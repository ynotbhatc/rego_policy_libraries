package digital_sovereignty.main

import rego.v1

import data.digital_sovereignty.ai_sovereignty
import data.digital_sovereignty.breach_notification_sovereignty
import data.digital_sovereignty.cryptographic_sovereignty
import data.digital_sovereignty.cyber_resilience_sovereignty
import data.digital_sovereignty.data_residency
import data.digital_sovereignty.dora_sovereignty
import data.digital_sovereignty.geopolitical_sovereignty
import data.digital_sovereignty.infrastructure_sovereignty
import data.digital_sovereignty.network_sovereignty
import data.digital_sovereignty.operational_sovereignty
import data.digital_sovereignty.software_sovereignty

# Digital Sovereignty — Aggregator
# Combines all sovereignty domains into a unified assessment.
#
# Applicable frameworks:
#   ENISA European Digital Sovereignty
#   GAIA-X Trust Framework
#   FedRAMP High / GovCloud (US)
#   BSI C5 (Germany)
#   NCSC Cloud Security Principles (UK)
#   IRAP Protected (Australia)
#   National data localisation laws (GDPR Chapter V, India DPDP, PDPA)

# =============================================================================
# DOMAIN COMPLIANCE STATUS
# =============================================================================

data_residency_compliant if { data_residency.compliant }
cryptographic_sovereignty_compliant if { cryptographic_sovereignty.compliant }
infrastructure_sovereignty_compliant if { infrastructure_sovereignty.compliant }
software_sovereignty_compliant if { software_sovereignty.compliant }
operational_sovereignty_compliant if { operational_sovereignty.compliant }
network_sovereignty_compliant if { network_sovereignty.compliant }
ai_sovereignty_compliant if { ai_sovereignty.compliant }
breach_notification_sovereignty_compliant if { breach_notification_sovereignty.compliant }
geopolitical_sovereignty_compliant if { geopolitical_sovereignty.compliant }
dora_sovereignty_compliant if { dora_sovereignty.compliant }
cyber_resilience_sovereignty_compliant if { cyber_resilience_sovereignty.compliant }

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default overall_compliant := false

overall_compliant if {
	data_residency_compliant
	cryptographic_sovereignty_compliant
	infrastructure_sovereignty_compliant
	software_sovereignty_compliant
	operational_sovereignty_compliant
	network_sovereignty_compliant
	ai_sovereignty_compliant
	breach_notification_sovereignty_compliant
	geopolitical_sovereignty_compliant
	dora_sovereignty_compliant
	cyber_resilience_sovereignty_compliant
}

# =============================================================================
# SCORING
# =============================================================================

domains_passing := count([d |
	domains := [
		data_residency_compliant,
		cryptographic_sovereignty_compliant,
		infrastructure_sovereignty_compliant,
		software_sovereignty_compliant,
		operational_sovereignty_compliant,
		network_sovereignty_compliant,
		ai_sovereignty_compliant,
		breach_notification_sovereignty_compliant,
		geopolitical_sovereignty_compliant,
		dora_sovereignty_compliant,
		cyber_resilience_sovereignty_compliant,
	]
	d := domains[_]
	d == true
])

sovereignty_score := (domains_passing * 100) / 11

# =============================================================================
# VIOLATION AGGREGATION
# =============================================================================

all_violations := violations if {
	# Convert sets to arrays for concat
	a_dr := [v | v := data_residency.violations[_]]
	a_cs := [v | v := cryptographic_sovereignty.violations[_]]
	a_is := [v | v := infrastructure_sovereignty.violations[_]]
	a_ss := [v | v := software_sovereignty.violations[_]]
	a_os := [v | v := operational_sovereignty.violations[_]]
	a_ns := [v | v := network_sovereignty.violations[_]]
	a_ai := [v | v := ai_sovereignty.violations[_]]
	a_bn := [v | v := breach_notification_sovereignty.violations[_]]
	a_gt := [v | v := geopolitical_sovereignty.violations[_]]
	a_dr_s := [v | v := dora_sovereignty.violations[_]]
	a_cr := [v | v := cyber_resilience_sovereignty.violations[_]]
	v_dr_cs  := array.concat(a_dr, a_cs)
	v_is_ss  := array.concat(a_is, a_ss)
	v_os_ns  := array.concat(a_os, a_ns)
	v_first  := array.concat(v_dr_cs, v_is_ss)
	v_second := array.concat(v_os_ns, a_ai)
	v_third  := array.concat(a_bn, a_gt)
	v_fourth := array.concat(a_dr_s, a_cr)
	v_all    := array.concat(v_first, v_second)
	v_base   := array.concat(v_all, v_third)
	violations := array.concat(v_base, v_fourth)
}

critical_violations := [v | v := all_violations[_]; v.severity == "critical"]
high_violations := [v | v := all_violations[_]; v.severity == "high"]
medium_violations := [v | v := all_violations[_]; v.severity == "medium"]

# =============================================================================
# SOVEREIGNTY LEVEL CLASSIFICATION
# =============================================================================

default sovereignty_level := "NON_SOVEREIGN"

sovereignty_level := "SOVEREIGN" if {
	overall_compliant
	count(critical_violations) == 0
	count(high_violations) == 0
} else := "NON_SOVEREIGN" if {
	count(critical_violations) > 0
} else := "HIGH_ASSURANCE" if {
	sovereignty_score >= 85
	count(critical_violations) == 0
	count(high_violations) <= 2
} else := "MODERATE_ASSURANCE" if {
	sovereignty_score >= 70
	count(critical_violations) == 0
} else := "LIMITED_ASSURANCE" if {
	sovereignty_score >= 50
}

# =============================================================================
# FULL REPORT
# =============================================================================

report := {
	"standard": "Digital Sovereignty Assessment",
	"overall_compliant": overall_compliant,
	"sovereignty_level": sovereignty_level,
	"sovereignty_score": sovereignty_score,
	"domains_passing": domains_passing,
	"domains_total": 11,
	"domains": {
		"data_residency": {
			"compliant": data_residency_compliant,
			"details": data_residency.report,
		},
		"cryptographic_sovereignty": {
			"compliant": cryptographic_sovereignty_compliant,
			"details": cryptographic_sovereignty.report,
		},
		"infrastructure_sovereignty": {
			"compliant": infrastructure_sovereignty_compliant,
			"details": infrastructure_sovereignty.report,
		},
		"software_sovereignty": {
			"compliant": software_sovereignty_compliant,
			"details": software_sovereignty.report,
		},
		"operational_sovereignty": {
			"compliant": operational_sovereignty_compliant,
			"details": operational_sovereignty.report,
		},
		"network_sovereignty": {
			"compliant": network_sovereignty_compliant,
			"details": network_sovereignty.report,
		},
		"ai_sovereignty": {
			"compliant": ai_sovereignty_compliant,
			"details": ai_sovereignty.report,
		},
		"breach_notification_sovereignty": {
			"compliant": breach_notification_sovereignty_compliant,
			"details": breach_notification_sovereignty.report,
		},
		"geopolitical_sovereignty": {
			"compliant": geopolitical_sovereignty_compliant,
			"details": geopolitical_sovereignty.report,
		},
		"dora_sovereignty": {
			"compliant": dora_sovereignty_compliant,
			"details": dora_sovereignty.report,
		},
		"cyber_resilience_sovereignty": {
			"compliant": cyber_resilience_sovereignty_compliant,
			"details": cyber_resilience_sovereignty.report,
		},
	},
	"violation_summary": {
		"total": count(all_violations),
		"critical": count(critical_violations),
		"high": count(high_violations),
		"medium": count(medium_violations),
	},
	"applicable_frameworks": [
		"ENISA European Digital Sovereignty",
		"GAIA-X Trust Framework",
		"DORA — EU Regulation 2022/2554",
		"EU Cyber Resilience Act (CRA) 2024/2847",
		"NIST SP 800-160 Vol. 2 (Cyber Resiliency Engineering)",
		"NIST CSF 2.0",
		"ISO 22301 (Business Continuity Management)",
		"FedRAMP High / GovCloud",
		"BSI C5 (Germany)",
		"NCSC Cloud Security Principles (UK)",
		"IRAP Protected (Australia)",
		"GDPR Chapter V (Data Transfers)",
		"GDPR Art. 33 (Breach Notification)",
		"NIS2 Art. 20 (Incident Reporting)",
		"EU AI Act §4.2 (Bias and Fairness)",
		"CLOUD Act / FISA 702 Response",
	],
}
