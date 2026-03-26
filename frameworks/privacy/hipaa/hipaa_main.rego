package hipaa.main

import rego.v1

import data.hipaa.hitech
import data.hipaa.privacy_rule
import data.hipaa.security_rule

# HIPAA Compliance Aggregator
# Combines Security Rule, Privacy Rule, and HITECH Act assessments

# =============================================================================
# OVERALL HIPAA COMPLIANCE
# =============================================================================

security_rule_compliant if {
	security_rule.compliant
}

privacy_rule_compliant if {
	privacy_rule.compliant
}

hitech_compliant if {
	hitech.compliant
}

default overall_compliant := false

overall_compliant if {
	security_rule_compliant
	privacy_rule_compliant
	hitech_compliant
}

# =============================================================================
# SCORING
# =============================================================================

# Count major domains passing
domains_passing := count([d |
	some d in [
		security_rule_compliant,
		privacy_rule_compliant,
		hitech_compliant,
	]
	d == true
])

# Individual safeguard scores (from security rule)
_admin_score := 1 if { security_rule.administrative_safeguards_compliant } else := 0
_phys_score := 1 if { security_rule.physical_safeguards_compliant } else := 0
_tech_score := 1 if { security_rule.technical_safeguards_compliant } else := 0

security_safeguards_score := ((_admin_score + _phys_score + _tech_score) * 100) / 3

# =============================================================================
# FULL COMPLIANCE REPORT
# =============================================================================

report := {
	"standard": "HIPAA (Security Rule + Privacy Rule + HITECH Act)",
	"overall_compliant": overall_compliant,
	"domains": {
		"security_rule": {
			"compliant": security_rule_compliant,
			"details": security_rule.report,
		},
		"privacy_rule": {
			"compliant": privacy_rule_compliant,
			"details": privacy_rule.report,
		},
		"hitech_act": {
			"compliant": hitech_compliant,
			"details": hitech.report,
		},
	},
	"summary": {
		"domains_passing": domains_passing,
		"domains_total": 3,
		"security_safeguards_score_pct": security_safeguards_score,
	},
}
