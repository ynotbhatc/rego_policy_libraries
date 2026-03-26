package gdpr.main

import rego.v1

import data.gdpr.compliance
import data.gdpr.controller_processor
import data.gdpr.cookies_tracking
import data.gdpr.data_transfers

# GDPR Compliance Aggregator
# Combines all GDPR module assessments into a single compliance report

# =============================================================================
# MODULE COMPLIANCE STATUS
# =============================================================================

core_compliant if { compliance.compliant }
controller_processor_compliant if { controller_processor.compliant }
data_transfers_compliant if { data_transfers.compliant }
cookies_tracking_compliant if { cookies_tracking.compliant }

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default overall_compliant := false

overall_compliant if {
	core_compliant
	controller_processor_compliant
	data_transfers_compliant
	cookies_tracking_compliant
}

modules_passing := count([m |
	some m in [
		core_compliant,
		controller_processor_compliant,
		data_transfers_compliant,
		cookies_tracking_compliant,
	]
	m == true
])

# =============================================================================
# FULL REPORT
# =============================================================================

report := {
	"standard": "GDPR (EU) 2016/679 — Full Compliance Assessment",
	"overall_compliant": overall_compliant,
	"modules_passing": modules_passing,
	"modules_total": 4,
	"modules": {
		"core_gdpr": {
			"compliant": core_compliant,
			"details": compliance.report,
		},
		"controller_processor": {
			"compliant": controller_processor_compliant,
			"details": controller_processor.report,
		},
		"data_transfers": {
			"compliant": data_transfers_compliant,
			"details": data_transfers.report,
		},
		"cookies_and_tracking": {
			"compliant": cookies_tracking_compliant,
			"details": cookies_tracking.report,
		},
	},
}
