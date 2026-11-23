# METADATA
# title: "GDPR Compliance Aggregator"
# custom:
#   class: compliance
#   framework: gdpr
#   source: eu
#   domains: [privacy, eu]
#   coverage:
#     checks: 5
#     cited: 5
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
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

default core_compliant := false

core_compliant if compliance.compliant

default controller_processor_compliant := false

controller_processor_compliant if controller_processor.compliant

default data_transfers_compliant := false

data_transfers_compliant if data_transfers.compliant

default cookies_tracking_compliant := false

cookies_tracking_compliant if cookies_tracking.compliant

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

# Framework-key entrypoint: the product reads /v1/data/gdpr/main/compliance_report. This package
# names its report `report`; expose it under the shared name with an explicit `compliant` and a
# fail-closed default so the entrypoint is never undefined.
default compliance_report := {
	"framework_key": "gdpr",
	"compliant": false,
	"fail_closed": true,
	"violations": [{"control": "FAIL-CLOSED", "title": "no report produced for gdpr; this is not a passing result"}],
	"violation_count": 1,
	"failed_controls": 1,
	"total_controls": 1,
}

# The product reads violations, violation_count and total_controls: the four modules are the units this
# aggregator decides on, so a failing module is one finding and total_controls is the module count.
#
# Conditional obligations (Art. 8, 9, 22, 26, 37, Chapter V, the tracking technologies) apply on a fact the
# collector states as a boolean. A fact that is absent, null or not a boolean is never read as "not
# applicable": the module fails and the fact is listed under evidence_missing, here and on the module's
# violation, so the reader can tell "not collected" from "collected and failing".
_module_violations := [violation |
	some name, ok in {
		"core_gdpr": core_compliant,
		"controller_processor": controller_processor_compliant,
		"data_transfers": data_transfers_compliant,
		"cookies_and_tracking": cookies_tracking_compliant,
	}
	not ok
	violation := {
		"control": name,
		"title": _module_title(name),
		"evidence_missing": [m.path | some m in _module_evidence_missing[name]],
	}
]

_module_evidence_missing := {
	"core_gdpr": compliance.evidence_missing,
	"controller_processor": controller_processor.evidence_missing,
	"data_transfers": [],
	"cookies_and_tracking": cookies_tracking.evidence_missing,
}

_module_title(name) := sprintf("GDPR module %v is not compliant", [name]) if {
	count(_module_evidence_missing[name]) == 0
} else := sprintf(
	"GDPR module %v is not compliant; evidence missing — must be true or false: %v",
	[name, concat(", ", [m.path | some m in _module_evidence_missing[name]])],
)

evidence_missing := [object.union(m, {"module": name}) |
	some name in sort(object.keys(_module_evidence_missing))
	some m in _module_evidence_missing[name]
]

compliance_report := object.union(report, {
	"framework_key": "gdpr",
	"compliant": _entrypoint_compliant,
	"violations": _module_violations,
	"violation_count": count(_module_violations),
	"failed_controls": count(_module_violations),
	"evidence_missing": evidence_missing,
	"total_controls": _declared_controls,
})

_declared_controls := 4

default _entrypoint_compliant := false

_entrypoint_compliant if report.overall_compliant == true
