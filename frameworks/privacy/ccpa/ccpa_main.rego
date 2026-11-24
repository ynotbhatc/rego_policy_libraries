# METADATA
# title: "Ccpa Main"
# custom:
#   class: compliance
#   framework: ccpa
#   source: us-state
#   domains: [privacy, us-state]
#   coverage:
#     checks: 7
#     cited: 7
#     expected: 7
#     found: 210
#     scope: directory
#     density: over
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package ccpa.main

import rego.v1

import data.ccpa.admt
import data.ccpa.business_obligations
import data.ccpa.consumer_rights
import data.ccpa.cybersecurity_audits
import data.ccpa.data_practices
import data.ccpa.risk_assessments
import data.ccpa.sensitive_data

default overall_compliant := false

overall_compliant if {
	consumer_rights.compliant
	business_obligations.compliant
	sensitive_data.compliant
	data_practices.compliant
	cybersecurity_audits.compliant
	risk_assessments.compliant
	admt.compliant
}

_modules := {
	"consumer_rights": {"title": "Consumer Rights", "compliant": consumer_rights.compliant, "findings": consumer_rights.violations},
	"business_obligations": {"title": "Business Obligations", "compliant": business_obligations.compliant, "findings": business_obligations.violations},
	"sensitive_data": {"title": "Sensitive Personal Information", "compliant": sensitive_data.compliant, "findings": sensitive_data.violations},
	"data_practices": {"title": "Data Practices", "compliant": data_practices.compliant, "findings": data_practices.violations},
	"cybersecurity_audits": {"title": "Cybersecurity Audits (11 CCR §§7120–7124)", "compliant": cybersecurity_audits.compliant, "findings": cybersecurity_audits.violations},
	"risk_assessments": {"title": "Risk Assessments (11 CCR §§7150–7157)", "compliant": risk_assessments.compliant, "findings": risk_assessments.violations},
	"admt": {"title": "Automated Decisionmaking Technology (11 CCR §§7200–7222)", "compliant": admt.compliant, "findings": admt.violations},
}

modules_passing := count([name | some name, m in _modules; m.compliant == true])

# The seven modules are the units this aggregator decides on: total_controls is the module count, a failing
# module is one violation, and passed + failed == total. The detailed rows of every module are carried in
# `findings` (and per module under modules.<name>.details), so the number of violations can never exceed the
# declared total. Before 2026-11-24 `violations` held the detail rows (118 on empty input against a total of 7).
_module_violations := [msg |
	some name in sort(object.keys(_modules))
	m := _modules[name]
	not m.compliant == true
	msg := sprintf("CCPA/CPRA %s: module not compliant — %d finding(s), listed in findings and in modules.%s.details", [m.title, count(m.findings), name])
]

_findings := [f |
	some name in sort(object.keys(_modules))
	some f in sort(_modules[name].findings)
]

compliance_report := {
	"framework": "California Consumer Privacy Act (CCPA / CPRA)",
	"compliant": overall_compliant,
	"total_controls": 7,
	"violations": _module_violations,
	"violation_count": count(_module_violations),
	"failed_controls": count(_module_violations),
	"passed_controls": 7 - count(_module_violations),
	"not_applicable_controls": 0,
	"findings": _findings,
	"finding_count": count(_findings),
	"standard": "CCPA/CPRA — California Consumer Privacy Act (as amended by CPRA 2023) + 2025 CPPA Regulations (cybersecurity audits, risk assessments, ADMT; effective 2026-01-01)",
	"overall_compliant": overall_compliant,
	"modules_passing": modules_passing,
	"modules_total": 7,
	"modules": {
		"consumer_rights": {
			"compliant": consumer_rights.compliant,
			"details": consumer_rights.compliance_report,
		},
		"business_obligations": {
			"compliant": business_obligations.compliant,
			"details": business_obligations.compliance_report,
		},
		"sensitive_data": {
			"compliant": sensitive_data.compliant,
			"details": sensitive_data.compliance_report,
		},
		"data_practices": {
			"compliant": data_practices.compliant,
			"details": data_practices.compliance_report,
		},
		"cybersecurity_audits": {
			"compliant": cybersecurity_audits.compliant,
			"details": cybersecurity_audits.compliance_report,
		},
		"risk_assessments": {
			"compliant": risk_assessments.compliant,
			"details": risk_assessments.compliance_report,
		},
		"admt": {
			"compliant": admt.compliant,
			"details": admt.compliance_report,
		},
	},
}
