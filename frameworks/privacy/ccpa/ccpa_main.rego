# METADATA
# title: "Ccpa Main"
# custom:
#   class: compliance
#   framework: ccpa
#   source: us-state
#   domains: [privacy, us-state]
#   coverage:
#     checks: 0
#     cited: 0
#     expected: 7
#     found: 197
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     as_of: v2.3.4
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

modules_passing := count([m |
	some m in [
		consumer_rights.compliant,
		business_obligations.compliant,
		sensitive_data.compliant,
		data_practices.compliant,
		cybersecurity_audits.compliant,
		risk_assessments.compliant,
		admt.compliant,
	]
	m == true
])

compliance_report := {
	"framework": "California Consumer Privacy Act (CCPA / CPRA)",
	"compliant": overall_compliant,
	"total_controls": 7,
	"violations": array.concat(
		array.concat(
			array.concat(
				[v | some v in consumer_rights.violations],
				[v | some v in business_obligations.violations],
			),
			array.concat(
				[v | some v in sensitive_data.violations],
				[v | some v in data_practices.violations],
			),
		),
		array.concat(
			array.concat(
				[v | some v in cybersecurity_audits.violations],
				[v | some v in risk_assessments.violations],
			),
			[v | some v in admt.violations],
		),
	),
	"violation_count": ((count(consumer_rights.violations) + count(business_obligations.violations)) + (count(sensitive_data.violations) + count(data_practices.violations))) + ((count(cybersecurity_audits.violations) + count(risk_assessments.violations)) + count(admt.violations)),
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
