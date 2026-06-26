package ccpa.main

import rego.v1

import data.ccpa.business_obligations
import data.ccpa.consumer_rights
import data.ccpa.data_practices
import data.ccpa.sensitive_data

default overall_compliant := false

overall_compliant if {
	consumer_rights.compliant
	business_obligations.compliant
	sensitive_data.compliant
	data_practices.compliant
}

modules_passing := count([m |
	some m in [
		consumer_rights.compliant,
		business_obligations.compliant,
		sensitive_data.compliant,
		data_practices.compliant,
	]
	m == true
])

compliance_report := {
    "framework":       "California Consumer Privacy Act (CCPA / CPRA)",
    "compliant":       overall_compliant,
    "total_controls":  4,
    "violations":      array.concat(
                           array.concat(
                               [v | some v in consumer_rights.violations],
                               [v | some v in business_obligations.violations]),
                           array.concat(
                               [v | some v in sensitive_data.violations],
                               [v | some v in data_practices.violations])),
    "violation_count": count(consumer_rights.violations) + count(business_obligations.violations)
                       + count(sensitive_data.violations) + count(data_practices.violations),
	"standard": "CCPA/CPRA — California Consumer Privacy Act (as amended by CPRA 2023)",
	"overall_compliant": overall_compliant,
	"modules_passing": modules_passing,
	"modules_total": 4,
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
	},
}
