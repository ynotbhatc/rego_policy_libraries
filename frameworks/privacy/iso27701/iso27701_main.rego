package iso27701.main

import rego.v1

import data.iso27701.data_subject_rights
import data.iso27701.pii_controller
import data.iso27701.pii_processor
import data.iso27701.pims_requirements

default overall_compliant := false

overall_compliant if {
	pims_requirements.compliant
	pii_controller.compliant
	pii_processor.compliant
	data_subject_rights.compliant
}

modules_passing := count([m |
	some m in [
		pims_requirements.compliant,
		pii_controller.compliant,
		pii_processor.compliant,
		data_subject_rights.compliant,
	]
	m == true
])

compliance_report := {
    "framework":       "ISO/IEC 27701 Privacy Information Management System",
    "compliant":       overall_compliant,
    "total_controls":  134,
    "violations":      array.concat(
                           array.concat(
                               [v | some v in pims_requirements.violations],
                               [v | some v in pii_controller.violations]),
                           array.concat(
                               [v | some v in pii_processor.violations],
                               [v | some v in data_subject_rights.violations])),
    "violation_count": count(pims_requirements.violations) + count(pii_controller.violations)
                       + count(pii_processor.violations) + count(data_subject_rights.violations),
	"standard": "ISO/IEC 27701:2019 — Privacy Information Management System",
	"overall_compliant": overall_compliant,
	"modules_passing": modules_passing,
	"modules_total": 4,
	"modules": {
		"pims_requirements": {
			"compliant": pims_requirements.compliant,
			"details": pims_requirements.compliance_report,
		},
		"pii_controller": {
			"compliant": pii_controller.compliant,
			"details": pii_controller.compliance_report,
		},
		"pii_processor": {
			"compliant": pii_processor.compliant,
			"details": pii_processor.compliance_report,
		},
		"data_subject_rights": {
			"compliant": data_subject_rights.compliant,
			"details": data_subject_rights.compliance_report,
		},
	},
}
