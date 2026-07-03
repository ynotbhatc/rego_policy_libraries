package iso27001

import rego.v1

# Defaults so report/details never collapse to {} on empty input
default access_control_compliant := false
default cryptography_compliant := false
default operations_security_compliant := false
default communications_security_compliant := false
default system_acquisition_maintenance_compliant := false


import data.iso27001.access_control
import data.iso27001.cryptography
import data.iso27001.operations_security
import data.iso27001.communications_security
import data.iso27001.system_acquisition_maintenance

# ISO/IEC 27001:2022 Information Security Management System
# Technical controls that can be validated through Ansible automation

# Main compliance check - system must pass all technical control categories
default allow := false

allow if {
    access_control.compliant
    cryptography.compliant
    operations_security.compliant
    communications_security.compliant
    system_acquisition_maintenance.compliant
}

# Individual category compliance checks
access_control_compliant if {
    access_control.compliant
}

cryptography_compliant if {
    cryptography.compliant
}

operations_security_compliant if {
    operations_security.compliant
}

communications_security_compliant if {
    communications_security.compliant
}

system_acquisition_maintenance_compliant if {
    system_acquisition_maintenance.compliant
}

# Consumer endpoint — /v1/data/iso27001/iso27001_assessment
# The compliance-repo iso27001_compliance role reads .compliant, .score,
# .isms_results. Score = % of the 5 ISMS domains passing.
iso27001_domains_passing := count([c |
	some c in [
		access_control_compliant,
		cryptography_compliant,
		operations_security_compliant,
		communications_security_compliant,
		system_acquisition_maintenance_compliant,
	]
	c == true
])

iso27001_assessment := {
	"framework": "ISO/IEC 27001:2022",
	"compliant": allow,
	"score": round((100 * iso27001_domains_passing) / 5),
	"domains_evaluated": 5,
	"domains_passing": iso27001_domains_passing,
	"isms_results": {
		"access_control": access_control_compliant,
		"cryptography": cryptography_compliant,
		"operations_security": operations_security_compliant,
		"communications_security": communications_security_compliant,
		"system_acquisition_maintenance": system_acquisition_maintenance_compliant,
	},
}

# Comprehensive ISO 27001 compliance report
iso27001_compliance_report := {
    "overall_compliant": allow,
    "access_control": {
        "compliant": access_control.compliant,
        "details": access_control.compliance_details
    },
    "cryptography": {
        "compliant": cryptography.compliant,
        "details": cryptography.compliance_details
    },
    "operations_security": {
        "compliant": operations_security.compliant,
        "details": operations_security.compliance_details
    },
    "communications_security": {
        "compliant": communications_security.compliant,
        "details": communications_security.compliance_details
    },
    "system_acquisition_maintenance": {
        "compliant": system_acquisition_maintenance.compliant,
        "details": system_acquisition_maintenance.compliance_details
    }
}