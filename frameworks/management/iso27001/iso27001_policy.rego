package iso27001

import rego.v1

import data.iso27001.access_control
import data.iso27001.cryptography
import data.iso27001.operations_security
import data.iso27001.communications_security
import data.iso27001.system_acquisition_maintenance

# ISO/IEC 27001:2022 Information Security Management System
# Technical controls that can be validated through Ansible automation

# Main compliance check - system must pass all technical control categories
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