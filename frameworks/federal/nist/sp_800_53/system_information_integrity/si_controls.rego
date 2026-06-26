package nist.sp800_53.system_information_integrity

import rego.v1

# NIST SP 800-53 Rev 5 — System and Information Integrity (SI) Family
# Flaw remediation, malicious code protection, monitoring, integrity verification.

default compliant := false

violation contains msg if {
    not input.si_controls.policy.documented
    msg := "NIST SI-1: System and information integrity policy not documented"
}

violation contains msg if {
    not input.si_controls.flaw_remediation.timely
    msg := "NIST SI-2: Flaw remediation (patching) not performed within defined timeframes"
}

violation contains msg if {
    not input.si_controls.malicious_code_protection.deployed
    msg := "NIST SI-3: Malicious code protection (antivirus/EDR) not deployed at entry/exit points"
}

violation contains msg if {
    not input.si_controls.system_monitoring.continuous
    msg := "NIST SI-4: System monitoring (IDS/IPS, log review) not continuous"
}

violation contains msg if {
    not input.si_controls.security_alerts.acted_upon
    msg := "NIST SI-5: Security alerts/advisories not received and acted upon"
}

violation contains msg if {
    not input.si_controls.security_function_verification.tested
    msg := "NIST SI-6: Security function verification not periodically tested"
}

violation contains msg if {
    not input.si_controls.software_firmware_integrity.verified
    msg := "NIST SI-7: Software and firmware integrity not verified before execution"
}

violation contains msg if {
    not input.si_controls.spam_protection.enabled
    msg := "NIST SI-8: Spam protection not enabled at gateways or endpoints"
}

violation contains msg if {
    not input.si_controls.input_validation.enforced
    msg := "NIST SI-10: Information input validation not enforced"
}

violation contains msg if {
    not input.si_controls.error_handling.no_info_disclosure
    msg := "NIST SI-11: Error handling discloses sensitive information"
}

violation contains msg if {
    not input.si_controls.information_management_retention.policy_enforced
    msg := "NIST SI-12: Information management/retention policies not enforced"
}

violation contains msg if {
    not input.si_controls.memory_protection.enabled
    msg := "NIST SI-16: Memory protection (ASLR, DEP, NX) not enabled"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "family": "SI",
    "name":   "System and Information Integrity",
    "controls_evaluated": 13,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
