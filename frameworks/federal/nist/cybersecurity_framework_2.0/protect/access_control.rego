package nist.csf.protect

import rego.v1

# NIST Cybersecurity Framework 2.0 - PROTECT Function
# Access Control Category (PR.AC)

# PR.AC-01: Identities and credentials are managed for authorized devices and users
identity_credential_management if {
    input.access_control.identity_management.centralized_system == true
    input.access_control.identity_management.lifecycle_management == true
    input.access_control.identity_management.credential_policies == true
}

# PR.AC-02: Physical access to assets is managed and protected
physical_access_management if {
    input.access_control.physical_access.controlled_access_points == true
    input.access_control.physical_access.visitor_management == true
    input.access_control.physical_access.monitoring_systems == true
}

# PR.AC-03: Remote access is managed
remote_access_management if {
    input.access_control.remote_access.vpn_required == true
    input.access_control.remote_access.multi_factor_authentication == true
    input.access_control.remote_access.encrypted_connections == true
}

# PR.AC-04: Access permissions are managed, incorporating the principles of least privilege and separation of duties
access_permissions_management if {
    input.access_control.permissions.least_privilege_implemented == true
    input.access_control.permissions.separation_of_duties == true
    input.access_control.permissions.regular_access_reviews == true
}

# PR.AC-05: Network integrity is protected, incorporating network segregation where appropriate
network_integrity_protection if {
    input.access_control.network.network_segmentation == true
    input.access_control.network.traffic_filtering == true
    input.access_control.network.unauthorized_access_prevention == true
}

# PR.AC-06: Identities are proofed and bound to credentials and asserted in interactions
identity_proofing if {
    input.access_control.identity_proofing.verification_processes == true
    input.access_control.identity_proofing.credential_binding == true
    input.access_control.identity_proofing.assertion_mechanisms == true
}

# PR.AC-07: Users, devices, and other assets are authenticated
authentication_mechanisms if {
    input.access_control.authentication.strong_authentication == true
    input.access_control.authentication.device_authentication == true
    input.access_control.authentication.multi_factor_required == true
}

# PR.AT-01: All users are informed and trained
user_awareness_training if {
    input.awareness_training.all_users_trained == true
    input.awareness_training.regular_updates == true
    input.awareness_training.role_specific_training == true
}

# PR.AT-02: Privileged users understand roles and responsibilities
privileged_user_training if {
    input.awareness_training.privileged_users.specialized_training == true
    input.awareness_training.privileged_users.responsibilities_documented == true
    input.awareness_training.privileged_users.regular_updates == true
}

# PR.AT-03: Third-party stakeholders understand roles and responsibilities
third_party_training if {
    input.awareness_training.third_party.training_provided == true
    input.awareness_training.third_party.expectations_documented == true
    input.awareness_training.third_party.compliance_verified == true
}

# PR.AT-04: Senior executives understand roles and responsibilities
executive_awareness if {
    input.awareness_training.executives.cybersecurity_briefings == true
    input.awareness_training.executives.risk_understanding == true
    input.awareness_training.executives.decision_impact_awareness == true
}

# PR.AT-05: Physical and cybersecurity personnel understand roles and responsibilities
security_personnel_training if {
    input.awareness_training.security_personnel.comprehensive_training == true
    input.awareness_training.security_personnel.ongoing_education == true
    input.awareness_training.security_personnel.certification_requirements == true
}

# PR.DS-01: Data-at-rest is protected
data_at_rest_protection if {
    input.data_security.at_rest.encryption_implemented == true
    input.data_security.at_rest.access_controls == true
    input.data_security.at_rest.integrity_monitoring == true
}

# PR.DS-02: Data-in-transit is protected
data_in_transit_protection if {
    input.data_security.in_transit.encryption_required == true
    input.data_security.in_transit.secure_protocols == true
    input.data_security.in_transit.integrity_verification == true
}

# PR.DS-03: Assets are formally managed throughout removal, transfers, and disposition
asset_lifecycle_management if {
    input.data_security.asset_management.formal_processes == true
    input.data_security.asset_management.secure_disposal == true
    input.data_security.asset_management.transfer_procedures == true
}

# PR.DS-04: Adequate capacity to ensure availability is maintained
availability_capacity_management if {
    input.data_security.availability.capacity_planning == true
    input.data_security.availability.redundancy_implemented == true
    input.data_security.availability.performance_monitoring == true
}

# PR.DS-05: Protections against data leaks are implemented
data_leak_protection if {
    input.data_security.leak_prevention.dlp_tools_deployed == true
    input.data_security.leak_prevention.monitoring_implemented == true
    input.data_security.leak_prevention.response_procedures == true
}

# PR.DS-06: Integrity checking mechanisms are used to verify software, firmware, and information integrity
integrity_checking if {
    input.data_security.integrity.verification_mechanisms == true
    input.data_security.integrity.regular_validation == true
    input.data_security.integrity.automated_monitoring == true
}

# PR.DS-07: The development and testing environment(s) are separate from the production environment
environment_separation if {
    input.data_security.environments.dev_prod_separation == true
    input.data_security.environments.test_isolation == true
    input.data_security.environments.secure_transitions == true
}

# PR.DS-08: Integrity checking mechanisms are used to verify hardware integrity
hardware_integrity if {
    input.data_security.hardware.integrity_verification == true
    input.data_security.hardware.trusted_hardware == true
    input.data_security.hardware.supply_chain_verification == true
}

# PR.IP-01: A baseline configuration of information technology/industrial control systems is created and maintained
baseline_configuration_management if {
    input.information_protection.configuration.baseline_established == true
    input.information_protection.configuration.regularly_updated == true
    input.information_protection.configuration.version_controlled == true
}

# PR.IP-02: A System Development Life Cycle to manage systems is implemented
sdlc_implementation if {
    input.information_protection.sdlc.formal_process == true
    input.information_protection.sdlc.security_integrated == true
    input.information_protection.sdlc.documentation_maintained == true
}

# PR.IP-03: Configuration change control processes are in place
change_control_processes if {
    input.information_protection.change_control.formal_process == true
    input.information_protection.change_control.approval_required == true
    input.information_protection.change_control.documentation_maintained == true
}

# PR.IP-04: Backups of information are conducted, maintained, and tested
backup_processes if {
    input.information_protection.backups.regular_backups == true
    input.information_protection.backups.tested_restoration == true
    input.information_protection.backups.secure_storage == true
}

# Aggregate NIST CSF Protect function compliance
nist_csf_protect_compliant if {
    identity_credential_management
    physical_access_management
    remote_access_management
    access_permissions_management
    network_integrity_protection
    identity_proofing
    authentication_mechanisms
    user_awareness_training
    privileged_user_training
    third_party_training
    executive_awareness
    security_personnel_training
    data_at_rest_protection
    data_in_transit_protection
    asset_lifecycle_management
    availability_capacity_management
    data_leak_protection
    integrity_checking
    environment_separation
    hardware_integrity
    baseline_configuration_management
    sdlc_implementation
    change_control_processes
    backup_processes
}

# Detailed NIST CSF Protect compliance report
nist_csf_protect_compliance := {
    "identity_credential_management": identity_credential_management,
    "physical_access_management": physical_access_management,
    "remote_access_management": remote_access_management,
    "access_permissions_management": access_permissions_management,
    "network_integrity_protection": network_integrity_protection,
    "identity_proofing": identity_proofing,
    "authentication_mechanisms": authentication_mechanisms,
    "user_awareness_training": user_awareness_training,
    "privileged_user_training": privileged_user_training,
    "third_party_training": third_party_training,
    "executive_awareness": executive_awareness,
    "security_personnel_training": security_personnel_training,
    "data_at_rest_protection": data_at_rest_protection,
    "data_in_transit_protection": data_in_transit_protection,
    "asset_lifecycle_management": asset_lifecycle_management,
    "availability_capacity_management": availability_capacity_management,
    "data_leak_protection": data_leak_protection,
    "integrity_checking": integrity_checking,
    "environment_separation": environment_separation,
    "hardware_integrity": hardware_integrity,
    "baseline_configuration_management": baseline_configuration_management,
    "sdlc_implementation": sdlc_implementation,
    "change_control_processes": change_control_processes,
    "backup_processes": backup_processes,
    "overall_compliant": nist_csf_protect_compliant
}