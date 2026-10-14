# METADATA
# title: "NIST Cybersecurity Framework 2.0 - PROTECT Function"
# custom:
#   class: compliance
#   framework: nist_cybersecurity_framework_2_0
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 18
#     cited: 9
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package nist.csf.protect

import rego.v1

# NIST Cybersecurity Framework 2.0 - PROTECT Function
#
# Fact checks. Each violation below is labelled with the CSF 2.0 subcategory it decides in nist.csf.main
# (CPRT ids, CSF_2_0_0). The checks were written against CSF 1.1; a check keeps deciding a subcategory only when
# its id is current in CSF 2.0 and it tests that outcome, or CPRT records its 1.1 id as moved to exactly one
# 2.0 subcategory and the check is a fair reading of that text. The other checks were removed; their lineage
# is the `legacy` data table at the end.

# CSF 2.0 PR.AA-02 (fact check; legacy label PR.AC-06, moved to PR.AA-02): Identities are proofed and bound to credentials and asserted in interactions
default identity_proofing := false

identity_proofing if {
	input.access_control.identity_proofing.verification_processes == true
	input.access_control.identity_proofing.credential_binding == true
	input.access_control.identity_proofing.assertion_mechanisms == true
}

# CSF 2.0 PR.AA-03 (fact check; legacy label PR.AC-07, moved to PR.AA-03): Users, devices, and other assets are authenticated
default authentication_mechanisms := false

authentication_mechanisms if {
	input.access_control.authentication.strong_authentication == true
	input.access_control.authentication.device_authentication == true
	input.access_control.authentication.multi_factor_required == true
}

# CSF 2.0 PR.AA-05 (fact check; legacy label PR.AC-04, moved to PR.AA-05): Access permissions are managed, incorporating the principles of least privilege and separation of duties
default access_permissions_management := false

access_permissions_management if {
	input.access_control.permissions.least_privilege_implemented == true
	input.access_control.permissions.separation_of_duties == true
	input.access_control.permissions.regular_access_reviews == true
}

# CSF 2.0 PR.AA-06 (fact check; legacy label PR.AC-02, moved to PR.AA-06): Physical access to assets is managed and protected
default physical_access_management := false

physical_access_management if {
	input.access_control.physical_access.controlled_access_points == true
	input.access_control.physical_access.visitor_management == true
	input.access_control.physical_access.monitoring_systems == true
}

# CSF 2.0 PR.AT-01 (fact check): All users are informed and trained
default user_awareness_training := false

user_awareness_training if {
	input.awareness_training.all_users_trained == true
	input.awareness_training.regular_updates == true
	input.awareness_training.role_specific_training == true
}

# CSF 2.0 PR.DS-01 (fact check): Data-at-rest is protected
default data_at_rest_protection := false

data_at_rest_protection if {
	input.data_security.at_rest.encryption_implemented == true
	input.data_security.at_rest.access_controls == true
	input.data_security.at_rest.integrity_monitoring == true
}

# CSF 2.0 PR.DS-02 (fact check): Data-in-transit is protected
default data_in_transit_protection := false

data_in_transit_protection if {
	input.data_security.in_transit.encryption_required == true
	input.data_security.in_transit.secure_protocols == true
	input.data_security.in_transit.integrity_verification == true
}

# CSF 2.0 PR.DS-11 (fact check; legacy label PR.IP-04, moved to PR.DS-11): Backups of information are conducted, maintained, and tested
default backup_processes := false

backup_processes if {
	input.information_protection.backups.regular_backups == true
	input.information_protection.backups.tested_restoration == true
	input.information_protection.backups.secure_storage == true
}

# CSF 2.0 PR.IR-04 (fact check; legacy label PR.DS-04, moved to PR.IR-04): Adequate capacity to ensure availability is maintained
default availability_capacity_management := false

availability_capacity_management if {
	input.data_security.availability.capacity_planning == true
	input.data_security.availability.redundancy_implemented == true
	input.data_security.availability.performance_monitoring == true
}

# Aggregate over the predicates above (the CSF 2.0 fact checks of this function only)
default nist_csf_protect_compliant := false

nist_csf_protect_compliant if {
	identity_proofing
	authentication_mechanisms
	access_permissions_management
	physical_access_management
	user_awareness_training
	data_at_rest_protection
	data_in_transit_protection
	backup_processes
	availability_capacity_management
}

# Detailed report of the predicates above (kept for consumers; current checks only)
nist_csf_protect_compliance := {
	"identity_proofing": identity_proofing,
	"authentication_mechanisms": authentication_mechanisms,
	"access_permissions_management": access_permissions_management,
	"physical_access_management": physical_access_management,
	"user_awareness_training": user_awareness_training,
	"data_at_rest_protection": data_at_rest_protection,
	"data_in_transit_protection": data_in_transit_protection,
	"backup_processes": backup_processes,
	"availability_capacity_management": availability_capacity_management,
	"overall_compliant": nist_csf_protect_compliant,
}

# ── Violation set (CSF 2.0 subcategories decided by facts; read by nist.csf.main) ──

violation contains msg if {
	not identity_proofing
	msg := "CSF PR.AA-02: Identities not proofed/bound to credentials (fact check carried from CSF 1.1 PR.AC-06, which CPRT records as moved to PR.AA-02)"
}

violation contains msg if {
	not authentication_mechanisms
	msg := "CSF PR.AA-03: Authentication mechanisms not strength-aligned with risk (fact check carried from CSF 1.1 PR.AC-07, which CPRT records as moved to PR.AA-03)"
}

violation contains msg if {
	not access_permissions_management
	msg := "CSF PR.AA-05: Access permissions/least privilege/SoD not enforced (fact check carried from CSF 1.1 PR.AC-04, which CPRT records as moved to PR.AA-05)"
}

violation contains msg if {
	not physical_access_management
	msg := "CSF PR.AA-06: Physical access to assets not managed/protected (fact check carried from CSF 1.1 PR.AC-02, which CPRT records as moved to PR.AA-06)"
}

violation contains msg if {
	not user_awareness_training
	msg := "CSF PR.AT-01: All users not trained on cybersecurity awareness"
}

violation contains msg if {
	not data_at_rest_protection
	msg := "CSF PR.DS-01: Data at rest not protected (encryption, access control)"
}

violation contains msg if {
	not data_in_transit_protection
	msg := "CSF PR.DS-02: Data in transit not protected (TLS, VPN, encrypted channels)"
}

violation contains msg if {
	not backup_processes
	msg := "CSF PR.DS-11: Backups not conducted, maintained, and tested (fact check carried from CSF 1.1 PR.IP-04, which CPRT records as moved to PR.DS-11)"
}

violation contains msg if {
	not availability_capacity_management
	msg := "CSF PR.IR-04: Adequate capacity to ensure availability not maintained (fact check carried from CSF 1.1 PR.DS-04, which CPRT records as moved to PR.IR-04)"
}

# Lineage of the CSF 1.1-era fact checks this module no longer evaluates (removed; data only, no rule
# behind it, not a control). Keyed by the label the check carried. status "retired": the CSF 1.1 id is
# withdrawn in CSF 2.0 (csf_2_0_ids = CPRT's destinations); "unmapped": the label reused a current CSF 2.0
# id but the check tested something else or only part of it. facts_read: the input the check read. Each 2.0
# subcategory is decided in nist.csf.main on its own basis (facts or attestation).
legacy := {
	"PR.AC-01": {
		"csf_1_1_id": "PR.AC-01",
		"status": "retired",
		"csf_2_0_ids": ["PR.AA-01", "PR.AA-05"],
		"facts_read": ["input.access_control.identity_management.centralized_system", "input.access_control.identity_management.lifecycle_management", "input.access_control.identity_management.credential_policies"],
		"legacy_message": "Identities and credentials not managed for authorized users/devices",
		"reason": "CSF 1.1 PR.AC-01 (\"Identities and credentials are issued, managed, verified, revoked, and audited for authorized devices, users and processes\") is withdrawn in CSF 2.0: Incorporated into PR.AA-01, PR.AA-05; this check its outcome is spread over 2 CSF 2.0 elements, so it cannot be attributed to one subcategory",
	},
	"PR.AC-03": {
		"csf_1_1_id": "PR.AC-03",
		"status": "retired",
		"csf_2_0_ids": ["PR.AA-03", "PR.AA-05", "PR.IR-01"],
		"facts_read": ["input.access_control.remote_access.vpn_required", "input.access_control.remote_access.multi_factor_authentication", "input.access_control.remote_access.encrypted_connections"],
		"legacy_message": "Remote access not managed (VPN, MFA, encryption)",
		"reason": "CSF 1.1 PR.AC-03 (\"Remote access is managed\") is withdrawn in CSF 2.0: Incorporated into PR.AA-03, PR.AA-05, PR.IR-01; this check its outcome is spread over 3 CSF 2.0 elements, so it cannot be attributed to one subcategory",
	},
	"PR.AC-05": {
		"csf_1_1_id": "PR.AC-05",
		"status": "retired",
		"csf_2_0_ids": ["PR.IR-01"],
		"facts_read": ["input.access_control.network.network_segmentation", "input.access_control.network.traffic_filtering", "input.access_control.network.unauthorized_access_prevention"],
		"legacy_message": "Network integrity (segmentation, isolation) not protected",
		"reason": "CSF 1.1 PR.AC-05 (\"Network integrity is protected (e.g., network segregation, network segmentation)\") is withdrawn in CSF 2.0: Incorporated into PR.IR-01; this check tests part of a broader CSF 2.0 outcome, so it cannot decide PR.IR-01 on its own",
	},
	"PR.AT-02": {
		"csf_1_1_id": "PR.AT-02",
		"status": "unmapped",
		"csf_2_0_ids": ["PR.AT-02"],
		"facts_read": ["input.awareness_training.privileged_users.specialized_training", "input.awareness_training.privileged_users.responsibilities_documented", "input.awareness_training.privileged_users.regular_updates"],
		"legacy_message": "Privileged users understand roles and responsibilities",
		"reason": "CSF 2.0 PR.AT-02 reads \"Individuals in specialized roles are provided with awareness and training so that they possess the knowledge and skills to perform relevant tasks with cybersecurity risks in mind\"; this check tests privileged users only; the 2.0 text covers all individuals in specialized roles (never emitted a violation) The predicate never emitted a violation.",
	},
	"PR.AT-03": {
		"csf_1_1_id": "PR.AT-03",
		"status": "retired",
		"csf_2_0_ids": ["PR.AT-01", "PR.AT-02"],
		"facts_read": ["input.awareness_training.third_party.training_provided", "input.awareness_training.third_party.expectations_documented", "input.awareness_training.third_party.compliance_verified"],
		"legacy_message": "Third-party stakeholders understand roles and responsibilities",
		"reason": "CSF 1.1 PR.AT-03 (\"Third-party stakeholders (e.g., suppliers, customers, partners) understand their roles and responsibilities\") is withdrawn in CSF 2.0: Incorporated into PR.AT-01, PR.AT-02; this check its outcome is spread over 2 CSF 2.0 elements, so it cannot be attributed to one subcategory The predicate never emitted a violation.",
	},
	"PR.AT-04": {
		"csf_1_1_id": "PR.AT-04",
		"status": "retired",
		"csf_2_0_ids": ["PR.AT-02"],
		"facts_read": ["input.awareness_training.executives.cybersecurity_briefings", "input.awareness_training.executives.risk_understanding", "input.awareness_training.executives.decision_impact_awareness"],
		"legacy_message": "Senior executives understand roles and responsibilities",
		"reason": "CSF 1.1 PR.AT-04 (\"Senior executives understand their roles and responsibilities\") is withdrawn in CSF 2.0: Incorporated into PR.AT-02; this check tests part of a broader CSF 2.0 outcome, so it cannot decide PR.AT-02 on its own The predicate never emitted a violation.",
	},
	"PR.AT-05": {
		"csf_1_1_id": "PR.AT-05",
		"status": "retired",
		"csf_2_0_ids": ["PR.AT-02"],
		"facts_read": ["input.awareness_training.security_personnel.comprehensive_training", "input.awareness_training.security_personnel.ongoing_education", "input.awareness_training.security_personnel.certification_requirements"],
		"legacy_message": "Physical and cybersecurity personnel understand roles and responsibilities",
		"reason": "CSF 1.1 PR.AT-05 (\"Physical and cybersecurity personnel understand their roles and responsibilities\") is withdrawn in CSF 2.0: Incorporated into PR.AT-02; this check tests part of a broader CSF 2.0 outcome, so it cannot decide PR.AT-02 on its own The predicate never emitted a violation.",
	},
	"PR.DS-03": {
		"csf_1_1_id": "PR.DS-03",
		"status": "retired",
		"csf_2_0_ids": ["ID.AM-08", "PR.PS-03"],
		"facts_read": ["input.data_security.asset_management.formal_processes", "input.data_security.asset_management.secure_disposal", "input.data_security.asset_management.transfer_procedures"],
		"legacy_message": "Assets not formally managed through removal/transfer/disposition",
		"reason": "CSF 1.1 PR.DS-03 (\"Assets are formally managed throughout removal, transfers, and disposition\") is withdrawn in CSF 2.0: Incorporated into ID.AM-08, PR.PS-03; this check its outcome is spread over 2 CSF 2.0 elements, so it cannot be attributed to one subcategory",
	},
	"PR.DS-05": {
		"csf_1_1_id": "PR.DS-05",
		"status": "retired",
		"csf_2_0_ids": ["PR.DS-01", "PR.DS-02", "PR.DS-10"],
		"facts_read": ["input.data_security.leak_prevention.dlp_tools_deployed", "input.data_security.leak_prevention.monitoring_implemented", "input.data_security.leak_prevention.response_procedures"],
		"legacy_message": "Data-leak protections not implemented",
		"reason": "CSF 1.1 PR.DS-05 (\"Protections against data leaks are implemented\") is withdrawn in CSF 2.0: Incorporated into PR.DS-01, PR.DS-02, PR.DS-10; this check its outcome is spread over 3 CSF 2.0 elements, so it cannot be attributed to one subcategory",
	},
	"PR.DS-06": {
		"csf_1_1_id": "PR.DS-06",
		"status": "retired",
		"csf_2_0_ids": ["PR.DS-01", "DE.CM-09"],
		"facts_read": ["input.data_security.integrity.verification_mechanisms", "input.data_security.integrity.regular_validation", "input.data_security.integrity.automated_monitoring"],
		"legacy_message": "Integrity-checking mechanisms not used on software/firmware/data",
		"reason": "CSF 1.1 PR.DS-06 (\"Integrity checking mechanisms are used to verify software, firmware, and information integrity\") is withdrawn in CSF 2.0: Incorporated into PR.DS-01, DE.CM-09; this check its outcome is spread over 2 CSF 2.0 elements, so it cannot be attributed to one subcategory",
	},
	"PR.DS-07": {
		"csf_1_1_id": "PR.DS-07",
		"status": "retired",
		"csf_2_0_ids": ["PR.IR-01"],
		"facts_read": ["input.data_security.environments.dev_prod_separation", "input.data_security.environments.test_isolation", "input.data_security.environments.secure_transitions"],
		"legacy_message": "The development and testing environment(s) are separate from the production environment",
		"reason": "CSF 1.1 PR.DS-07 (\"The development and testing environment(s) are separate from the production environment\") is withdrawn in CSF 2.0: Incorporated into PR.IR-01; this check tests part of a broader CSF 2.0 outcome, so it cannot decide PR.IR-01 on its own The predicate never emitted a violation.",
	},
	"PR.DS-08": {
		"csf_1_1_id": "PR.DS-08",
		"status": "retired",
		"csf_2_0_ids": ["ID.RA-09", "DE.CM-09"],
		"facts_read": ["input.data_security.hardware.integrity_verification", "input.data_security.hardware.trusted_hardware", "input.data_security.hardware.supply_chain_verification"],
		"legacy_message": "Integrity checking mechanisms are used to verify hardware integrity",
		"reason": "CSF 1.1 PR.DS-08 (\"Integrity checking mechanisms are used to verify hardware integrity\") is withdrawn in CSF 2.0: Incorporated into ID.RA-09, DE.CM-09; this check its outcome is spread over 2 CSF 2.0 elements, so it cannot be attributed to one subcategory The predicate never emitted a violation.",
	},
	"PR.IP-01": {
		"csf_1_1_id": "PR.IP-01",
		"status": "retired",
		"csf_2_0_ids": ["PR.PS-01"],
		"facts_read": ["input.information_protection.configuration.baseline_established", "input.information_protection.configuration.regularly_updated", "input.information_protection.configuration.version_controlled"],
		"legacy_message": "Baseline configuration not created/maintained",
		"reason": "CSF 1.1 PR.IP-01 (\"A baseline configuration of information technology/industrial control systems is created and maintained incorporating security principles (e.g. concept of least functionality)\") is withdrawn in CSF 2.0: Incorporated into PR.PS-01; this check tests part of a broader CSF 2.0 outcome, so it cannot decide PR.PS-01 on its own",
	},
	"PR.IP-02": {
		"csf_1_1_id": "PR.IP-02",
		"status": "retired",
		"csf_2_0_ids": ["ID.AM-08", "PR.PS-06"],
		"facts_read": ["input.information_protection.sdlc.formal_process", "input.information_protection.sdlc.security_integrated", "input.information_protection.sdlc.documentation_maintained"],
		"legacy_message": "A System Development Life Cycle to manage systems is implemented",
		"reason": "CSF 1.1 PR.IP-02 (\"A System Development Life Cycle to manage systems is implemented\") is withdrawn in CSF 2.0: Incorporated into ID.AM-08, PR.PS-06; this check its outcome is spread over 2 CSF 2.0 elements, so it cannot be attributed to one subcategory The predicate never emitted a violation.",
	},
	"PR.IP-03": {
		"csf_1_1_id": "PR.IP-03",
		"status": "retired",
		"csf_2_0_ids": ["PR.PS-01", "ID.RA-07"],
		"facts_read": ["input.information_protection.change_control.formal_process", "input.information_protection.change_control.approval_required", "input.information_protection.change_control.documentation_maintained"],
		"legacy_message": "Configuration change control processes are in place",
		"reason": "CSF 1.1 PR.IP-03 (\"Configuration change control processes are in place\") is withdrawn in CSF 2.0: Incorporated into PR.PS-01, ID.RA-07; this check its outcome is spread over 2 CSF 2.0 elements, so it cannot be attributed to one subcategory The predicate never emitted a violation.",
	},
}
