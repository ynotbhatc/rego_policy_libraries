package ami.nist_ir7628.system_comms

import rego.v1

# NIST IR 7628 Rev 1 - Smart Grid Cybersecurity
# Control Family: SG.SC - System and Communications Protection
# Scope: AMI RF mesh network, backhaul communications, head-end interfaces

# Allowed TLS versions — TLS 1.2 minimum
allowed_tls_versions := {"TLS_1.2", "TLS_1.3"}

# Prohibited cipher suites (weak or broken)
prohibited_ciphers := {
    "DES", "3DES", "RC4", "RC2", "NULL",
    "MD5", "SHA1", "EXPORT", "ANON",
    "SSL_3.0", "TLS_1.0", "TLS_1.1",
}

# Minimum key sizes by algorithm
minimum_key_sizes := {
    "RSA": 2048,
    "ECDSA": 256,
    "AES": 128,
    "HMAC_SHA": 256,
}

# SG.SC-1: System and Communications Protection Policy
comms_policy_documented if {
    input.system_comms.policy.documented == true
    input.system_comms.policy.approved == true
}

# SG.SC-4: Information in Shared Resources
# AMI networks must be segmented from corporate IT and public internet
network_segmentation_enforced if {
    input.system_comms.network.ot_it_segmented == true
    input.system_comms.network.ami_isolated_from_internet == true
    input.system_comms.network.firewall_between_zones == true
}

# SG.SC-8: Transmission Confidentiality and Integrity
# All AMI data in transit must use approved TLS versions
tls_version_compliant if {
    input.system_comms.encryption.tls_version in allowed_tls_versions
}

no_prohibited_ciphers_enabled if {
    configured := {cipher | cipher := input.system_comms.encryption.enabled_ciphers[_]}
    count(configured & prohibited_ciphers) == 0
}

# SG.SC-8: RF mesh network encryption
rf_mesh_encrypted if {
    input.system_comms.rf_mesh.encrypted == true
    input.system_comms.rf_mesh.encryption_algorithm in {"AES-128-CCM", "AES-256-CCM", "AES-128-GCM", "AES-256-GCM"}
}

# SG.SC-12: Cryptographic Key Management
# Keys must be managed with HSM or equivalent
key_management_secure if {
    input.system_comms.key_management.hsm_used == true
    input.system_comms.key_management.key_escrow_policy_defined == true
    input.system_comms.key_management.master_key_rotation_days <= 365
}

# SG.SC-17: Public Key Infrastructure Certificates
# AMI must use a trusted PKI hierarchy
pki_hierarchy_valid if {
    input.system_comms.pki.root_ca_offline == true
    input.system_comms.pki.intermediate_ca_online == true
    input.system_comms.pki.crl_or_ocsp_enabled == true
}

# SG.SC-28: Protection of Information At Rest
# Sensitive AMI data stored in MDMS must be encrypted
data_at_rest_encrypted if {
    input.system_comms.storage.mdms_encrypted == true
    input.system_comms.storage.encryption_algorithm in {"AES-256", "AES-128"}
    input.system_comms.storage.key_management_integrated == true
}

# Violations

violations contains msg if {
    not comms_policy_documented
    msg := "SG.SC-1: System and communications protection policy not documented or approved"
}

violations contains msg if {
    not network_segmentation_enforced
    msg := "SG.SC-4: AMI network not properly segmented from IT networks and internet"
}

violations contains msg if {
    not tls_version_compliant
    msg := sprintf("SG.SC-8: TLS version '%v' is not approved — use TLS 1.2 or TLS 1.3", [input.system_comms.encryption.tls_version])
}

violations contains msg if {
    not no_prohibited_ciphers_enabled
    bad := {cipher | cipher := input.system_comms.encryption.enabled_ciphers[_]; cipher in prohibited_ciphers}
    msg := sprintf("SG.SC-8: Prohibited cipher suites are enabled: %v", [bad])
}

violations contains msg if {
    not rf_mesh_encrypted
    msg := "SG.SC-8: RF mesh network does not use AES-based encryption (CCM or GCM mode required)"
}

violations contains msg if {
    not key_management_secure
    msg := "SG.SC-12: Cryptographic key management does not use HSM or lacks rotation policy"
}

violations contains msg if {
    not pki_hierarchy_valid
    msg := "SG.SC-17: PKI hierarchy invalid — offline root CA, online intermediate CA, and CRL/OCSP required"
}

violations contains msg if {
    not data_at_rest_encrypted
    msg := "SG.SC-28: MDMS data at rest is not encrypted with AES-128 or AES-256"
}

default compliant := false

compliant if {
    count(violations) == 0
}

compliance_report := {
    "control_family": "SG.SC",
    "framework": "NIST IR 7628 Rev 1",
    "controls_assessed": ["SG.SC-1", "SG.SC-4", "SG.SC-8", "SG.SC-12", "SG.SC-17", "SG.SC-28"],
    "total_violations": count(violations),
    "compliant": compliant,
    "violations": violations,
}
