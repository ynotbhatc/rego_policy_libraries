# SOC 2 Trust Service Criteria - Confidentiality (C1.0)
# Data Confidentiality and Protection Controls

# METADATA
# title: "SOC 2 Trust Service Criteria - Confidentiality (C1.0)"
# custom:
#   class: compliance
#   framework: soc2
#   source: aicpa
#   domains: [assurance]
#   coverage:
#     checks: 20
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package soc2.confidentiality.data_confidentiality

import rego.v1

# =================================================================
# C1.1 - Confidentiality - Information is Protected
# =================================================================

# Data classification system is implemented
default data_classification_implemented := false

data_classification_implemented if {
    input.data_classification.system_defined == true
    input.data_classification.categories.public.defined == true
    input.data_classification.categories.internal.defined == true
    input.data_classification.categories.confidential.defined == true
    input.data_classification.categories.restricted.defined == true
}

# Access controls based on data classification
default classification_based_access_controls := false

classification_based_access_controls if {
    input.data_classification.access_controls.role_based == true
    input.data_classification.access_controls.need_to_know == true
    input.data_classification.access_controls.regular_reviews == true
}

# Data handling procedures are documented
default data_handling_procedures_documented := false

data_handling_procedures_documented if {
    input.data_handling.procedures.documented == true
    input.data_handling.procedures.training_provided == true
    input.data_handling.procedures.compliance_monitoring == true
}

# =================================================================
# C1.2 - Confidentiality - Information is Protected in Transit
# =================================================================

# TLS version as a number. Accepts 1.2 / "1.2" / "TLSv1.2" / "TLS 1.3"; a plain `>= 1.2` would
# let any string through because OPA orders strings above numbers. Undefined when unparsable.
tls_version_number(v) := v if is_number(v)

tls_version_number(v) := to_number(m[0][1]) if {
    is_string(v)
    m := regex.find_all_string_submatch_n(`(\d+\.\d+)`, v, 1)
}

tls_at_least_1_2(v) if tls_version_number(v) >= 1.2

# Encryption in transit is implemented
default encryption_in_transit := false

encryption_in_transit if {
    input.encryption.in_transit.enabled == true
    tls_at_least_1_2(input.encryption.in_transit.protocols.tls_version)
    input.encryption.in_transit.cipher_suites.strong_only == true
    input.encryption.in_transit.certificate_management.automated == true
}

# Network security controls for data transmission
default network_transmission_security := false

network_transmission_security if {
    input.network_security.vpn.required_for_remote_access == true
    input.network_security.network_segmentation.enabled == true
    input.network_security.firewalls.configured == true
    input.network_security.intrusion_detection.enabled == true
}

# API security for data transmission
default api_transmission_security := false

api_transmission_security if {
    input.apis.authentication.required == true
    input.apis.authorization.implemented == true
    input.apis.encryption.https_only == true
    input.apis.rate_limiting.enabled == true
}

# =================================================================
# C1.3 - Confidentiality - Information is Protected at Rest
# =================================================================

# Encryption at rest is implemented
default encryption_at_rest := false

encryption_at_rest if {
    input.encryption.at_rest.enabled == true
    input.encryption.at_rest.algorithm.strength >= 256  # AES-256 or equivalent
    input.encryption.at_rest.key_management.centralized == true
    input.encryption.at_rest.database_encryption == true
}

# File system encryption is configured
default filesystem_encryption := false

filesystem_encryption if {
    input.storage.filesystem.encryption.enabled == true
    input.storage.filesystem.encryption.full_disk == true
    input.storage.removable_media.encryption.required == true
}

# Database security controls
default database_confidentiality := false

database_confidentiality if {
    input.databases.encryption.transparent_data_encryption == true
    input.databases.access_controls.column_level_encryption == true
    input.databases.access_controls.view_based_access == true
    input.databases.auditing.access_logging == true
}

# =================================================================
# OpenShift/Kubernetes Confidentiality Controls
# =================================================================

# Secrets management in OpenShift
default openshift_secrets_management := false

openshift_secrets_management if {
    input.openshift.secrets.external_secret_management == true
    input.openshift.secrets.encryption_at_rest == true
    input.openshift.secrets.rbac_controlled == true
    input.openshift.secrets.rotation_policy.enabled == true
}

# Pod security for confidentiality
default pod_confidentiality_controls := false

pod_confidentiality_controls if {
    input.openshift.pods.security_context.non_root == true
    input.openshift.pods.security_context.read_only_filesystem == true
    input.openshift.pods.resource_isolation.enabled == true
    input.openshift.pods.network_policies.deny_all_default == true
}

# Container image security
default container_image_confidentiality := false

container_image_confidentiality if {
    input.openshift.images.vulnerability_scanning == true
    input.openshift.images.trusted_registries_only == true
    input.openshift.images.image_signing.required == true
    input.openshift.images.base_image_minimal == true
}

# Service mesh confidentiality
default service_mesh_confidentiality := false

service_mesh_confidentiality if {
    input.openshift.service_mesh.mtls.enabled == true
    input.openshift.service_mesh.encryption.automatic == true
    input.openshift.service_mesh.traffic_policies.encryption_required == true
}

# =================================================================
# Data Loss Prevention
# =================================================================

# Data loss prevention controls
default data_loss_prevention := false

data_loss_prevention if {
    input.dlp.monitoring.enabled == true
    input.dlp.policies.data_classification_based == true
    input.dlp.detection.content_inspection == true
    input.dlp.response.automatic_blocking == true
}

# Email and communication security
default communication_security := false

communication_security if {
    input.communication.email.encryption_required == true
    input.communication.messaging.end_to_end_encryption == true
    input.communication.file_sharing.controlled_platforms == true
}

# Mobile device management
default mobile_device_management := false

mobile_device_management if {
    input.mobile_devices.mdm_enrollment.required == true
    input.mobile_devices.encryption.device_level == true
    input.mobile_devices.remote_wipe.capability == true
    input.mobile_devices.app_management.controlled == true
}

# =================================================================
# Data Retention and Disposal
# =================================================================

# Data retention policies are implemented
default data_retention_implemented := false

data_retention_implemented if {
    input.data_retention.policies.documented == true
    input.data_retention.policies.classification_based == true
    input.data_retention.policies.automated_enforcement == true
}

# Secure data disposal procedures
default secure_data_disposal := false

secure_data_disposal if {
    input.data_disposal.procedures.documented == true
    input.data_disposal.methods.cryptographic_erasure == true
    input.data_disposal.verification.completion_verified == true
    input.data_disposal.media_destruction.certified == true
}

# =================================================================
# Access Monitoring and Logging
# =================================================================

# Confidential data access is logged
default confidential_data_access_logged := false

confidential_data_access_logged if {
    input.access_logging.confidential_data.enabled == true
    input.access_logging.confidential_data.detailed == true
    input.access_logging.confidential_data.real_time_monitoring == true
    input.access_logging.confidential_data.retention_period >= 365
}

# Anomaly detection for data access
default data_access_anomaly_detection := false

data_access_anomaly_detection if {
    input.anomaly_detection.unusual_access_patterns == true
    input.anomaly_detection.privileged_user_monitoring == true
    input.anomaly_detection.data_exfiltration_detection == true
    input.anomaly_detection.automated_alerts == true
}

# =================================================================
# Overall Confidentiality Assessment
# =================================================================

default confidentiality_controls_compliant := false

confidentiality_controls_compliant if {
    data_classification_implemented
    classification_based_access_controls
    data_handling_procedures_documented
    encryption_in_transit
    network_transmission_security
    api_transmission_security
    encryption_at_rest
    filesystem_encryption
    database_confidentiality
}

default openshift_confidentiality_compliant := false

openshift_confidentiality_compliant if {
    openshift_secrets_management
    pod_confidentiality_controls
    container_image_confidentiality
    service_mesh_confidentiality
}

default dlp_controls_compliant := false

dlp_controls_compliant if {
    data_loss_prevention
    communication_security
    mobile_device_management
}

default data_lifecycle_compliant := false

data_lifecycle_compliant if {
    data_retention_implemented
    secure_data_disposal
}

default monitoring_compliant := false

monitoring_compliant if {
    confidential_data_access_logged
    data_access_anomaly_detection
}

default overall_confidentiality_compliant := false

overall_confidentiality_compliant if {
    confidentiality_controls_compliant
    openshift_confidentiality_compliant
    dlp_controls_compliant
    data_lifecycle_compliant
    monitoring_compliant
}

# =================================================================
# Confidentiality Score Calculation
# =================================================================

confidentiality_score := score if {
    controls := [
        data_classification_implemented,
        classification_based_access_controls,
        data_handling_procedures_documented,
        encryption_in_transit,
        network_transmission_security,
        api_transmission_security,
        encryption_at_rest,
        filesystem_encryption,
        database_confidentiality,
        openshift_secrets_management,
        pod_confidentiality_controls,
        container_image_confidentiality,
        service_mesh_confidentiality,
        data_loss_prevention,
        communication_security,
        mobile_device_management,
        data_retention_implemented,
        secure_data_disposal,
        confidential_data_access_logged,
        data_access_anomaly_detection
    ]
    
    passed := count([control | control := controls[_]; control == true])
    total := count(controls)
    score := (passed / total) * 100
}

# =================================================================
# Detailed Findings
# =================================================================

confidentiality_findings := findings if {
    findings := {
        "data_classification_implemented": data_classification_implemented,
        "classification_based_access_controls": classification_based_access_controls,
        "data_handling_procedures_documented": data_handling_procedures_documented,
        "encryption_in_transit": encryption_in_transit,
        "network_transmission_security": network_transmission_security,
        "api_transmission_security": api_transmission_security,
        "encryption_at_rest": encryption_at_rest,
        "filesystem_encryption": filesystem_encryption,
        "database_confidentiality": database_confidentiality,
        "openshift_secrets_management": openshift_secrets_management,
        "pod_confidentiality_controls": pod_confidentiality_controls,
        "container_image_confidentiality": container_image_confidentiality,
        "service_mesh_confidentiality": service_mesh_confidentiality,
        "data_loss_prevention": data_loss_prevention,
        "communication_security": communication_security,
        "mobile_device_management": mobile_device_management,
        "data_retention_implemented": data_retention_implemented,
        "secure_data_disposal": secure_data_disposal,
        "confidential_data_access_logged": confidential_data_access_logged,
        "data_access_anomaly_detection": data_access_anomaly_detection,
        "overall_score": confidentiality_score
    }
}