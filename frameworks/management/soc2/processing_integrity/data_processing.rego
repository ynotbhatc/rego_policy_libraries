# SOC 2 Trust Service Criteria - Processing Integrity (PI1.0)
# Data Processing Integrity and Validation

package soc2.processing_integrity.data_processing

import rego.v1

# =================================================================
# PI1.1 - Processing Integrity - Data Processing is Complete and Accurate
# =================================================================

# Input validation controls are implemented
input_validation_implemented if {
    input.data_processing.input_validation.enabled == true
    input.data_processing.input_validation.data_type_checking == true
    input.data_processing.input_validation.range_checking == true
    input.data_processing.input_validation.format_validation == true
}

# Data integrity checks are performed
data_integrity_checks_active if {
    input.data_processing.integrity_checks.checksums.enabled == true
    input.data_processing.integrity_checks.digital_signatures.enabled == true
    input.data_processing.integrity_checks.hash_verification == true
}

# Error handling and logging is comprehensive
error_handling_comprehensive if {
    input.data_processing.error_handling.logging.enabled == true
    input.data_processing.error_handling.logging.detailed == true
    input.data_processing.error_handling.alerts.configured == true
    input.data_processing.error_handling.recovery_procedures.documented == true
}

# =================================================================
# PI1.2 - Processing Integrity - Data Processing is Authorized
# =================================================================

# Processing authorization is required
processing_authorization_required if {
    input.data_processing.authorization.required == true
    input.data_processing.authorization.approval_workflow == true
    input.data_processing.authorization.audit_trail == true
}

# System access for processing is controlled
processing_access_controlled if {
    input.data_processing.access_controls.role_based == true
    input.data_processing.access_controls.least_privilege == true
    input.data_processing.access_controls.regular_reviews == true
}

# Processing activities are monitored
processing_activities_monitored if {
    input.data_processing.monitoring.real_time == true
    input.data_processing.monitoring.anomaly_detection == true
    input.data_processing.monitoring.threshold_alerts == true
}

# =================================================================
# PI1.3 - Processing Integrity - Data Processing is Complete
# =================================================================

# Transaction completeness is verified
transaction_completeness_verified if {
    input.data_processing.transactions.sequence_checking == true
    input.data_processing.transactions.batch_totals == true
    input.data_processing.transactions.reconciliation.enabled == true
    input.data_processing.transactions.reconciliation.frequency_hours <= 24
}

# Data transmission integrity is maintained
data_transmission_integrity if {
    input.data_processing.transmission.encryption_in_transit == true
    input.data_processing.transmission.message_authentication == true
    input.data_processing.transmission.delivery_confirmation == true
}

# Processing queues are monitored
processing_queues_monitored if {
    input.data_processing.queues.monitoring.enabled == true
    input.data_processing.queues.dead_letter_handling == true
    input.data_processing.queues.retention_policies.defined == true
}

# =================================================================
# OpenShift/Kubernetes Processing Controls
# =================================================================

# Container workload integrity is maintained
container_workload_integrity if {
    input.openshift.workloads.image_verification.enabled == true
    input.openshift.workloads.admission_controllers.configured == true
    input.openshift.workloads.security_policies.enforced == true
}

# Data processing pipelines are secured
data_pipelines_secured if {
    input.openshift.pipelines.rbac_enabled == true
    input.openshift.pipelines.secrets_management.enabled == true
    input.openshift.pipelines.audit_logging == true
    input.openshift.pipelines.approval_gates.required == true
}

# Service mesh integrity controls
service_mesh_integrity if {
    input.openshift.service_mesh.enabled == true
    input.openshift.service_mesh.mtls_enabled == true
    input.openshift.service_mesh.traffic_policies.enforced == true
    input.openshift.service_mesh.observability.enabled == true
}

# =================================================================
# Application-Level Controls
# =================================================================

# API integrity controls are implemented
api_integrity_controls if {
    input.applications.apis.input_validation == true
    input.applications.apis.rate_limiting == true
    input.applications.apis.authentication_required == true
    input.applications.apis.response_validation == true
}

# Database transaction integrity
database_transaction_integrity if {
    input.databases.transactions.acid_compliance == true
    input.databases.transactions.rollback_capability == true
    input.databases.transactions.deadlock_detection == true
    input.databases.integrity_constraints.enforced == true
}

# Message processing integrity
message_processing_integrity if {
    input.messaging.exactly_once_delivery.enabled == true
    input.messaging.message_ordering.maintained == true
    input.messaging.duplicate_detection.enabled == true
    input.messaging.poison_message_handling == true
}

# =================================================================
# Data Quality and Validation
# =================================================================

# Data quality checks are performed
data_quality_checks_active if {
    input.data_quality.completeness_checks == true
    input.data_quality.consistency_checks == true
    input.data_quality.accuracy_validation == true
    input.data_quality.timeliness_validation == true
}

# Data lineage is tracked
data_lineage_tracked if {
    input.data_lineage.tracking.enabled == true
    input.data_lineage.transformation_logging == true
    input.data_lineage.source_attribution == true
}

# =================================================================
# Overall Processing Integrity Assessment
# =================================================================

processing_integrity_controls_compliant if {
    input_validation_implemented
    data_integrity_checks_active
    error_handling_comprehensive
    processing_authorization_required
    processing_access_controlled
    processing_activities_monitored
    transaction_completeness_verified
    data_transmission_integrity
    processing_queues_monitored
}

openshift_processing_compliant if {
    container_workload_integrity
    data_pipelines_secured
    service_mesh_integrity
}

application_controls_compliant if {
    api_integrity_controls
    database_transaction_integrity
    message_processing_integrity
}

data_quality_compliant if {
    data_quality_checks_active
    data_lineage_tracked
}

overall_processing_integrity_compliant if {
    processing_integrity_controls_compliant
    openshift_processing_compliant
    application_controls_compliant
    data_quality_compliant
}

# =================================================================
# Processing Integrity Score Calculation
# =================================================================

processing_integrity_score := score if {
    controls := [
        input_validation_implemented,
        data_integrity_checks_active,
        error_handling_comprehensive,
        processing_authorization_required,
        processing_access_controlled,
        processing_activities_monitored,
        transaction_completeness_verified,
        data_transmission_integrity,
        processing_queues_monitored,
        container_workload_integrity,
        data_pipelines_secured,
        service_mesh_integrity,
        api_integrity_controls,
        database_transaction_integrity,
        message_processing_integrity,
        data_quality_checks_active,
        data_lineage_tracked
    ]
    
    passed := count([control | control := controls[_]; control == true])
    total := count(controls)
    score := (passed / total) * 100
}

# =================================================================
# Detailed Findings
# =================================================================

processing_integrity_findings := findings if {
    findings := {
        "input_validation_implemented": input_validation_implemented,
        "data_integrity_checks_active": data_integrity_checks_active,
        "error_handling_comprehensive": error_handling_comprehensive,
        "processing_authorization_required": processing_authorization_required,
        "processing_access_controlled": processing_access_controlled,
        "processing_activities_monitored": processing_activities_monitored,
        "transaction_completeness_verified": transaction_completeness_verified,
        "data_transmission_integrity": data_transmission_integrity,
        "processing_queues_monitored": processing_queues_monitored,
        "container_workload_integrity": container_workload_integrity,
        "data_pipelines_secured": data_pipelines_secured,
        "service_mesh_integrity": service_mesh_integrity,
        "api_integrity_controls": api_integrity_controls,
        "database_transaction_integrity": database_transaction_integrity,
        "message_processing_integrity": message_processing_integrity,
        "data_quality_checks_active": data_quality_checks_active,
        "data_lineage_tracked": data_lineage_tracked,
        "overall_score": processing_integrity_score
    }
}