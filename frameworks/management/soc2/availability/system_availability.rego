# SOC 2 Trust Service Criteria - Availability (A1.0)
# System Availability and Performance Monitoring

package soc2.availability.system_availability

import rego.v1

# =================================================================
# A1.1 - Availability - System Availability Commitments
# =================================================================

# System availability meets service level commitments
availability_commitments_met if {
    input.availability.sla.target_uptime >= 99.9
    input.availability.current_uptime >= input.availability.sla.target_uptime
    input.availability.downtime_tracking.enabled == true
}

# Monitoring systems are in place
monitoring_systems_configured if {
    input.monitoring.infrastructure.enabled == true
    input.monitoring.application.enabled == true
    input.monitoring.alerts.configured == true
    input.monitoring.alerts.response_time_sla <= 15  # minutes
}

# Capacity planning is performed
capacity_planning_implemented if {
    input.capacity_management.monitoring.enabled == true
    input.capacity_management.thresholds.cpu_warning <= 80
    input.capacity_management.thresholds.memory_warning <= 85
    input.capacity_management.thresholds.storage_warning <= 90
    input.capacity_management.forecasting.enabled == true
}

# =================================================================
# A1.2 - Availability - System Operation and Maintenance
# =================================================================

# Preventive maintenance is scheduled
preventive_maintenance_scheduled if {
    input.maintenance.scheduled_windows.defined == true
    input.maintenance.change_management.process_documented == true
    input.maintenance.rollback_procedures.documented == true
    input.maintenance.testing.required_before_production == true
}

# Backup and recovery procedures are implemented
backup_recovery_implemented if {
    input.backup.automated_backups.enabled == true
    input.backup.frequency.daily == true
    input.backup.retention.days >= 30
    input.backup.recovery_testing.frequency_days <= 90
    input.backup.offsite_storage.enabled == true
}

# Incident response procedures are in place
incident_response_ready if {
    input.incident_response.procedures_documented == true
    input.incident_response.team_defined == true
    input.incident_response.escalation_matrix.defined == true
    input.incident_response.communication_plan.defined == true
}

# =================================================================
# OpenShift/Kubernetes Availability Controls
# =================================================================

# High availability is configured
openshift_ha_configured if {
    input.openshift.control_plane.replicas >= 3
    input.openshift.worker_nodes.count >= 3
    input.openshift.etcd.ha_configured == true
    input.openshift.load_balancer.configured == true
}

# Auto-scaling is implemented
auto_scaling_configured if {
    input.openshift.autoscaling.horizontal_pod_autoscaler.enabled == true
    input.openshift.autoscaling.cluster_autoscaler.enabled == true
    input.openshift.autoscaling.vertical_pod_autoscaler.enabled == true
}

# Pod disruption budgets are set
pod_disruption_budgets_set if {
    count(input.openshift.workloads) > 0
    workloads_with_pdb := [workload | 
        workload := input.openshift.workloads[_];
        workload.pod_disruption_budget.configured == true
    ]
    count(workloads_with_pdb) == count(input.openshift.workloads)
}

# Resource quotas and limits are enforced
resource_limits_enforced if {
    input.openshift.resource_management.quotas.enabled == true
    input.openshift.resource_management.limit_ranges.enabled == true
    count([workload | 
        workload := input.openshift.workloads[_];
        workload.resources.requests.defined == true;
        workload.resources.limits.defined == true
    ]) == count(input.openshift.workloads)
}

# Health checks are configured
health_checks_configured if {
    count([workload | 
        workload := input.openshift.workloads[_];
        workload.health_checks.readiness_probe.configured == true;
        workload.health_checks.liveness_probe.configured == true
    ]) == count(input.openshift.workloads)
}

# =================================================================
# Infrastructure Resilience
# =================================================================

# Multi-zone deployment is implemented
multi_zone_deployment if {
    input.infrastructure.zones.count >= 2
    input.infrastructure.load_balancing.cross_zone == true
    input.infrastructure.data_replication.cross_zone == true
}

# Network redundancy is in place
network_redundancy_implemented if {
    input.network.redundant_connections.count >= 2
    input.network.failover.automatic == true
    input.network.monitoring.enabled == true
}

# Storage redundancy is configured
storage_redundancy_configured if {
    input.storage.replication.enabled == true
    input.storage.replication.factor >= 2
    input.storage.backup.automated == true
    input.storage.snapshots.enabled == true
}

# =================================================================
# Performance Management
# =================================================================

# Performance monitoring is implemented
performance_monitoring_active if {
    input.performance.response_time.monitoring == true
    input.performance.throughput.monitoring == true
    input.performance.resource_utilization.monitoring == true
    input.performance.alerts.configured == true
}

# Performance thresholds are defined
performance_thresholds_defined if {
    input.performance.thresholds.response_time_ms <= 2000
    input.performance.thresholds.error_rate_percent <= 1
    input.performance.thresholds.cpu_utilization_percent <= 80
}

# =================================================================
# Overall Availability Assessment
# =================================================================

availability_controls_compliant if {
    availability_commitments_met
    monitoring_systems_configured
    capacity_planning_implemented
    preventive_maintenance_scheduled
    backup_recovery_implemented
    incident_response_ready
}

openshift_availability_compliant if {
    openshift_ha_configured
    auto_scaling_configured
    pod_disruption_budgets_set
    resource_limits_enforced
    health_checks_configured
}

infrastructure_resilient if {
    multi_zone_deployment
    network_redundancy_implemented
    storage_redundancy_configured
}

performance_managed if {
    performance_monitoring_active
    performance_thresholds_defined
}

overall_availability_compliant if {
    availability_controls_compliant
    openshift_availability_compliant
    infrastructure_resilient
    performance_managed
}

# =================================================================
# Availability Score Calculation
# =================================================================

availability_score := score if {
    controls := [
        availability_commitments_met,
        monitoring_systems_configured,
        capacity_planning_implemented,
        preventive_maintenance_scheduled,
        backup_recovery_implemented,
        incident_response_ready,
        openshift_ha_configured,
        auto_scaling_configured,
        pod_disruption_budgets_set,
        resource_limits_enforced,
        health_checks_configured,
        multi_zone_deployment,
        network_redundancy_implemented,
        storage_redundancy_configured,
        performance_monitoring_active,
        performance_thresholds_defined
    ]
    
    passed := count([control | control := controls[_]; control == true])
    total := count(controls)
    score := (passed / total) * 100
}

# =================================================================
# Detailed Findings
# =================================================================

availability_findings := findings if {
    findings := {
        "availability_commitments_met": availability_commitments_met,
        "monitoring_systems_configured": monitoring_systems_configured,
        "capacity_planning_implemented": capacity_planning_implemented,
        "preventive_maintenance_scheduled": preventive_maintenance_scheduled,
        "backup_recovery_implemented": backup_recovery_implemented,
        "incident_response_ready": incident_response_ready,
        "openshift_ha_configured": openshift_ha_configured,
        "auto_scaling_configured": auto_scaling_configured,
        "pod_disruption_budgets_set": pod_disruption_budgets_set,
        "resource_limits_enforced": resource_limits_enforced,
        "health_checks_configured": health_checks_configured,
        "multi_zone_deployment": multi_zone_deployment,
        "network_redundancy_implemented": network_redundancy_implemented,
        "storage_redundancy_configured": storage_redundancy_configured,
        "performance_monitoring_active": performance_monitoring_active,
        "performance_thresholds_defined": performance_thresholds_defined,
        "overall_score": availability_score
    }
}