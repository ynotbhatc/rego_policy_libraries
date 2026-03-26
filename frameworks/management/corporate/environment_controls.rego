package corporate.environment.controls

import rego.v1

# Environment Control Policies for Development, QA, and Production
# Enforces separation of duties, data protection, and access controls across environments

# Main environment controls compliance
environment_controls_compliant if {
    environment_separation_enforced
    data_flow_controls_compliant
    access_segregation_compliant
    deployment_controls_compliant
    monitoring_controls_compliant
}

# Environment Separation Enforcement
# Corporate Policy: "Development, QA, and Production must be logically and physically separated"
environment_separation_enforced if {
    network_separation_adequate
    infrastructure_separation_adequate
    data_separation_adequate
}

network_separation_adequate if {
    # Verify each environment has separate network segments
    environments := {"development", "qa", "production"}
    every env in environments {
        other_env := environments[_]
        env != other_env
        env_config := input.environments[env]
        env_config.network.vlan_id != input.environments[other_env].network.vlan_id
    }
}

infrastructure_separation_adequate if {
    # Verify production uses dedicated infrastructure
    input.environments.production.infrastructure.shared == false
    input.environments.production.infrastructure.dedicated_hosts == true
    
    # Development and QA may share infrastructure but not with production
    not infrastructure_overlap_with_production
}

infrastructure_overlap_with_production if {
    prod_hosts := {host | host := input.environments.production.infrastructure.hosts[_]}
    non_prod_hosts := {host | 
        env := ["development", "qa"][_]
        host := input.environments[env].infrastructure.hosts[_]
    }
    count(prod_hosts & non_prod_hosts) > 0
}

data_separation_adequate if {
    # Production data never in non-production environments (unless masked/anonymized)
    production_data_isolated
    non_production_data_properly_handled
}

production_data_isolated if {
    # No production data in development or QA without proper controls
    violations := [violation |
        env := ["development", "qa"][_]
        env_config := input.environments[env]
        datasource := env_config.data_sources[_]
        datasource.contains_production_data == true
        not datasource.data_masked == true
        not datasource.data_anonymized == true
        violation := {
            "environment": env,
            "datasource": datasource.name,
            "issue": "production_data_without_masking"
        }
    ]
    count(violations) == 0
}

non_production_data_properly_handled if {
    # All non-production data sources have appropriate controls
    every env in ["development", "qa"] {
        env_config := input.environments[env]
        every datasource in env_config.data_sources {
            datasource_controls_adequate(datasource)
        }
    }
}

datasource_controls_adequate(datasource) if {
    datasource.contains_production_data == false
}

datasource_controls_adequate(datasource) if {
    datasource.contains_production_data == true
    datasource.data_masked == true
    datasource.masking_method in ["tokenization", "anonymization", "synthetic"]
}

# Data Flow Controls
# Corporate Policy: "Data flows between environments must be controlled and audited"
data_flow_controls_compliant if {
    allowed_data_flows_only
    data_flow_monitoring_enabled
    data_flow_approval_required
}

allowed_data_flows_only if {
    # Only specific data flows are permitted
    violations := [flow |
        flow := input.data_flows[_]
        not data_flow_permitted(flow)
    ]
    count(violations) == 0
}

data_flow_permitted(flow) if {
    # Development to QA: Allowed with approval
    flow.source_environment == "development"
    flow.destination_environment == "qa"
    flow.approval_status == "approved"
}

data_flow_permitted(flow) if {
    # QA to Production: Only for approved releases
    flow.source_environment == "qa"
    flow.destination_environment == "production"
    flow.flow_type == "application_deployment"
    flow.approval_status == "approved"
    flow.change_control_number
}

data_flow_permitted(flow) if {
    # Production to QA: Only for debugging (with data masking)
    flow.source_environment == "production"
    flow.destination_environment == "qa"
    flow.data_masked == true
    flow.approval_status == "approved"
    flow.purpose == "debugging"
}

# Never allow: Production to Development, or any reverse data flows
data_flow_permitted(flow) if {
    flow.source_environment == "production"
    flow.destination_environment == "development"
    false  # Never permitted
}

data_flow_monitoring_enabled if {
    every flow in input.data_flows {
        flow.monitoring.enabled == true
        flow.monitoring.audit_logging == true
    }
}

data_flow_approval_required if {
    violations := [flow |
        flow := input.data_flows[_]
        not flow_approval_adequate(flow)
    ]
    count(violations) == 0
}

flow_approval_adequate(flow) if {
    flow.approval_status == "approved"
    flow.approved_by
    flow.approval_date
    approval_age_days := (time.now_ns() - flow.approval_date) / (24 * 60 * 60 * 1000000000)
    approval_age_days <= max_approval_age_days(flow)
}

max_approval_age_days(flow) := 30 if {
    flow.destination_environment == "production"
}

max_approval_age_days(flow) := 90 if {
    flow.destination_environment in ["development", "qa"]
}

# Access Segregation
# Corporate Policy: "Personnel access must be segregated by environment and role"
access_segregation_compliant if {
    role_based_access_enforced
    segregation_of_duties_maintained
    privileged_access_controlled
    temporary_access_managed
}

role_based_access_enforced if {
    # Each user has appropriate roles for each environment
    violations := [violation |
        user := input.users[_]
        env := ["development", "qa", "production"][_]
        user_env_access := user.environment_access[env]
        user_env_access  # User has access to this environment
        not role_appropriate_for_environment(user, env)
        violation := {
            "user_id": user.id,
            "environment": env,
            "current_roles": user_env_access.roles,
            "issue": "inappropriate_role_for_environment"
        }
    ]
    count(violations) == 0
}

role_appropriate_for_environment(user, "production") if {
    # Production access requires specific authorization
    user.environment_access.production.authorized == true
    user.environment_access.production.business_justification
    every role in user.environment_access.production.roles {
        role in allowed_production_roles
    }
}

role_appropriate_for_environment(user, env) if {
    env in ["development", "qa"]
    # Development and QA have more flexible access but still controlled
    user.environment_access[env].authorized == true
}

allowed_production_roles := {
    "production_deployer", "production_monitor", "production_support",
    "database_admin", "security_admin", "compliance_auditor"
}

segregation_of_duties_maintained if {
    # No single user can both develop and deploy to production
    violations := [user |
        user := input.users[_]
        user.environment_access.development.roles[_] in ["developer", "dev_admin"]
        user.environment_access.production.roles[_] in ["production_deployer", "production_admin"]
    ]
    count(violations) == 0
}

privileged_access_controlled if {
    # Privileged access requires additional controls
    violations := [violation |
        user := input.users[_]
        env := ["development", "qa", "production"][_]
        user_env_access := user.environment_access[env]
        privileged_role := [role | 
            role := user_env_access.roles[_]
            role in privileged_roles
        ][_]
        not privileged_access_controls_adequate(user, env, privileged_role)
        violation := {
            "user_id": user.id,
            "environment": env,
            "privileged_role": privileged_role,
            "issue": "inadequate_privileged_access_controls"
        }
    ]
    count(violations) == 0
}

privileged_roles := {
    "admin", "root", "database_admin", "security_admin", 
    "production_admin", "system_admin", "network_admin"
}

privileged_access_controls_adequate(user, env, role) if {
    user_access := user.environment_access[env]
    user_access.mfa_enabled == true
    user_access.session_recording == true
    user_access.approval_workflow == true
    user_access.access_review_frequency <= privileged_review_frequency(env)
}

privileged_review_frequency("production") := 30  # 30 days
privileged_review_frequency("qa") := 60         # 60 days
privileged_review_frequency("development") := 90 # 90 days

temporary_access_managed if {
    # All temporary access has expiration and justification
    violations := [access |
        user := input.users[_]
        env := ["development", "qa", "production"][_]
        access := user.environment_access[env]
        access.access_type == "temporary"
        not temporary_access_valid(access)
    ]
    count(violations) == 0
}

temporary_access_valid(access) if {
    access.expiration_date
    expiration_ns := time.parse_rfc3339_ns(access.expiration_date)
    expiration_ns > time.now_ns()
    access.business_justification
    access.approver
}

# Deployment Controls
# Corporate Policy: "Code deployment must follow change control procedures"
deployment_controls_compliant if {
    change_control_enforced
    automated_deployment_pipelines
    rollback_procedures_available
    deployment_authorization_required
}

change_control_enforced if {
    # All production deployments have change control tickets
    violations := [deployment |
        deployment := input.deployments[_]
        deployment.target_environment == "production"
        not change_control_adequate(deployment)
    ]
    count(violations) == 0
}

change_control_adequate(deployment) if {
    deployment.change_control.ticket_number
    deployment.change_control.approver
    deployment.change_control.risk_assessment == "completed"
    deployment.change_control.rollback_plan == "approved"
}

automated_deployment_pipelines if {
    # All environments use automated deployment pipelines
    every env in ["development", "qa", "production"] {
        env_config := input.environments[env]
        env_config.deployment.automated == true
        env_config.deployment.pipeline.source_control_integration == true
        env_config.deployment.pipeline.automated_testing == true
    }
}

rollback_procedures_available if {
    # All deployments have tested rollback procedures
    violations := [deployment |
        deployment := input.deployments[_]
        not rollback_procedure_adequate(deployment)
    ]
    count(violations) == 0
}

rollback_procedure_adequate(deployment) if {
    deployment.rollback.procedure_documented == true
    deployment.rollback.tested == true
    deployment.rollback.automated == true
    deployment.rollback.rto_minutes <= max_rollback_time(deployment.target_environment)
}

max_rollback_time("production") := 30    # 30 minutes
max_rollback_time("qa") := 60           # 60 minutes
max_rollback_time("development") := 120  # 120 minutes

deployment_authorization_required if {
    # Deployment authorization based on environment
    violations := [deployment |
        deployment := input.deployments[_]
        not deployment_authorization_adequate(deployment)
    ]
    count(violations) == 0
}

deployment_authorization_adequate(deployment) if {
    deployment.target_environment == "development"
    deployment.authorization.developer_approval == true
}

deployment_authorization_adequate(deployment) if {
    deployment.target_environment == "qa"
    deployment.authorization.qa_lead_approval == true
    deployment.authorization.security_review == "completed"
}

deployment_authorization_adequate(deployment) if {
    deployment.target_environment == "production"
    deployment.authorization.change_board_approval == true
    deployment.authorization.security_review == "completed"
    deployment.authorization.business_approval == true
    deployment.authorization.technical_approval == true
}

# Monitoring Controls
# Corporate Policy: "All environments must have appropriate monitoring and alerting"
monitoring_controls_compliant if {
    environment_monitoring_configured
    security_monitoring_enabled
    compliance_monitoring_active
    incident_response_procedures
}

environment_monitoring_configured if {
    # Each environment has monitoring appropriate to its criticality
    every env in ["development", "qa", "production"] {
        env_config := input.environments[env]
        monitoring_adequate_for_environment(env_config, env)
    }
}

monitoring_adequate_for_environment(env_config, "production") if {
    env_config.monitoring.availability_monitoring == true
    env_config.monitoring.performance_monitoring == true
    env_config.monitoring.security_monitoring == true
    env_config.monitoring.compliance_monitoring == true
    env_config.monitoring.alert_escalation == true
    env_config.monitoring.sla_monitoring == true
}

monitoring_adequate_for_environment(env_config, env) if {
    env in ["development", "qa"]
    env_config.monitoring.availability_monitoring == true
    env_config.monitoring.performance_monitoring == true
    env_config.monitoring.security_monitoring == true
}

security_monitoring_enabled if {
    # Security monitoring for access, changes, and anomalies
    every env in ["development", "qa", "production"] {
        env_config := input.environments[env]
        env_config.security_monitoring.access_logging == true
        env_config.security_monitoring.change_detection == true
        env_config.security_monitoring.anomaly_detection == true
    }
}

compliance_monitoring_active if {
    # Compliance monitoring tracks policy violations
    every env in ["development", "qa", "production"] {
        env_config := input.environments[env]
        env_config.compliance_monitoring.policy_violations == true
        env_config.compliance_monitoring.access_reviews == true
        env_config.compliance_monitoring.audit_logging == true
    }
}

incident_response_procedures if {
    # Incident response procedures exist and are tested
    every env in ["development", "qa", "production"] {
        env_config := input.environments[env]
        env_config.incident_response.procedures_documented == true
        env_config.incident_response.contact_list_current == true
        env_config.incident_response.escalation_matrix == true
        incident_response_tested(env_config, env)
    }
}

incident_response_tested(env_config, env) if {
    test_age_days := (time.now_ns() - env_config.incident_response.last_test_date) / (24 * 60 * 60 * 1000000000)
    test_age_days <= incident_response_test_frequency(env)
}

incident_response_test_frequency("production") := 90   # Quarterly
incident_response_test_frequency("qa") := 180         # Semi-annually
incident_response_test_frequency("development") := 365 # Annually

# Environment Control Violations
environment_violations := violations if {
    violations := array.concat(
        separation_violations,
        array.concat(access_violations,
        array.concat(deployment_violations, monitoring_violations))
    )
}

separation_violations := [violation |
    not network_separation_adequate
    violation := {
        "type": "network_separation",
        "severity": "critical",
        "description": "Network separation between environments is inadequate",
        "remediation": "Implement separate VLANs/subnets for each environment"
    }
]

access_violations := [violation |
    user := input.users[_]
    env := ["development", "qa", "production"][_]
    user.environment_access[env]
    not role_appropriate_for_environment(user, env)
    violation := {
        "type": "inappropriate_access",
        "severity": "high",
        "user_id": user.id,
        "environment": env,
        "description": sprintf("User %s has inappropriate access to %s environment", [user.id, env]),
        "remediation": "Review and adjust user access permissions"
    }
]

deployment_violations := [violation |
    deployment := input.deployments[_]
    deployment.target_environment == "production"
    not change_control_adequate(deployment)
    violation := {
        "type": "deployment_control",
        "severity": "critical",
        "deployment_id": deployment.id,
        "description": "Production deployment lacks proper change control",
        "remediation": "Implement change control procedures for all production deployments"
    }
]

monitoring_violations := [violation |
    env := ["development", "qa", "production"][_]
    env_config := input.environments[env]
    not monitoring_adequate_for_environment(env_config, env)
    violation := {
        "type": "monitoring_inadequate",
        "severity": "medium",
        "environment": env,
        "description": sprintf("Monitoring for %s environment is inadequate", [env]),
        "remediation": "Implement comprehensive monitoring for all required areas"
    }
]

# Environment Control Score
environment_control_score := score if {
    total_checks := 5
    passed_checks := count([check |
        checks := [
            environment_separation_enforced,
            data_flow_controls_compliant,
            access_segregation_compliant,
            deployment_controls_compliant,
            monitoring_controls_compliant
        ]
        check := checks[_]
        check == true
    ])
    score := (passed_checks * 100) / total_checks
}

# Compliance Framework Mapping
sox_environment_controls_compliant if {
    environment_controls_compliant
    # Additional SOX-specific requirements
    segregation_of_duties_maintained
    every deployment in input.deployments {
        deployment.target_environment == "production"
        "financial_reporting" in deployment.impact_areas
        deployment.authorization.change_board_approval == true
    }
}

pci_dss_environment_controls_compliant if {
    environment_controls_compliant
    # Additional PCI DSS requirements for cardholder data environment
    every env in ["development", "qa", "production"] {
        env_config := input.environments[env]
        "cardholder_data" in env_config.data_types
        env_config.network.cardholder_data_environment == true
        env_config.security_monitoring.data_access_logging == true
    }
}

# Policy Metadata
environment_control_metadata := {
    "policy_name": "Environment Control Policy",
    "version": "1.4",
    "effective_date": "2025-01-01",
    "last_updated": "2025-10-05",
    "policy_owner": "Chief Technology Officer",
    "compliance_frameworks": ["SOX", "PCI DSS", "ISO 27001", "COBIT"],
    "enforcement_level": "mandatory",
    "review_frequency": "semi_annual",
    "exception_approval_required": true
}