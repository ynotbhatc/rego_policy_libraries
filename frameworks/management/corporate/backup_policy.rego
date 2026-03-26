package corporate.backup

import rego.v1

# Corporate Backup and Recovery Policy Implementation
# Validates backup procedures, retention, testing, and recovery capabilities

# Main backup policy compliance evaluation
backup_compliant if {
    backup_schedule_compliant
    retention_policy_compliant
    backup_testing_compliant
    recovery_procedures_compliant
    backup_security_compliant
    offsite_backup_compliant
}

# Backup Schedule Compliance
# Corporate Policy: "Critical systems daily, important systems weekly, standard systems monthly"
backup_schedule_compliant if {
    all_systems_have_backup_schedule
    backup_frequencies_meet_requirements
    backup_windows_appropriate
}

all_systems_have_backup_schedule if {
    count(input.systems) > 0
    count([system | 
        system := input.systems[_]
        not system.backup_config.schedule
    ]) == 0
}

backup_frequencies_meet_requirements if {
    violations := [system |
        system := input.systems[_]
        not backup_frequency_adequate(system)
    ]
    count(violations) == 0
}

backup_frequency_adequate(system) if {
    system.criticality_level == "critical"
    system.backup_config.frequency in ["daily", "twice_daily", "continuous"]
}

backup_frequency_adequate(system) if {
    system.criticality_level == "important"
    system.backup_config.frequency in ["daily", "weekly"]
}

backup_frequency_adequate(system) if {
    system.criticality_level == "standard"
    system.backup_config.frequency in ["daily", "weekly", "monthly"]
}

backup_frequency_adequate(system) if {
    system.criticality_level == "low"
    system.backup_config.frequency in ["weekly", "monthly", "quarterly"]
}

backup_windows_appropriate if {
    every system in input.systems {
        system.backup_config.backup_window.duration_hours <= maximum_backup_window(system)
    }
}

maximum_backup_window(system) := 4 if {
    system.criticality_level == "critical"
}

maximum_backup_window(system) := 8 if {
    system.criticality_level == "important"
}

maximum_backup_window(system) := 12 if {
    system.criticality_level in ["standard", "low"]
}

# Retention Policy Compliance
# Corporate Policy: "Financial data 7 years, operational data 3 years, personal data per privacy law"
retention_policy_compliant if {
    all_systems_have_retention_policy
    retention_periods_meet_requirements
    automated_deletion_configured
}

all_systems_have_retention_policy if {
    violations := [system |
        system := input.systems[_]
        not system.backup_config.retention_policy
    ]
    count(violations) == 0
}

retention_periods_meet_requirements if {
    violations := [system |
        system := input.systems[_]
        not retention_period_adequate(system)
    ]
    count(violations) == 0
}

retention_period_adequate(system) if {
    "financial" in system.data_types
    system.backup_config.retention_policy.years >= 7
}

retention_period_adequate(system) if {
    "operational" in system.data_types
    not "financial" in system.data_types
    system.backup_config.retention_policy.years >= 3
}

retention_period_adequate(system) if {
    "personal" in system.data_types
    system.backup_config.retention_policy.years >= minimum_personal_data_retention(system)
}

retention_period_adequate(system) if {
    not "financial" in system.data_types
    not "operational" in system.data_types
    not "personal" in system.data_types
    system.backup_config.retention_policy.years >= 1
}

minimum_personal_data_retention(system) := 3 if {
    system.regulatory_requirements[_] == "GDPR"
}

minimum_personal_data_retention(system) := 6 if {
    system.regulatory_requirements[_] == "HIPAA"
}

minimum_personal_data_retention(system) := 7 if {
    system.regulatory_requirements[_] == "SOX"
}

minimum_personal_data_retention(system) := 2 if {
    true  # Default minimum
}

automated_deletion_configured if {
    violations := [system |
        system := input.systems[_]
        not system.backup_config.automated_deletion.enabled
    ]
    count(violations) == 0
}

# Backup Testing Compliance
# Corporate Policy: "Monthly restore tests for critical systems, quarterly for others"
backup_testing_compliant if {
    all_systems_tested_regularly
    test_success_rates_adequate
    test_documentation_complete
}

all_systems_tested_regularly if {
    violations := [system |
        system := input.systems[_]
        not restore_testing_frequent_enough(system)
    ]
    count(violations) == 0
}

restore_testing_frequent_enough(system) if {
    system.criticality_level == "critical"
    days_since_last_test := (time.now_ns() - system.backup_config.last_restore_test) / (24 * 60 * 60 * 1000000000)
    days_since_last_test <= 30
}

restore_testing_frequent_enough(system) if {
    system.criticality_level == "important"
    days_since_last_test := (time.now_ns() - system.backup_config.last_restore_test) / (24 * 60 * 60 * 1000000000)
    days_since_last_test <= 60
}

restore_testing_frequent_enough(system) if {
    system.criticality_level in ["standard", "low"]
    days_since_last_test := (time.now_ns() - system.backup_config.last_restore_test) / (24 * 60 * 60 * 1000000000)
    days_since_last_test <= 90
}

test_success_rates_adequate if {
    violations := [system |
        system := input.systems[_]
        system.backup_config.test_success_rate < minimum_success_rate(system)
    ]
    count(violations) == 0
}

minimum_success_rate(system) := 98 if {
    system.criticality_level == "critical"
}

minimum_success_rate(system) := 95 if {
    system.criticality_level == "important"
}

minimum_success_rate(system) := 90 if {
    system.criticality_level in ["standard", "low"]
}

test_documentation_complete if {
    violations := [system |
        system := input.systems[_]
        not system.backup_config.test_documentation.complete
    ]
    count(violations) == 0
}

# Recovery Procedures Compliance
# Corporate Policy: "Documented RTO/RPO objectives, tested recovery procedures"
recovery_procedures_compliant if {
    rto_objectives_defined
    rpo_objectives_defined
    recovery_procedures_documented
    recovery_procedures_tested
}

rto_objectives_defined if {
    violations := [system |
        system := input.systems[_]
        not system.recovery_config.rto_hours
    ]
    count(violations) == 0
}

rpo_objectives_defined if {
    violations := [system |
        system := input.systems[_]
        not system.recovery_config.rpo_hours
    ]
    count(violations) == 0
}

recovery_procedures_documented if {
    violations := [system |
        system := input.systems[_]
        not system.recovery_config.procedures_documented
    ]
    count(violations) == 0
}

recovery_procedures_tested if {
    violations := [system |
        system := input.systems[_]
        not disaster_recovery_testing_current(system)
    ]
    count(violations) == 0
}

disaster_recovery_testing_current(system) if {
    days_since_dr_test := (time.now_ns() - system.recovery_config.last_dr_test) / (24 * 60 * 60 * 1000000000)
    days_since_dr_test <= dr_test_frequency_days(system)
}

dr_test_frequency_days(system) := 180 if {  # 6 months
    system.criticality_level == "critical"
}

dr_test_frequency_days(system) := 365 if {  # 1 year
    system.criticality_level in ["important", "standard", "low"]
}

# Backup Security Compliance
# Corporate Policy: "Encrypted backups, access controls, immutable storage"
backup_security_compliant if {
    backup_encryption_enabled
    backup_access_controls_implemented
    immutable_storage_configured
    backup_integrity_verified
}

backup_encryption_enabled if {
    violations := [system |
        system := input.systems[_]
        not system.backup_config.encryption.enabled
    ]
    count(violations) == 0
}

backup_access_controls_implemented if {
    violations := [system |
        system := input.systems[_]
        not adequate_backup_access_controls(system)
    ]
    count(violations) == 0
}

adequate_backup_access_controls(system) if {
    system.backup_config.access_controls.rbac_enabled
    system.backup_config.access_controls.mfa_required
    count(system.backup_config.access_controls.authorized_users) <= max_backup_admins(system)
}

max_backup_admins(system) := 2 if {
    system.criticality_level == "critical"
}

max_backup_admins(system) := 3 if {
    system.criticality_level == "important"
}

max_backup_admins(system) := 5 if {
    system.criticality_level in ["standard", "low"]
}

immutable_storage_configured if {
    violations := [system |
        system := input.systems[_]
        system.criticality_level in ["critical", "important"]
        not system.backup_config.immutable_storage.enabled
    ]
    count(violations) == 0
}

backup_integrity_verified if {
    violations := [system |
        system := input.systems[_]
        not system.backup_config.integrity_verification.enabled
    ]
    count(violations) == 0
}

# Offsite Backup Compliance
# Corporate Policy: "Geographic separation, secure transmission, vendor management"
offsite_backup_compliant if {
    geographic_separation_adequate
    secure_transmission_configured
    offsite_vendor_compliant
}

geographic_separation_adequate if {
    violations := [system |
        system := input.systems[_]
        system.criticality_level in ["critical", "important"]
        not adequate_geographic_separation(system)
    ]
    count(violations) == 0
}

adequate_geographic_separation(system) if {
    system.backup_config.offsite.distance_km >= minimum_separation_distance(system)
}

minimum_separation_distance(system) := 500 if {  # 500km minimum
    system.criticality_level == "critical"
}

minimum_separation_distance(system) := 200 if {  # 200km minimum
    system.criticality_level == "important"
}

minimum_separation_distance(system) := 50 if {   # 50km minimum
    system.criticality_level in ["standard", "low"]
}

secure_transmission_configured if {
    violations := [system |
        system := input.systems[_]
        not system.backup_config.offsite.encryption_in_transit
    ]
    count(violations) == 0
}

offsite_vendor_compliant if {
    violations := [vendor |
        vendor := input.backup_vendors[_]
        not vendor_compliance_adequate(vendor)
    ]
    count(violations) == 0
}

vendor_compliance_adequate(vendor) if {
    vendor.certifications[_] in ["SOC 2", "ISO 27001", "PCI DSS"]
    vendor.sla.availability >= 99.9
    vendor.contract.data_residency_compliant
}

# Backup Performance Metrics
backup_performance_score := score if {
    total_systems := count(input.systems)
    
    schedule_score := (count([system | 
        system := input.systems[_]
        backup_frequency_adequate(system)
    ]) * 100) / total_systems
    
    retention_score := (count([system |
        system := input.systems[_]
        retention_period_adequate(system)
    ]) * 100) / total_systems
    
    testing_score := (count([system |
        system := input.systems[_]
        restore_testing_frequent_enough(system)
    ]) * 100) / total_systems
    
    security_score := (count([system |
        system := input.systems[_]
        system.backup_config.encryption.enabled
        adequate_backup_access_controls(system)
    ]) * 100) / total_systems
    
    score := (schedule_score + retention_score + testing_score + security_score) / 4
}

# Backup Policy Violations and Remediation
backup_violations := violations if {
    violations := array.concat(
        schedule_violations,
        array.concat(retention_violations,
        array.concat(testing_violations,
        array.concat(recovery_violations,
        array.concat(security_violations, offsite_violations))))
    )
}

schedule_violations := [violation |
    system := input.systems[_]
    not backup_frequency_adequate(system)
    violation := {
        "system_id": system.id,
        "type": "backup_schedule",
        "severity": "high",
        "description": sprintf("Backup frequency for %s system does not meet %s level requirements", [system.name, system.criticality_level]),
        "current_frequency": system.backup_config.frequency,
        "required_frequency": required_frequency_for_criticality(system.criticality_level),
        "remediation": "Update backup schedule to meet criticality level requirements"
    }
]

retention_violations := [violation |
    system := input.systems[_]
    not retention_period_adequate(system)
    violation := {
        "system_id": system.id,
        "type": "retention_policy",
        "severity": "medium",
        "description": sprintf("Retention period for %s does not meet data type requirements", [system.name]),
        "current_retention": sprintf("%d years", [system.backup_config.retention_policy.years]),
        "required_retention": sprintf("%d years minimum", [minimum_retention_for_data_types(system.data_types)]),
        "remediation": "Extend backup retention period to meet regulatory and policy requirements"
    }
]

testing_violations := [violation |
    system := input.systems[_]
    not restore_testing_frequent_enough(system)
    violation := {
        "system_id": system.id,
        "type": "backup_testing",
        "severity": "high",
        "description": sprintf("Restore testing for %s is overdue", [system.name]),
        "days_overdue": (time.now_ns() - system.backup_config.last_restore_test) / (24 * 60 * 60 * 1000000000),
        "remediation": "Schedule and perform restore testing immediately"
    }
]

recovery_violations := [violation |
    system := input.systems[_]
    not disaster_recovery_testing_current(system)
    violation := {
        "system_id": system.id,
        "type": "disaster_recovery",
        "severity": "critical",
        "description": sprintf("Disaster recovery testing for %s is overdue", [system.name]),
        "days_overdue": (time.now_ns() - system.recovery_config.last_dr_test) / (24 * 60 * 60 * 1000000000),
        "remediation": "Conduct full disaster recovery test and update procedures"
    }
]

security_violations := [violation |
    system := input.systems[_]
    not system.backup_config.encryption.enabled
    violation := {
        "system_id": system.id,
        "type": "backup_security",
        "severity": "critical",
        "description": sprintf("Backup encryption not enabled for %s", [system.name]),
        "remediation": "Enable backup encryption using AES-256 or equivalent"
    }
]

offsite_violations := [violation |
    system := input.systems[_]
    system.criticality_level in ["critical", "important"]
    not adequate_geographic_separation(system)
    violation := {
        "system_id": system.id,
        "type": "offsite_backup",
        "severity": "high",
        "description": sprintf("Offsite backup for %s does not meet geographic separation requirements", [system.name]),
        "current_distance": sprintf("%d km", [system.backup_config.offsite.distance_km]),
        "required_distance": sprintf("%d km minimum", [minimum_separation_distance(system)]),
        "remediation": "Configure offsite backup location with adequate geographic separation"
    }
]

# Helper Functions
required_frequency_for_criticality("critical") := "daily"
required_frequency_for_criticality("important") := "daily or weekly"
required_frequency_for_criticality("standard") := "weekly or monthly"
required_frequency_for_criticality("low") := "monthly"

minimum_retention_for_data_types(data_types) := 7 if {
    "financial" in data_types
}

minimum_retention_for_data_types(data_types) := 3 if {
    "operational" in data_types
    not "financial" in data_types
}

minimum_retention_for_data_types(data_types) := 2 if {
    "personal" in data_types
    not "financial" in data_types
    not "operational" in data_types
}

minimum_retention_for_data_types(data_types) := 1 if {
    true  # Default
}

# Compliance Framework Mapping
pci_dss_backup_compliant if {
    backup_compliant
    every system in input.systems {
        "cardholder_data" in system.data_types
        system.backup_config.encryption.enabled
        system.backup_config.access_controls.mfa_required
    }
}

sox_backup_compliant if {
    backup_compliant
    every system in input.systems {
        "financial" in system.data_types
        system.backup_config.retention_policy.years >= 7
        disaster_recovery_testing_current(system)
    }
}

iso27001_backup_compliant if {
    backup_compliant
    backup_security_compliant
    all_systems_tested_regularly
}

# Policy Metadata
backup_policy_metadata := {
    "policy_name": "Corporate Backup and Recovery Policy",
    "version": "1.6",
    "effective_date": "2025-01-01",
    "last_updated": "2025-10-05",
    "policy_owner": "Chief Information Officer",
    "compliance_frameworks": ["SOX", "PCI DSS", "ISO 27001", "GDPR"],
    "enforcement_level": "mandatory",
    "review_frequency": "annual",
    "exception_approval_required": true
}