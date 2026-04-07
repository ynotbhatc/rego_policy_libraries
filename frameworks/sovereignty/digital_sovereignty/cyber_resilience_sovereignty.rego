package digital_sovereignty.cyber_resilience_sovereignty

import rego.v1

# Digital Sovereignty — Cyber Resilience
# Assesses organisational ability to withstand, recover from, and adapt to
# cyber incidents — including hostile nation-state and supply chain attacks.
#
# Applicable frameworks:
#   NIST SP 800-160 Vol. 2 (Cyber Resiliency Engineering)
#   NIST CSF 2.0 — Govern, Identify, Protect, Detect, Respond, Recover
#   ISO 22301 (Business Continuity Management)
#   EU Cyber Resilience Act (CRA) — Regulation 2024/2847
#   ENISA Cyber Resilience Guidelines
#   NCSC Cyber Resilience Framework (UK)
#
# Input schema:
#   input.cyber_resilience
#     .redundancy
#       .critical_systems_have_active_redundancy     — bool
#       .failover_tested_date                        — ISO8601 string
#       .failover_test_frequency_days                — int
#     .backup_and_recovery
#       .backups_taken_frequency_hours               — int (max acceptable)
#       .recovery_tested_date                        — ISO8601 string
#       .recovery_test_frequency_days                — int
#       .recovery_test_met_rto                       — bool
#       .recovery_test_met_rpo                       — bool
#       .backup_immutability_enforced                — bool
#       .backup_location_sovereign                   — bool
#     .adversarial_testing
#       .red_team_conducted                          — bool
#       .red_team_date                               — ISO8601 string
#       .red_team_frequency_days                     — int
#       .purple_team_or_chaos_engineering            — bool
#     .incident_response
#       .ir_plan_documented                          — bool
#       .ir_plan_tested_date                         — ISO8601 string
#       .ir_plan_test_frequency_days                 — int
#       .roles_formally_assigned                     — bool (CISO, incident commander, comms lead)
#       .nation_state_scenario_included              — bool
#     .threat_intelligence
#       .feeds_active                                — bool
#       .feeds_integrated_into_soc                   — bool
#       .sovereign_feed_available                    — bool (in-jurisdiction TI source)
#     .supply_chain_resilience
#       .assessment_conducted                        — bool
#       .assessment_date                             — ISO8601 string
#       .assessment_frequency_days                   — int
#       .critical_suppliers_have_alternatives        — bool
#       .software_bill_of_materials_for_resilience   — bool
#     .metrics
#       .mttr_tracked                                — bool (Mean Time to Recover)
#       .mttr_hours                                  — int (actual tracked MTTR)
#       .mttr_threshold_hours                        — int (max acceptable)
#       .mttd_tracked                                — bool (Mean Time to Detect)
#     .governance
#       .board_cyber_resilience_review_frequency_days — int (max 365)
#       .board_review_date                           — ISO8601 string
#       .cyber_resilience_training_date              — ISO8601 string
#       .cyber_resilience_training_frequency_days    — int

# =============================================================================
# REDUNDANCY AND FAILOVER
# =============================================================================

redundancy_adequate if {
	input.cyber_resilience.redundancy.critical_systems_have_active_redundancy == true
	tested_ns := time.parse_rfc3339_ns(input.cyber_resilience.redundancy.failover_tested_date)
	max_age_ns := input.cyber_resilience.redundancy.failover_test_frequency_days * 24 * 3600 * 1000000000
	tested_ns >= time.now_ns() - max_age_ns
}

# =============================================================================
# BACKUP AND RECOVERY
# =============================================================================

recovery_tested_and_met_objectives if {
	input.cyber_resilience.backup_and_recovery.recovery_test_met_rto == true
	input.cyber_resilience.backup_and_recovery.recovery_test_met_rpo == true
	tested_ns := time.parse_rfc3339_ns(input.cyber_resilience.backup_and_recovery.recovery_tested_date)
	max_age_ns := input.cyber_resilience.backup_and_recovery.recovery_test_frequency_days * 24 * 3600 * 1000000000
	tested_ns >= time.now_ns() - max_age_ns
}

backup_immutable_and_sovereign if {
	input.cyber_resilience.backup_and_recovery.backup_immutability_enforced == true
	input.cyber_resilience.backup_and_recovery.backup_location_sovereign == true
}

# =============================================================================
# ADVERSARIAL TESTING
# =============================================================================

adversarial_testing_current if {
	input.cyber_resilience.adversarial_testing.red_team_conducted == true
	tested_ns := time.parse_rfc3339_ns(input.cyber_resilience.adversarial_testing.red_team_date)
	max_age_ns := input.cyber_resilience.adversarial_testing.red_team_frequency_days * 24 * 3600 * 1000000000
	tested_ns >= time.now_ns() - max_age_ns
}

# =============================================================================
# INCIDENT RESPONSE
# =============================================================================

ir_plan_tested_and_current if {
	input.cyber_resilience.incident_response.ir_plan_documented == true
	input.cyber_resilience.incident_response.roles_formally_assigned == true
	tested_ns := time.parse_rfc3339_ns(input.cyber_resilience.incident_response.ir_plan_tested_date)
	max_age_ns := input.cyber_resilience.incident_response.ir_plan_test_frequency_days * 24 * 3600 * 1000000000
	tested_ns >= time.now_ns() - max_age_ns
}

nation_state_scenario_covered if {
	input.cyber_resilience.incident_response.nation_state_scenario_included == true
}

# =============================================================================
# THREAT INTELLIGENCE
# =============================================================================

threat_intelligence_active if {
	input.cyber_resilience.threat_intelligence.feeds_active == true
	input.cyber_resilience.threat_intelligence.feeds_integrated_into_soc == true
}

# =============================================================================
# SUPPLY CHAIN RESILIENCE
# =============================================================================

supply_chain_resilience_current if {
	input.cyber_resilience.supply_chain_resilience.assessment_conducted == true
	input.cyber_resilience.supply_chain_resilience.critical_suppliers_have_alternatives == true
	assessed_ns := time.parse_rfc3339_ns(input.cyber_resilience.supply_chain_resilience.assessment_date)
	max_age_ns := input.cyber_resilience.supply_chain_resilience.assessment_frequency_days * 24 * 3600 * 1000000000
	assessed_ns >= time.now_ns() - max_age_ns
}

# =============================================================================
# METRICS
# =============================================================================

mttr_within_threshold if {
	input.cyber_resilience.metrics.mttr_tracked == true
	input.cyber_resilience.metrics.mttr_hours <= input.cyber_resilience.metrics.mttr_threshold_hours
}

# =============================================================================
# GOVERNANCE
# =============================================================================

board_oversight_current if {
	reviewed_ns := time.parse_rfc3339_ns(input.cyber_resilience.governance.board_review_date)
	max_age_ns := input.cyber_resilience.governance.board_cyber_resilience_review_frequency_days * 24 * 3600 * 1000000000
	reviewed_ns >= time.now_ns() - max_age_ns
}

staff_training_current if {
	trained_ns := time.parse_rfc3339_ns(input.cyber_resilience.governance.cyber_resilience_training_date)
	max_age_ns := input.cyber_resilience.governance.cyber_resilience_training_frequency_days * 24 * 3600 * 1000000000
	trained_ns >= time.now_ns() - max_age_ns
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not redundancy_adequate
	v := {
		"domain":      "cyber_resilience_sovereignty",
		"control":     "CR-001",
		"severity":    "critical",
		"description": "Critical systems lack active redundancy or failover has not been tested within required frequency (NIST SP 800-160 Vol.2, ISO 22301)",
		"remediation": "Deploy active-active or active-passive redundancy for all critical systems; test failover at least annually and record outcomes",
	}
}

violations contains v if {
	not recovery_tested_and_met_objectives
	v := {
		"domain":      "cyber_resilience_sovereignty",
		"control":     "CR-002",
		"severity":    "critical",
		"description": "Backup recovery not tested within required frequency, or tested recovery failed to meet RTO/RPO objectives (ISO 22301 §8.5)",
		"remediation": "Conduct regular tested recovery drills; document results against RTO/RPO targets; remediate gaps before next test cycle",
	}
}

violations contains v if {
	not backup_immutable_and_sovereign
	v := {
		"domain":      "cyber_resilience_sovereignty",
		"control":     "CR-003",
		"severity":    "high",
		"description": "Backups are not immutable or are stored outside approved jurisdiction — ransomware and sovereignty risk (NIST CSF RC.RP, EU CRA Art. 13)",
		"remediation": "Implement immutable backup storage (WORM) in-jurisdiction; test restoration from immutable backups quarterly",
	}
}

violations contains v if {
	not adversarial_testing_current
	v := {
		"domain":      "cyber_resilience_sovereignty",
		"control":     "CR-004",
		"severity":    "high",
		"description": "Red team / adversarial testing not conducted or overdue (NIST SP 800-160 Vol.2 §3.3, NCSC Cyber Resilience)",
		"remediation": "Conduct annual adversarial testing using threat-intelligence-led scenarios; include supply chain and insider threat vectors",
	}
}

violations contains v if {
	not ir_plan_tested_and_current
	v := {
		"domain":      "cyber_resilience_sovereignty",
		"control":     "CR-005",
		"severity":    "critical",
		"description": "Incident response plan not documented, roles not assigned, or plan not tested within required frequency (NIST CSF RS.RP, ISO 22301 §8.4)",
		"remediation": "Document IR plan with named roles (CISO, incident commander, communications lead); test via tabletop exercises at least annually",
	}
}

violations contains v if {
	not nation_state_scenario_covered
	v := {
		"domain":      "cyber_resilience_sovereignty",
		"control":     "CR-006",
		"severity":    "high",
		"description": "Incident response plan does not include nation-state or advanced persistent threat (APT) scenarios (NIST SP 800-160 Vol.2)",
		"remediation": "Add nation-state attack scenarios to IR playbooks; include state-sponsored ransomware, supply chain compromise, and long-dwell intrusion patterns",
	}
}

violations contains v if {
	not threat_intelligence_active
	v := {
		"domain":      "cyber_resilience_sovereignty",
		"control":     "CR-007",
		"severity":    "high",
		"description": "Threat intelligence feeds not active or not integrated into SOC operations (NIST CSF DE.AE, ENISA Cyber Resilience)",
		"remediation": "Subscribe to and integrate threat intelligence feeds (MISP, ISAC, national CERT); automate IOC ingestion into SIEM/SOAR",
	}
}

violations contains v if {
	not supply_chain_resilience_current
	v := {
		"domain":      "cyber_resilience_sovereignty",
		"control":     "CR-008",
		"severity":    "high",
		"description": "Supply chain resilience assessment not current or critical suppliers lack identified alternatives (EU CRA Art. 13, NIST SP 800-160 Vol.2 §3.4)",
		"remediation": "Conduct annual supply chain resilience assessment; identify and qualify alternative suppliers for all critical components",
	}
}

violations contains v if {
	not mttr_within_threshold
	v := {
		"domain":      "cyber_resilience_sovereignty",
		"control":     "CR-009",
		"severity":    "high",
		"description":  concat("", [
			"Mean Time to Recover (MTTR) exceeds threshold: ",
			format_int(input.cyber_resilience.metrics.mttr_hours, 10),
			"h actual vs ",
			format_int(input.cyber_resilience.metrics.mttr_threshold_hours, 10),
			"h target (NIST CSF RC.RP)",
		]),
		"remediation": "Analyse recovery bottlenecks; invest in automation of recovery procedures; conduct post-incident reviews to reduce MTTR",
	}
}

violations contains v if {
	not board_oversight_current
	v := {
		"domain":      "cyber_resilience_sovereignty",
		"control":     "CR-010",
		"severity":    "medium",
		"description": "Board or executive cyber resilience review overdue (NIST CSF GV.OC, EU CRA Art. 13, ISO 22301 §5.1)",
		"remediation": "Schedule regular board-level cyber resilience briefings including resilience posture, incident trends, and recovery capability",
	}
}

violations contains v if {
	not staff_training_current
	v := {
		"domain":      "cyber_resilience_sovereignty",
		"control":     "CR-011",
		"severity":    "medium",
		"description": "Cyber resilience training for staff not conducted within required frequency (NIST CSF GV.RR, ISO 22301 §7.2)",
		"remediation": "Deliver annual cyber resilience training covering incident recognition, response procedures, and escalation paths",
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	redundancy_adequate
	recovery_tested_and_met_objectives
	backup_immutable_and_sovereign
	adversarial_testing_current
	ir_plan_tested_and_current
	nation_state_scenario_covered
	threat_intelligence_active
	supply_chain_resilience_current
	mttr_within_threshold
	board_oversight_current
	staff_training_current
}

report := {
	"domain":    "Cyber Resilience",
	"compliant": compliant,
	"controls": {
		"CR-001_redundancy_tested":             redundancy_adequate,
		"CR-002_recovery_meets_objectives":     recovery_tested_and_met_objectives,
		"CR-003_backup_immutable_sovereign":    backup_immutable_and_sovereign,
		"CR-004_adversarial_testing_current":   adversarial_testing_current,
		"CR-005_ir_plan_tested":                ir_plan_tested_and_current,
		"CR-006_nation_state_scenario":         nation_state_scenario_covered,
		"CR-007_threat_intelligence_active":    threat_intelligence_active,
		"CR-008_supply_chain_resilience":       supply_chain_resilience_current,
		"CR-009_mttr_within_threshold":         mttr_within_threshold,
		"CR-010_board_oversight_current":       board_oversight_current,
		"CR-011_staff_training_current":        staff_training_current,
	},
	"violations":      violations,
	"violation_count": count(violations),
}
