# Unit tests for the SOC 2 master aggregation policy (frameworks/management/soc2/soc2_main.rego)
# Closes issue #81.
#
# NOTE ON SCOPE
# soc2_main.rego is an ORCHESTRATOR, not a violation-based policy: it defines no
# `violation`/`violations contains` rules and no `compliance_report` object.
# These tests therefore exercise:
#   1. Every rule DEFINED IN THIS FILE that reads input.* directly (one firing
#      fixture + one negative case each).
#   2. The defaulted Trust Service Criteria rules on empty input (assert `false`).
#   3. The report-shaped rules (soc2_detailed_findings / scores) — pinned as
#      UNDEFINED on empty input. They cannot be populated on `{}` because the ten
#      imported sub-modules declare no `default` values, so every score/findings
#      field is undefined and collapses the object (repo CLAUDE.md critical rule #5).
#      That is a finding about the module, captured here as a regression guard.

package soc2.main_test

import rego.v1

import data.soc2.main

# =================================================================
# Defaulted Trust Service Criteria rules — false on empty input
# =================================================================

test_security_compliant_false_on_empty if {
	main.security_compliant == false with input as {}
}

test_availability_compliant_false_on_empty if {
	main.availability_compliant == false with input as {}
}

test_processing_integrity_compliant_false_on_empty if {
	main.processing_integrity_compliant == false with input as {}
}

test_confidentiality_compliant_false_on_empty if {
	main.confidentiality_compliant == false with input as {}
}

test_privacy_compliant_false_on_empty if {
	main.privacy_compliant == false with input as {}
}

# =================================================================
# operating_effectiveness_demonstrated
# =================================================================

test_operating_effectiveness_demonstrated_fires if {
	main.operating_effectiveness_demonstrated with input as {"soc2": {"operating_effectiveness": {
		"testing_period_months": 12,
		"continuous_monitoring": true,
		"exception_reporting": true,
		"management_response": {"documented": true},
	}}}
}

test_operating_effectiveness_demonstrated_not_under_min_period if {
	# 11 months is below the >= 12 boundary
	not main.operating_effectiveness_demonstrated with input as {"soc2": {"operating_effectiveness": {
		"testing_period_months": 11,
		"continuous_monitoring": true,
		"exception_reporting": true,
		"management_response": {"documented": true},
	}}}
}

# =================================================================
# service_commitments_defined
# =================================================================

test_service_commitments_defined_fires if {
	main.service_commitments_defined with input as {"soc2": {"service_commitments": {
		"security": {"defined": true},
		"suitability_of_design": true,
		"operating_effectiveness": true,
	}}}
}

test_service_commitments_defined_not_when_field_false if {
	not main.service_commitments_defined with input as {"soc2": {"service_commitments": {
		"security": {"defined": false},
		"suitability_of_design": true,
		"operating_effectiveness": true,
	}}}
}

# =================================================================
# system_boundaries_defined
# =================================================================

test_system_boundaries_defined_fires if {
	main.system_boundaries_defined with input as {"soc2": {"system_boundaries": {
		"infrastructure": {"documented": true},
		"software": {"documented": true},
		"people": {"documented": true},
		"procedures": {"documented": true},
		"data": {"documented": true},
	}}}
}

test_system_boundaries_defined_not_when_missing_component if {
	not main.system_boundaries_defined with input as {"soc2": {"system_boundaries": {
		"infrastructure": {"documented": true},
		"software": {"documented": true},
		"people": {"documented": true},
		"procedures": {"documented": true},
		# data omitted
	}}}
}

# =================================================================
# risk_assessment_established
# =================================================================

test_risk_assessment_established_fires if {
	main.risk_assessment_established with input as {"soc2": {"risk_management": {
		"risk_assessment": {"periodic": true, "methodology": {"defined": true}},
		"risk_identification": {"comprehensive": true},
		"risk_response": {"documented": true},
	}}}
}

test_risk_assessment_established_not_when_field_false if {
	not main.risk_assessment_established with input as {"soc2": {"risk_management": {
		"risk_assessment": {"periodic": false, "methodology": {"defined": true}},
		"risk_identification": {"comprehensive": true},
		"risk_response": {"documented": true},
	}}}
}

# =================================================================
# risk_monitoring_active
# =================================================================

test_risk_monitoring_active_fires if {
	main.risk_monitoring_active with input as {"soc2": {"risk_management": {
		"monitoring": {"continuous": true},
		"reporting": {"regular": true},
		"escalation": {"procedures": {"defined": true}},
	}}}
}

test_risk_monitoring_active_not_when_field_false if {
	not main.risk_monitoring_active with input as {"soc2": {"risk_management": {
		"monitoring": {"continuous": true},
		"reporting": {"regular": false},
		"escalation": {"procedures": {"defined": true}},
	}}}
}

# =================================================================
# management_oversight
# =================================================================

test_management_oversight_fires if {
	main.management_oversight with input as {"soc2": {"control_environment": {
		"governance": {"board_oversight": true, "management_philosophy": true},
		"integrity": {"code_of_conduct": true},
		"competence": {"defined_roles": true},
	}}}
}

test_management_oversight_not_when_field_false if {
	not main.management_oversight with input as {"soc2": {"control_environment": {
		"governance": {"board_oversight": true, "management_philosophy": false},
		"integrity": {"code_of_conduct": true},
		"competence": {"defined_roles": true},
	}}}
}

# =================================================================
# hr_controls_effective
# =================================================================

test_hr_controls_effective_fires if {
	main.hr_controls_effective with input as {"soc2": {"human_resources": {
		"background_checks": true,
		"training_programs": true,
		"performance_evaluations": true,
		"disciplinary_procedures": true,
	}}}
}

test_hr_controls_effective_not_when_field_false if {
	not main.hr_controls_effective with input as {"soc2": {"human_resources": {
		"background_checks": true,
		"training_programs": true,
		"performance_evaluations": true,
		"disciplinary_procedures": false,
	}}}
}

# =================================================================
# vendor_management_program
# =================================================================

test_vendor_management_program_fires if {
	main.vendor_management_program with input as {"soc2": {"vendor_management": {
		"due_diligence": {"performed": true},
		"contracts": {"security_requirements": true},
		"monitoring": {"ongoing": true},
		"termination": {"procedures": {"defined": true}},
	}}}
}

test_vendor_management_program_not_when_field_false if {
	not main.vendor_management_program with input as {"soc2": {"vendor_management": {
		"due_diligence": {"performed": false},
		"contracts": {"security_requirements": true},
		"monitoring": {"ongoing": true},
		"termination": {"procedures": {"defined": true}},
	}}}
}

# =================================================================
# subservice_organization_oversight
# count(input.soc2.subservice_organizations) == 0
# =================================================================

test_subservice_organization_oversight_fires_on_empty_array if {
	main.subservice_organization_oversight with input as {"soc2": {"subservice_organizations": []}}
}

test_subservice_organization_oversight_not_when_orgs_present if {
	not main.subservice_organization_oversight with input as {"soc2": {"subservice_organizations": [{"name": "vendor-a"}]}}
}

test_subservice_organization_oversight_not_when_key_missing if {
	# count() on a missing key is undefined, so the rule does not fire
	not main.subservice_organization_oversight with input as {}
}

# =================================================================
# change_management_process
# =================================================================

test_change_management_process_fires if {
	main.change_management_process with input as {"soc2": {"change_management": {
		"process": {"documented": true},
		"approval": {"required": true},
		"testing": {"required": true},
		"rollback": {"procedures": {"defined": true}},
	}}}
}

test_change_management_process_not_when_field_false if {
	not main.change_management_process with input as {"soc2": {"change_management": {
		"process": {"documented": true},
		"approval": {"required": false},
		"testing": {"required": true},
		"rollback": {"procedures": {"defined": true}},
	}}}
}

# =================================================================
# configuration_management
# =================================================================

test_configuration_management_fires if {
	main.configuration_management with input as {"soc2": {"configuration_management": {
		"baseline": {"established": true},
		"version_control": true,
		"unauthorized_changes": {"detection": true},
	}}}
}

test_configuration_management_not_when_field_false if {
	not main.configuration_management with input as {"soc2": {"configuration_management": {
		"baseline": {"established": true},
		"version_control": false,
		"unauthorized_changes": {"detection": true},
	}}}
}

# =================================================================
# incident_response_program
# =================================================================

test_incident_response_program_fires if {
	main.incident_response_program with input as {"soc2": {"incident_response": {
		"program": {"established": true},
		"team": {"defined": true},
		"procedures": {"documented": true},
		"testing": {"regular": true},
	}}}
}

test_incident_response_program_not_when_field_false if {
	not main.incident_response_program with input as {"soc2": {"incident_response": {
		"program": {"established": true},
		"team": {"defined": true},
		"procedures": {"documented": true},
		"testing": {"regular": false},
	}}}
}

# =================================================================
# business_continuity_planning
# =================================================================

test_business_continuity_planning_fires if {
	main.business_continuity_planning with input as {"soc2": {"business_continuity": {
		"plan": {"documented": true},
		"testing": {"annual": true},
		"recovery_objectives": {"defined": true},
		"communication": {"plan": {"defined": true}},
	}}}
}

test_business_continuity_planning_not_when_field_false if {
	not main.business_continuity_planning with input as {"soc2": {"business_continuity": {
		"plan": {"documented": true},
		"testing": {"annual": false},
		"recovery_objectives": {"defined": true},
		"communication": {"plan": {"defined": true}},
	}}}
}

# =================================================================
# system_monitoring_comprehensive
# =================================================================

test_system_monitoring_comprehensive_fires if {
	main.system_monitoring_comprehensive with input as {"soc2": {"monitoring": {
		"infrastructure": {"comprehensive": true},
		"applications": {"comprehensive": true},
		"security_events": {"real_time": true},
		"performance": {"continuous": true},
	}}}
}

test_system_monitoring_comprehensive_not_when_field_false if {
	not main.system_monitoring_comprehensive with input as {"soc2": {"monitoring": {
		"infrastructure": {"comprehensive": true},
		"applications": {"comprehensive": true},
		"security_events": {"real_time": false},
		"performance": {"continuous": true},
	}}}
}

# =================================================================
# log_management_effective
# =================================================================

test_log_management_effective_fires if {
	main.log_management_effective with input as {"soc2": {"logging": {
		"centralized": true,
		"integrity_protection": true,
		"retention": {"adequate": true},
		"review": {"regular": true},
	}}}
}

test_log_management_effective_not_when_field_false if {
	not main.log_management_effective with input as {"soc2": {"logging": {
		"centralized": true,
		"integrity_protection": true,
		"retention": {"adequate": false},
		"review": {"regular": true},
	}}}
}

# =================================================================
# Aggregates defined in this file — undefined on empty input
# (no defaults; assert with `not`)
# =================================================================

test_core_soc2_requirements_met_not_on_empty if {
	not main.core_soc2_requirements_met with input as {}
}

test_operational_controls_effective_not_on_empty if {
	not main.operational_controls_effective with input as {}
}

test_monitoring_oversight_effective_not_on_empty if {
	not main.monitoring_oversight_effective with input as {}
}

test_overall_soc2_compliant_not_on_empty if {
	not main.overall_soc2_compliant with input as {}
}

test_soc2_type_i_compliant_not_on_empty if {
	not main.soc2_type_i_compliant with input as {}
}

# =================================================================
# Report-shaped rules — pinned as UNDEFINED on empty input.
# Cannot populate on {} because the ten imported sub-modules declare
# no `default` values, so every score/findings field collapses the
# object (repo CLAUDE.md critical rule #5). Finding, not a test gap.
# =================================================================

test_soc2_detailed_findings_undefined_on_empty if {
	not main.soc2_detailed_findings with input as {}
}

test_trust_service_criteria_scores_undefined_on_empty if {
	not main.trust_service_criteria_scores with input as {}
}

test_soc2_compliance_score_undefined_on_empty if {
	not main.soc2_compliance_score with input as {}
}
