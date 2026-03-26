package fisma.ssp

import rego.v1

# System Security Plan (SSP) Validation Policy
# NIST SP 800-18 Rev. 1 - Guide for Developing Security Plans for Federal Information Systems
# Validates SSP completeness, accuracy, and compliance with FISMA requirements

# Main SSP Compliance Check
ssp_compliant if {
	ssp_document_structure_valid
	system_identification_complete
	system_categorization_documented
	control_implementation_documented
	system_environment_documented
	roles_responsibilities_defined
	ssp_maintenance_current
}

# SSP Document Structure and Format
ssp_document_structure_valid if {
	input.ssp.document.format in ["pdf", "docx", "xml", "oscal"]
	input.ssp.document.version_control == true
	input.ssp.document.approval_signatures_present == true
	input.ssp.document.table_of_contents_present == true
	input.ssp.document.page_numbering_consistent == true
}

# System Identification and Description (Section 1)
system_identification_complete if {
	system_overview_adequate
	system_boundary_defined
	system_ownership_documented
}

system_overview_adequate if {
	input.ssp.system_identification.system_name != ""
	input.ssp.system_identification.system_abbreviation != ""
	input.ssp.system_identification.system_description != ""
	input.ssp.system_identification.system_purpose != ""
	input.ssp.system_identification.system_version != ""
}

system_boundary_defined if {
	input.ssp.system_identification.boundary.physical_boundary_described == true
	input.ssp.system_identification.boundary.logical_boundary_described == true
	input.ssp.system_identification.boundary.network_architecture_documented == true
	input.ssp.system_identification.boundary.data_flows_documented == true
	count(input.ssp.system_identification.boundary.components) > 0
}

system_ownership_documented if {
	input.ssp.system_identification.ownership.system_owner.name != ""
	input.ssp.system_identification.ownership.system_owner.title != ""
	input.ssp.system_identification.ownership.system_owner.organization != ""
	input.ssp.system_identification.ownership.system_owner.contact_info != ""
	input.ssp.system_identification.ownership.authorizing_official.name != ""
	input.ssp.system_identification.ownership.authorizing_official.title != ""
}

# System Categorization (Section 2)
system_categorization_documented if {
	fips_199_categorization_complete
	information_types_categorized
	impact_analysis_documented
	categorization_rationale_provided
}

fips_199_categorization_complete if {
	input.ssp.categorization.confidentiality.impact_level in ["low", "moderate", "high"]
	input.ssp.categorization.integrity.impact_level in ["low", "moderate", "high"]
	input.ssp.categorization.availability.impact_level in ["low", "moderate", "high"]
	input.ssp.categorization.overall_impact_level in ["low", "moderate", "high"]
}

information_types_categorized if {
	count(input.ssp.categorization.information_types) > 0
	every info_type in input.ssp.categorization.information_types {
		info_type.name != ""
		info_type.description != ""
		info_type.confidentiality_impact in ["low", "moderate", "high"]
		info_type.integrity_impact in ["low", "moderate", "high"]
		info_type.availability_impact in ["low", "moderate", "high"]
		info_type.nist_sp_800_60_reference != ""
	}
}

impact_analysis_documented if {
	input.ssp.categorization.impact_analysis.methodology_described == true
	input.ssp.categorization.impact_analysis.assumptions_documented == true
	input.ssp.categorization.impact_analysis.threat_sources_identified == true
	input.ssp.categorization.impact_analysis.vulnerability_considerations == true
}

categorization_rationale_provided if {
	input.ssp.categorization.rationale.confidentiality_rationale != ""
	input.ssp.categorization.rationale.integrity_rationale != ""
	input.ssp.categorization.rationale.availability_rationale != ""
	input.ssp.categorization.rationale.overall_rationale != ""
}

# Security Control Implementation (Section 3)
control_implementation_documented if {
	control_baseline_identified
	control_descriptions_complete
	control_implementation_details_provided
	control_responsibility_assigned
}

control_baseline_identified if {
	input.ssp.controls.baseline.nist_sp_800_53_baseline in ["low", "moderate", "high"]
	input.ssp.controls.baseline.revision == "5"
	count(input.ssp.controls.baseline.selected_controls) > 0
}

control_descriptions_complete if {
	every control in input.ssp.controls.implemented_controls {
		control.control_id != ""
		control.control_name != ""
		control.control_description != ""
		control.implementation_status in ["implemented", "partially_implemented", "planned", "alternative_implementation", "not_applicable"]
		control.implementation_description != ""
	}
}

control_implementation_details_provided if {
	every control in input.ssp.controls.implemented_controls {
		control.responsible_role != ""
		control.implementation_guidance != ""
		# Parameters filled if control has parameters
		control_parameters_valid(control)
	}
}

control_parameters_valid(control) if {
	not "parameters" in object.keys(control)
}

control_parameters_valid(control) if {
	"parameters" in object.keys(control)
	every param in control.parameters {
		param.parameter_id != ""
		param.value != ""
	}
}

control_responsibility_assigned if {
	every control in input.ssp.controls.implemented_controls {
		control.responsibility in ["system_specific", "common", "hybrid"]
		control.responsible_entity != ""
		# Common controls must reference provider
		control_provider_valid(control)
	}
}

control_provider_valid(control) if {
	control.responsibility != "common"
}

control_provider_valid(control) if {
	control.common_control_provider != ""
}

# System Environment (Section 4)
system_environment_documented if {
	hardware_inventory_complete
	software_inventory_complete
	network_architecture_documented
	data_flows_mapped
}

hardware_inventory_complete if {
	count(input.ssp.environment.hardware) > 0
	every hw in input.ssp.environment.hardware {
		hw.component_name != ""
		hw.component_type != ""
		hw.location != ""
		hw.responsible_organization != ""
		hw.security_impact_level in ["low", "moderate", "high"]
	}
}

software_inventory_complete if {
	count(input.ssp.environment.software) > 0
	every sw in input.ssp.environment.software {
		sw.software_name != ""
		sw.version != ""
		sw.vendor != ""
		sw.purpose != ""
		sw.security_impact_level in ["low", "moderate", "high"]
	}
}

network_architecture_documented if {
	input.ssp.environment.network.architecture_diagram_current == true
	input.ssp.environment.network.network_topology_documented == true
	count(input.ssp.environment.network.network_connections) >= 0
	every conn in input.ssp.environment.network.network_connections {
		conn.source != ""
		conn.destination != ""
		conn.protocol != ""
		conn.port != ""
		conn.security_controls_applied == true
	}
}

data_flows_mapped if {
	count(input.ssp.environment.data_flows) > 0
	every flow in input.ssp.environment.data_flows {
		flow.data_type != ""
		flow.source != ""
		flow.destination != ""
		flow.protection_mechanisms != ""
		flow.classification != ""
	}
}

# Roles and Responsibilities (Section 5)
roles_responsibilities_defined if {
	key_personnel_identified
	role_descriptions_complete
	contact_information_current
	delegation_authorities_documented
}

key_personnel_identified if {
	input.ssp.roles.authorizing_official.name != ""
	input.ssp.roles.senior_agency_iso.name != ""
	input.ssp.roles.system_owner.name != ""
	input.ssp.roles.isso.name != ""
	input.ssp.roles.system_administrator.name != ""
}

role_descriptions_complete if {
	every role in [
		input.ssp.roles.authorizing_official,
		input.ssp.roles.senior_agency_iso,
		input.ssp.roles.system_owner,
		input.ssp.roles.isso,
		input.ssp.roles.system_administrator,
	] {
		role.role_title != ""
		role.responsibilities != ""
		role.authority_level != ""
		role.required_qualifications != ""
	}
}

contact_information_current if {
	every role in [
		input.ssp.roles.authorizing_official,
		input.ssp.roles.senior_agency_iso,
		input.ssp.roles.system_owner,
		input.ssp.roles.isso,
		input.ssp.roles.system_administrator,
	] {
		role.contact_info.email != ""
		role.contact_info.phone != ""
		role.contact_info.organization != ""
		role.contact_info.mailing_address != ""
	}
}

delegation_authorities_documented if {
	input.ssp.roles.delegation.delegation_agreements_current == true
	input.ssp.roles.delegation.backup_personnel_identified == true
	input.ssp.roles.delegation.succession_planning_documented == true
}

# SSP Maintenance and Currency
ssp_maintenance_current if {
	document_version_control_implemented
	review_cycle_established
	change_management_procedures_defined
	document_distribution_controlled
}

document_version_control_implemented if {
	input.ssp.maintenance.version_control.version_numbering_scheme != ""
	input.ssp.maintenance.version_control.change_tracking_implemented == true
	input.ssp.maintenance.version_control.approval_workflow_defined == true
	input.ssp.maintenance.version_control.historical_versions_maintained == true
}

review_cycle_established if {
	input.ssp.maintenance.review_cycle.frequency in ["annually", "semi_annually", "quarterly"]
	input.ssp.maintenance.review_cycle.review_criteria_defined == true
	input.ssp.maintenance.review_cycle.responsible_parties_assigned == true
	input.ssp.maintenance.review_cycle.next_review_date != ""
}

change_management_procedures_defined if {
	input.ssp.maintenance.change_management.change_request_process == true
	input.ssp.maintenance.change_management.impact_assessment_required == true
	input.ssp.maintenance.change_management.approval_authorities_defined == true
	input.ssp.maintenance.change_management.notification_procedures == true
}

document_distribution_controlled if {
	input.ssp.maintenance.distribution.controlled_distribution == true
	input.ssp.maintenance.distribution.authorized_recipients_list == true
	input.ssp.maintenance.distribution.distribution_tracking == true
	input.ssp.maintenance.distribution.confidentiality_marking == true
}

# SSP Quality Assessment
ssp_quality_score := score if {
	total_sections := 7
	passed_sections = count([section |
		sections = [
			ssp_document_structure_valid,
			system_identification_complete,
			system_categorization_documented,
			control_implementation_documented,
			system_environment_documented,
			roles_responsibilities_defined,
			ssp_maintenance_current,
		]
		section = sections[_]
		section == true
	])
	score := (passed_sections * 100) / total_sections
}

# SSP Deficiencies
ssp_deficiencies := deficiencies if {
	structure_deficiencies = [deficiency |
		not ssp_document_structure_valid
		deficiency = {
			"section": "Document Structure",
			"severity": "medium",
			"description": "SSP document structure or format does not meet requirements",
			"remediation": "Ensure proper document format, version control, and approval signatures",
		}
	]

	identification_deficiencies = [deficiency |
		not system_identification_complete
		deficiency = {
			"section": "System Identification",
			"severity": "high",
			"description": "System identification and boundary definition is incomplete",
			"remediation": "Complete system description, boundary definition, and ownership documentation",
		}
	]

	categorization_deficiencies = [deficiency |
		not system_categorization_documented
		deficiency = {
			"section": "System Categorization",
			"severity": "critical",
			"description": "FIPS 199 system categorization is incomplete or incorrect",
			"remediation": "Complete impact analysis and provide proper categorization rationale",
		}
	]

	controls_deficiencies = [deficiency |
		not control_implementation_documented
		deficiency = {
			"section": "Control Implementation",
			"severity": "critical",
			"description": "Security control implementation documentation is inadequate",
			"remediation": "Provide complete control descriptions, implementation details, and responsibility assignments",
		}
	]

	environment_deficiencies = [deficiency |
		not system_environment_documented
		deficiency = {
			"section": "System Environment",
			"severity": "high",
			"description": "System environment documentation is incomplete",
			"remediation": "Complete hardware/software inventories, network architecture, and data flow documentation",
		}
	]

	roles_deficiencies = [deficiency |
		not roles_responsibilities_defined
		deficiency = {
			"section": "Roles and Responsibilities",
			"severity": "high",
			"description": "Key personnel roles and responsibilities are not properly defined",
			"remediation": "Identify all key personnel with complete contact information and role descriptions",
		}
	]

	maintenance_deficiencies = [deficiency |
		not ssp_maintenance_current
		deficiency = {
			"section": "SSP Maintenance",
			"severity": "medium",
			"description": "SSP maintenance procedures are not properly established",
			"remediation": "Implement version control, review cycles, and change management procedures",
		}
	]

	deficiencies := array.concat(structure_deficiencies, array.concat(identification_deficiencies, array.concat(categorization_deficiencies, array.concat(controls_deficiencies, array.concat(environment_deficiencies, array.concat(roles_deficiencies, maintenance_deficiencies))))))
}

# SSP Assessment Report
ssp_assessment := {
	"ssp_compliant": ssp_compliant == true,
	"quality_score": ssp_quality_score,
	"sections_assessment": [
		{
			"section": "Document Structure",
			"compliant": ssp_document_structure_valid == true,
			"description": "Document format, version control, and approval requirements",
		},
		{
			"section": "System Identification",
			"compliant": system_identification_complete == true,
			"description": "System description, boundary definition, and ownership",
		},
		{
			"section": "System Categorization",
			"compliant": system_categorization_documented == true,
			"description": "FIPS 199 categorization and impact analysis",
		},
		{
			"section": "Control Implementation",
			"compliant": control_implementation_documented == true,
			"description": "Security control implementation documentation",
		},
		{
			"section": "System Environment",
			"compliant": system_environment_documented == true,
			"description": "Hardware, software, network, and data flow documentation",
		},
		{
			"section": "Roles and Responsibilities",
			"compliant": roles_responsibilities_defined == true,
			"description": "Key personnel identification and role definitions",
		},
		{
			"section": "SSP Maintenance",
			"compliant": ssp_maintenance_current == true,
			"description": "Version control, review cycles, and change management",
		},
	],
	"total_deficiencies": count(ssp_deficiencies),
	"deficiencies": ssp_deficiencies,
}

# SSP Metadata
ssp_metadata := {
	"document_standard": "NIST SP 800-18 Rev. 1",
	"framework": "FISMA/RMF",
	"purpose": "System Security Plan validation and quality assessment",
	"scope": "Federal information systems requiring FISMA compliance",
	"last_updated": "2025-01-06",
}