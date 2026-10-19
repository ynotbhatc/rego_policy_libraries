# METADATA
# title: "Digital Sovereignty — Software Sovereignty"
# custom:
#   class: compliance
#   framework: digital_sovereignty
#   source: aac
#   domains: [sovereignty, data-residency]
#   coverage:
#     checks: 38
#     cited: 20
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package digital_sovereignty.software_sovereignty

import rego.v1

# Digital Sovereignty — Software Sovereignty
# Ensures the organisation controls its software stack: auditable source,
# known provenance, no hidden update mechanisms, and SBOM coverage.
#
# Input schema:
#   input.software_components[]
#     .component_id, .name, .version
#     .component_type                    — os | middleware | application | library | firmware
#     .vendor_country                    — country of vendor HQ
#     .source_available                  — bool (open source or source escrow)
#     .audited                           — bool
#     .forced_update_mechanism           — bool (vendor can push updates without consent)
#     .telemetry_to_vendor               — bool
#     .telemetry_can_be_disabled         — bool
#     .license_type                      — open_source | proprietary | dual
#     .sbom_available                    — bool
#   input.sbom
#     .maintained                        — bool
#     .format                            — spdx | cyclonedx | swid
#     .last_updated
#     .coverage_pct                      — % of components with SBOM entries
#     .includes_transitive_dependencies  — bool
#   input.update_mechanisms[]
#     .software_id, .update_type         — automatic | manual | vendor_pushed | airgapped
#     .requires_approval_before_update   — bool
#     .update_source_in_jurisdiction     — bool
#   input.code_repositories[]
#     .repo_id, .location_country
#     .hosting_provider_jurisdiction
#     .access_controls_adequate          — bool
#   input.software_provenance
#     .signing.all_artifacts_signed      — bool
#     .signing.key_in_approved_jurisdiction — bool
#     .verification.integrity_checked_on_deploy — bool
#     .verification.hash_validation      — bool
#   input.dependency_management
#     .private_registry_used             — bool
#     .registry_in_approved_jurisdiction — bool
#     .dependency_pinning_enforced       — bool
#     .vulnerability_scanning.enabled    — bool
#     .vulnerability_scanning.last_scan_date

# =============================================================================
# SOFTWARE BILL OF MATERIALS (SBOM)
# =============================================================================

sbom_maintained if {
	input.sbom.maintained == true
	input.sbom.format in ["spdx", "cyclonedx", "swid"]
}

sbom_current if {
	last_update_ns := time.parse_rfc3339_ns(input.sbom.last_updated)
	age_days := (time.now_ns() - last_update_ns) / (24 * 60 * 60 * 1000000000)
	age_days <= 30 # SBOM must be updated monthly
}

sbom_coverage_adequate if {
	is_number(input.sbom.coverage_pct)
	input.sbom.coverage_pct >= 95
}

default sbom_includes_transitive_deps := false

sbom_includes_transitive_deps if {
	input.sbom.includes_transitive_dependencies == true
}

# =============================================================================
# VENDOR PROVENANCE
# =============================================================================

# Critical software components must come from approved-jurisdiction vendors
# or have audited source code
# `not c.field in list` is undefined when the field is absent (the reference is
# hoisted outside the negation), which skipped components with no recorded vendor
# country / repos with no recorded location. Fields are read with object.get so
# an unrecorded value counts against the item (fail closed).
default critical_software_provenance_acceptable := false

critical_software_provenance_acceptable if {
	violations := [c |
		c := input.software_components[_]
		c.component_type in ["os", "middleware", "firmware"]
		not object.get(c, "vendor_country", "") in object.get(input, "approved_jurisdictions", [])
		not c.source_available == true
		not c.audited == true
	]
	count(violations) == 0
}

# All critical components must be auditable (open source or source escrow)
default critical_software_auditable := false

critical_software_auditable if {
	violations := [c |
		c := input.software_components[_]
		c.component_type in ["os", "middleware"]
		not c.source_available == true
		not c.audited == true
	]
	count(violations) == 0
}

# =============================================================================
# UPDATE MECHANISM CONTROL
# =============================================================================

# No vendor-pushed automatic updates without approval for critical systems
default no_uncontrolled_vendor_updates := false

no_uncontrolled_vendor_updates if {
	violations := [u |
		u := input.update_mechanisms[_]
		u.update_type == "vendor_pushed"
		not u.requires_approval_before_update == true
	]
	count(violations) == 0
}

# Update sources must be in approved jurisdictions or use airgapped process
default update_sources_in_jurisdiction := false

update_sources_in_jurisdiction if {
	violations := [u |
		u := input.update_mechanisms[_]
		u.update_type != "airgapped"
		not u.update_source_in_jurisdiction == true
	]
	count(violations) == 0
}

# Components with forced update mechanisms must be flagged and managed
default forced_updates_managed := false

forced_updates_managed if {
	violations := [c |
		c := input.software_components[_]
		c.forced_update_mechanism == true
		not c.forced_update_mitigation_documented == true
	]
	count(violations) == 0
}

# =============================================================================
# TELEMETRY CONTROLS
# =============================================================================

# Vendor telemetry to foreign entities must be disabled or scoped to non-regulated data
default vendor_telemetry_controlled := false

vendor_telemetry_controlled if {
	violations := [c |
		c := input.software_components[_]
		c.telemetry_to_vendor == true
		not object.get(c, "vendor_country", "") in object.get(input, "approved_jurisdictions", [])
		not c.telemetry_can_be_disabled == true
		not c.telemetry_scoped_to_non_regulated == true
	]
	count(violations) == 0
}

# =============================================================================
# SOFTWARE INTEGRITY AND SIGNING
# =============================================================================

# All deployed artifacts must be signed
all_artifacts_signed if {
	input.software_provenance.signing.all_artifacts_signed == true
	input.software_provenance.signing.key_in_approved_jurisdiction == true
}

# Integrity must be verified on deployment
default integrity_verified_on_deploy := false

integrity_verified_on_deploy if {
	input.software_provenance.verification.integrity_checked_on_deploy == true
	input.software_provenance.verification.hash_validation == true
}

# =============================================================================
# DEPENDENCY AND REGISTRY MANAGEMENT
# =============================================================================

# Private package registry must be used (no direct pull from public internet)
private_registry_used if {
	input.dependency_management.private_registry_used == true
	input.dependency_management.registry_in_approved_jurisdiction == true
}

# Dependencies must be pinned to exact versions (no floating versions)
default dependencies_pinned := false

dependencies_pinned if {
	input.dependency_management.dependency_pinning_enforced == true
}

# Vulnerability scanning of dependencies must be enabled and current
dependency_vulnerability_scanning if {
	input.dependency_management.vulnerability_scanning.enabled == true
	last_scan_ns := time.parse_rfc3339_ns(input.dependency_management.vulnerability_scanning.last_scan_date)
	scan_age_days := (time.now_ns() - last_scan_ns) / (24 * 60 * 60 * 1000000000)
	scan_age_days <= 7
}

# =============================================================================
# SOURCE CODE REPOSITORY CONTROLS
# =============================================================================

# Source code repositories must be in approved jurisdictions
default code_repos_in_jurisdiction := false

code_repos_in_jurisdiction if {
	violations := [r |
		r := input.code_repositories[_]
		not object.get(r, "location_country", "") in object.get(input, "approved_jurisdictions", [])
		not object.get(r, "hosting_provider_jurisdiction", "") in object.get(input, "approved_jurisdictions", [])
	]
	count(violations) == 0
}

# Repositories must have adequate access controls
default repo_access_controls_adequate := false

repo_access_controls_adequate if {
	violations := [r |
		r := input.code_repositories[_]
		not r.access_controls_adequate == true
	]
	count(violations) == 0
}

# =============================================================================
# OPEN SOURCE POLICY
# =============================================================================

# Open source components must have compatible licenses
default open_source_license_reviewed := false

open_source_license_reviewed if {
	violations := [c |
		c := input.software_components[_]
		c.license_type == "open_source"
		not c.license_reviewed == true
	]
	count(violations) == 0
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not sbom_maintained
	v := {
		"domain": "software_sovereignty",
		"control": "SS-001",
		"severity": "high",
		"description": "Software Bill of Materials (SBOM) not maintained or not in recognised format (SPDX/CycloneDX)",
		"remediation": "Generate and maintain SBOM in SPDX or CycloneDX format for all software components",
	}
}

violations contains v if {
	not sbom_current
	v := {
		"domain": "software_sovereignty",
		"control": "SS-002",
		"severity": "medium",
		"description": "SBOM not updated within the last 30 days",
		"remediation": "Integrate SBOM generation into CI/CD pipeline to maintain current SBOM",
	}
}

violations contains v if {
	not sbom_coverage_adequate
	v := {
		"domain": "software_sovereignty",
		"control": "SS-003",
		"severity": "medium",
		"description": concat("", ["SBOM coverage insufficient (or not recorded): ", sprintf("%v", [object.get(object.get(input, "sbom", {}), "coverage_pct", "not recorded")]), "% (requires 95%)"]),
		"remediation": "Expand SBOM tooling to cover all components including transitive dependencies",
	}
}

violations contains v if {
	not critical_software_provenance_acceptable
	c := input.software_components[_]
	c.component_type in ["os", "middleware", "firmware"]
	not object.get(c, "vendor_country", "") in object.get(input, "approved_jurisdictions", [])
	not c.source_available == true
	not c.audited == true
	v := {
		"domain": "software_sovereignty",
		"control": "SS-004",
		"severity": "high",
		"component_id": object.get(c, "component_id", "unknown"),
		"description": concat("", ["Critical software component from unapproved jurisdiction without audit: ", object.get(c, "name", "unknown"), " (", object.get(c, "vendor_country", "unknown"), ")"]),
		"remediation": "Replace with approved-jurisdiction equivalent, obtain source code escrow, or conduct security audit",
	}
}

violations contains v if {
	not no_uncontrolled_vendor_updates
	u := input.update_mechanisms[_]
	u.update_type == "vendor_pushed"
	not u.requires_approval_before_update == true
	v := {
		"domain": "software_sovereignty",
		"control": "SS-005",
		"severity": "critical",
		"software_id": object.get(u, "software_id", "unknown"),
		"description": concat("", ["Vendor can push updates without approval: ", object.get(u, "software_id", "unknown")]),
		"remediation": "Disable automatic vendor updates; require internal testing and approval before deployment",
	}
}

violations contains v if {
	not vendor_telemetry_controlled
	c := input.software_components[_]
	c.telemetry_to_vendor == true
	not object.get(c, "vendor_country", "") in object.get(input, "approved_jurisdictions", [])
	not c.telemetry_can_be_disabled == true
	v := {
		"domain": "software_sovereignty",
		"control": "SS-006",
		"severity": "high",
		"component_id": object.get(c, "component_id", "unknown"),
		"description": concat("", ["Software sends telemetry to foreign vendor and cannot be disabled: ", object.get(c, "name", "unknown")]),
		"remediation": "Disable telemetry, restrict network access, or replace with sovereignty-compliant alternative",
	}
}

violations contains v if {
	not all_artifacts_signed
	v := {
		"domain": "software_sovereignty",
		"control": "SS-007",
		"severity": "high",
		"description": "Not all deployed artifacts are signed or signing keys not in approved jurisdiction",
		"remediation": "Implement code signing for all artifacts with keys managed in approved jurisdiction",
	}
}

violations contains v if {
	not private_registry_used
	v := {
		"domain": "software_sovereignty",
		"control": "SS-008",
		"severity": "high",
		"description": "No private package registry in use — dependencies pulled from public internet",
		"remediation": "Deploy private package registry (Nexus, Artifactory, etc.) in approved jurisdiction",
	}
}

violations contains v if {
	not dependency_vulnerability_scanning
	v := {
		"domain": "software_sovereignty",
		"control": "SS-009",
		"severity": "high",
		"description": "Dependency vulnerability scanning not enabled or last scan older than 7 days",
		"remediation": "Enable automated dependency scanning in CI/CD pipeline with weekly minimum frequency",
	}
}

violations contains v if {
	not code_repos_in_jurisdiction
	r := input.code_repositories[_]
	not object.get(r, "location_country", "") in object.get(input, "approved_jurisdictions", [])
	not object.get(r, "hosting_provider_jurisdiction", "") in object.get(input, "approved_jurisdictions", [])
	v := {
		"domain": "software_sovereignty",
		"control": "SS-010",
		"severity": "high",
		"repo_id": object.get(r, "repo_id", "unknown"),
		"description": concat("", ["Source code repository hosted outside approved jurisdiction: ", object.get(r, "repo_id", "unknown")]),
		"remediation": "Migrate repositories to in-jurisdiction hosting or self-hosted git in approved jurisdiction",
	}
}

# Controls that gate `compliant` and previously had no violation entry
# (compliant could be false with violation_count 0).
violations contains v if {
	not sbom_includes_transitive_deps
	v := {
		"domain": "software_sovereignty",
		"control": "SS-011",
		"severity": "medium",
		"description": "SBOM does not include transitive dependencies",
		"remediation": "Generate the SBOM with transitive dependency resolution enabled",
	}
}

violations contains v if {
	not update_sources_in_jurisdiction
	v := {
		"domain": "software_sovereignty",
		"control": "SS-012",
		"severity": "high",
		"description": "One or more update sources are outside approved jurisdictions (and not air-gapped)",
		"remediation": "Mirror updates through an in-jurisdiction source or use an air-gapped update process",
	}
}

violations contains v if {
	not forced_updates_managed
	v := {
		"domain": "software_sovereignty",
		"control": "SS-013",
		"severity": "high",
		"description": "One or more components have a forced update mechanism with no documented mitigation",
		"remediation": "Document and enforce a mitigation (staging, approval gate or network control) for forced vendor updates",
	}
}

violations contains v if {
	not integrity_verified_on_deploy
	v := {
		"domain": "software_sovereignty",
		"control": "SS-014",
		"severity": "high",
		"description": "Artifact integrity and hash validation are not verified on deployment",
		"remediation": "Verify signatures and hashes of every artifact at deploy time",
	}
}

violations contains v if {
	not dependencies_pinned
	v := {
		"domain": "software_sovereignty",
		"control": "SS-015",
		"severity": "medium",
		"description": "Dependency version pinning is not enforced",
		"remediation": "Pin dependencies to exact versions and enforce it in CI",
	}
}

violations contains v if {
	not repo_access_controls_adequate
	v := {
		"domain": "software_sovereignty",
		"control": "SS-016",
		"severity": "high",
		"description": "One or more source code repositories lack adequate access controls",
		"remediation": "Apply least-privilege access controls and MFA to all source code repositories",
	}
}

violations contains v if {
	not critical_software_auditable
	v := {
		"domain": "software_sovereignty",
		"control": "SS-017",
		"severity": "high",
		"description": "One or more critical OS/middleware components are neither source-available nor independently audited",
		"remediation": "Use open-source or source-escrow components for critical software, or commission an independent audit",
	}
}

violations contains v if {
	not open_source_license_reviewed
	v := {
		"domain": "software_sovereignty",
		"control": "SS-018",
		"severity": "medium",
		"description": "One or more open source components have not had their license reviewed",
		"remediation": "Review and record the license of every open source component",
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	sbom_maintained
	sbom_current
	sbom_coverage_adequate
	sbom_includes_transitive_deps
	critical_software_provenance_acceptable
	no_uncontrolled_vendor_updates
	update_sources_in_jurisdiction
	forced_updates_managed
	vendor_telemetry_controlled
	all_artifacts_signed
	integrity_verified_on_deploy
	private_registry_used
	dependencies_pinned
	dependency_vulnerability_scanning
	code_repos_in_jurisdiction
	repo_access_controls_adequate
	critical_software_auditable
	open_source_license_reviewed
}

report := {
	"domain": "Software Sovereignty",
	"compliant": compliant,
	"controls": {
		"SS-001_sbom_maintained": sbom_maintained,
		"SS-002_sbom_current": sbom_current,
		"SS-003_sbom_coverage": sbom_coverage_adequate,
		"SS-004_provenance_acceptable": critical_software_provenance_acceptable,
		"SS-005_no_uncontrolled_updates": no_uncontrolled_vendor_updates,
		"SS-006_telemetry_controlled": vendor_telemetry_controlled,
		"SS-007_artifacts_signed": all_artifacts_signed,
		"SS-008_private_registry": private_registry_used,
		"SS-009_vuln_scanning": dependency_vulnerability_scanning,
		"SS-010_repos_in_jurisdiction": code_repos_in_jurisdiction,
		"SS-011_sbom_transitive_deps": sbom_includes_transitive_deps,
		"SS-012_update_sources_in_jurisdiction": update_sources_in_jurisdiction,
		"SS-013_forced_updates_managed": forced_updates_managed,
		"SS-014_integrity_verified_on_deploy": integrity_verified_on_deploy,
		"SS-015_dependencies_pinned": dependencies_pinned,
		"SS-016_repo_access_controls": repo_access_controls_adequate,
		"SS-017_critical_software_auditable": critical_software_auditable,
		"SS-018_open_source_license_reviewed": open_source_license_reviewed,
	},
	"sbom_summary": {
		"maintained": object.get(input, ["sbom", "maintained"], false),
		"coverage_pct": object.get(input, ["sbom", "coverage_pct"], 0),
		"format": object.get(input, ["sbom", "format"], "none"),
	},
	"violations": violations,
	"violation_count": count(violations),
}

# Defaults for control rules — ensure report never collapses to {} on absent facts
default all_artifacts_signed := false
default dependency_vulnerability_scanning := false
default private_registry_used := false
default sbom_coverage_adequate := false
default sbom_current := false
default sbom_maintained := false
