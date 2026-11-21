# METADATA
# title: "NIST SP 800-53 Rev 5 — Configuration Management (CM) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 47
#     cited: 35
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.configuration_management

import rego.v1

# NIST SP 800-53 Rev 5 — Configuration Management (CM) Family
# Baseline configurations, change control, and configuration monitoring. Every active base control CM-1 to CM-14,
# the NIST SP 800-53B Moderate-baseline enhancements, and the enhancements the NIST and FedRAMP High baselines
# add. An enhancement is its own requirement with its own finding; a base control never fails for an enhancement.
#
# CM-1 to CM-11 read one boolean each (input.cm_controls.<name>.<flag>) and pass only when it is true; a flag that
# is absent or not a boolean ("yes", 1, "true", null, an object) is reported as evidence missing, a flag that is
# false keeps its original message.
# CM-12 to CM-14 and the enhancements fail closed: a fact that is absent or of the wrong type is evidence missing;
# booleans pass only on true; counts and frequencies are checked with is_number before any comparison.

default compliant := false

# ---------------------------------------------------------------------------------------------------------------
# Helpers. Paths are dotted and relative to input.cm_controls.
# ---------------------------------------------------------------------------------------------------------------

_get(path) := object.get(input, array.concat(["cm_controls"], split(path, ".")), null)

_path(p) := concat("", ["input.cm_controls.", p])

_missing_txt(paths) := sprintf("evidence missing — %s not collected", [concat(", ", sort(paths))])

# Required booleans that are absent or not a boolean ("true", 1 and null are not evidence).
_bool_missing(paths) := {_path(p) |
	some p in paths
	not is_boolean(_get(p))
}

# Required booleans that are present and false: `checks` is a list of [path, text when false].
_bool_false(checks) := {sprintf("%s (%s is false)", [c[1], _path(c[0])]) |
	some c in checks
	_get(c[0]) == false
}

_paths(checks) := [c[0] | some c in checks]

# Counts that must be zero (exceptions found by a tool or a records query). A non-number, a negative or a fractional
# number is missing evidence.
# Days and other non-negative measures (not counts): a non-negative number.
_nonneg(x) if {
	is_number(x)
	x >= 0
}

_count_ok(x) if {
	is_number(x)
	x >= 0
	floor(x) == x
}

_zero_missing(paths) := {_path(p) |
	some p in paths
	not _count_ok(_get(p))
}

_zero_unmet(checks) := {sprintf(c[1], [n]) |
	some c in checks
	n := _get(c[0])
	is_number(n)
	_count_ok(n)
	n > 0
}

# Organization-defined frequency (IR-2/IR-3 shape): <base>.days_since_last against <base>.odp.frequency_days.
_freq_missing(base) := {_path(concat(".", [base, k])) |
	some k in ["days_since_last", "odp.frequency_days"]
	not _nonneg(_get(concat(".", [base, k])))
}

_overdue(base, what) := {msg |
	obs := _get(concat(".", [base, "days_since_last"]))
	odp := _get(concat(".", [base, "odp.frequency_days"]))
	is_number(obs)
	is_number(odp)
	obs > odp
	msg := sprintf("%s %v days ago; the organization-defined frequency is %v days", [what, obs, odp])
}

# One finding per id: evidence missing first, then every unmet element.
_detail(missing, unmet) := _missing_txt(missing) if {
	count(missing) > 0
	count(unmet) == 0
} else := sprintf("%s; %s", [concat("; ", sort(unmet)), _missing_txt(missing)]) if {
	count(missing) > 0
} else := concat("; ", sort(unmet))

violation contains msg if {
	not is_boolean(_get("policy.documented"))
	msg := sprintf("NIST CM-1: %s", [_missing_txt({_path("policy.documented")})])
}

violation contains msg if {
	input.cm_controls.policy.documented == false
	msg := "NIST CM-1: Configuration management policy not documented"
}

violation contains msg if {
	not is_boolean(_get("baseline_config.maintained"))
	msg := sprintf("NIST CM-2: %s", [_missing_txt({_path("baseline_config.maintained")})])
}

violation contains msg if {
	input.cm_controls.baseline_config.maintained == false
	msg := "NIST CM-2: Baseline configuration not established or maintained for the system"
}

violation contains msg if {
	not is_boolean(_get("change_control.process_exists"))
	msg := sprintf("NIST CM-3: %s", [_missing_txt({_path("change_control.process_exists")})])
}

violation contains msg if {
	input.cm_controls.change_control.process_exists == false
	msg := "NIST CM-3: Configuration change control process not in place"
}

violation contains msg if {
	not is_boolean(_get("security_impact_analysis.performed"))
	msg := sprintf("NIST CM-4: %s", [_missing_txt({_path("security_impact_analysis.performed")})])
}

violation contains msg if {
	input.cm_controls.security_impact_analysis.performed == false
	msg := "NIST CM-4: Impact analysis (security and privacy) not performed before changes are implemented"
}

violation contains msg if {
	not is_boolean(_get("access_restrictions_for_change.enforced"))
	msg := sprintf("NIST CM-5: %s", [_missing_txt({_path("access_restrictions_for_change.enforced")})])
}

violation contains msg if {
	input.cm_controls.access_restrictions_for_change.enforced == false
	msg := "NIST CM-5: Access restrictions for change are not enforced"
}

violation contains msg if {
	not is_boolean(_get("configuration_settings.documented"))
	msg := sprintf("NIST CM-6: %s", [_missing_txt({_path("configuration_settings.documented")})])
}

violation contains msg if {
	input.cm_controls.configuration_settings.documented == false
	msg := "NIST CM-6: Mandatory configuration settings not documented or applied"
}

violation contains msg if {
	not is_boolean(_get("least_functionality.enforced"))
	msg := sprintf("NIST CM-7: %s", [_missing_txt({_path("least_functionality.enforced")})])
}

violation contains msg if {
	input.cm_controls.least_functionality.enforced == false
	msg := "NIST CM-7: Least functionality (disable unused services/ports) not enforced"
}

violation contains msg if {
	not is_boolean(_get("system_component_inventory.maintained"))
	msg := sprintf("NIST CM-8: %s", [_missing_txt({_path("system_component_inventory.maintained")})])
}

violation contains msg if {
	input.cm_controls.system_component_inventory.maintained == false
	msg := "NIST CM-8: System component inventory not maintained or accurate"
}

violation contains msg if {
	not is_boolean(_get("config_management_plan.documented"))
	msg := sprintf("NIST CM-9: %s", [_missing_txt({_path("config_management_plan.documented")})])
}

violation contains msg if {
	input.cm_controls.config_management_plan.documented == false
	msg := "NIST CM-9: Configuration management plan not documented"
}

violation contains msg if {
	not is_boolean(_get("software_usage_restrictions.enforced"))
	msg := sprintf("NIST CM-10: %s", [_missing_txt({_path("software_usage_restrictions.enforced")})])
}

violation contains msg if {
	input.cm_controls.software_usage_restrictions.enforced == false
	msg := "NIST CM-10: Software usage restrictions (licensing/copy controls) not enforced"
}

violation contains msg if {
	not is_boolean(_get("user_installed_software.restricted"))
	msg := sprintf("NIST CM-11: %s", [_missing_txt({_path("user_installed_software.restricted")})])
}

violation contains msg if {
	input.cm_controls.user_installed_software.restricted == false
	msg := "NIST CM-11: User-installed software is not restricted by policy"
}

# ---------------------------------------------------------------------------------------------------------------
# CM-2(2) Automation Support for Accuracy and Currency: the baseline configuration is kept current, complete,
# accurate and available by an automated mechanism.
# Facts: baseline_config.automation.automated (boolean: an automated mechanism maintains the baseline);
#        baseline_config.automation.components_not_covered (number of in-scope components the mechanism does not
#        cover; must be 0).
# ---------------------------------------------------------------------------------------------------------------

_cm2_2_bools := [["baseline_config.automation.automated", "baseline configuration not maintained by an automated mechanism"]]

_cm2_2_zeros := [["baseline_config.automation.components_not_covered", "%v components not covered by the automated baseline mechanism"]]

_cm2_2_missing := _bool_missing(_paths(_cm2_2_bools)) | _zero_missing(_paths(_cm2_2_zeros))

_cm2_2_unmet := _bool_false(_cm2_2_bools) | _zero_unmet(_cm2_2_zeros)

violation contains msg if {
	count(_cm2_2_missing | _cm2_2_unmet) > 0
	msg := sprintf("NIST CM-2(2): %s", [_detail(_cm2_2_missing, _cm2_2_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# CM-2(3) Retention of Previous Configurations: the organization-defined number of previous baseline versions is
# retained to support rollback.
# Facts: baseline_config.previous_versions.retained_count (number of previous versions held) against
#        baseline_config.previous_versions.odp.retained_count (organization-defined number).
# ---------------------------------------------------------------------------------------------------------------

_cm2_3_obs := _get("baseline_config.previous_versions.retained_count")

_cm2_3_odp := _get("baseline_config.previous_versions.odp.retained_count")

_cm2_3_missing := {_path(p) |
	some pair in [["baseline_config.previous_versions.retained_count", _cm2_3_obs], ["baseline_config.previous_versions.odp.retained_count", _cm2_3_odp]]
	not _count_ok(pair[1])
	p := pair[0]
}

violation contains msg if {
	count(_cm2_3_missing) > 0
	msg := sprintf("NIST CM-2(3): %s", [_missing_txt(_cm2_3_missing)])
}

violation contains msg if {
	count(_cm2_3_missing) == 0
	is_number(_cm2_3_obs)
	is_number(_cm2_3_odp)
	_cm2_3_obs < _cm2_3_odp
	msg := sprintf("NIST CM-2(3): %v previous baseline configuration versions retained; the organization-defined number is %v", [_cm2_3_obs, _cm2_3_odp])
}

# ---------------------------------------------------------------------------------------------------------------
# CM-2(7) Configure Systems and Components for High-risk Areas: devices issued for travel to high-risk locations
# carry the organization-defined configurations, and the organization-defined controls are applied on return.
# Facts: baseline_config.high_risk_travel.devices_issued_without_defined_config,
#        baseline_config.high_risk_travel.returned_devices_without_controls (numbers from device-management
#        records; both must be 0).
# ---------------------------------------------------------------------------------------------------------------

_cm2_7_zeros := [
	["baseline_config.high_risk_travel.devices_issued_without_defined_config", "%v devices issued for high-risk travel without the organization-defined configuration"],
	["baseline_config.high_risk_travel.returned_devices_without_controls", "%v devices returned from high-risk travel without the organization-defined controls applied"],
]

_cm2_7_missing := _zero_missing(_paths(_cm2_7_zeros))

_cm2_7_unmet := _zero_unmet(_cm2_7_zeros)

violation contains msg if {
	count(_cm2_7_missing | _cm2_7_unmet) > 0
	msg := sprintf("NIST CM-2(7): %s", [_detail(_cm2_7_missing, _cm2_7_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# CM-3(2) Testing, Validation, and Documentation of Changes: changes are tested, validated and documented before
# implementation is finalized.
# Facts: change_control.testing.changes_without_test_record (number of finalized changes in the review period
#        with no test, validation and documentation record; must be 0).
# ---------------------------------------------------------------------------------------------------------------

_cm3_2_zeros := [["change_control.testing.changes_without_test_record", "%v changes finalized without a test, validation and documentation record"]]

_cm3_2_missing := _zero_missing(_paths(_cm3_2_zeros))

_cm3_2_unmet := _zero_unmet(_cm3_2_zeros)

violation contains msg if {
	count(_cm3_2_missing | _cm3_2_unmet) > 0
	msg := sprintf("NIST CM-3(2): %s", [_detail(_cm3_2_missing, _cm3_2_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# CM-3(4) Security and Privacy Representatives: the organization-defined security and privacy representatives
# are members of the configuration change control element.
# Facts: change_control.representatives.security_member, change_control.representatives.privacy_member
#        (booleans, from the change control board membership roster).
# ---------------------------------------------------------------------------------------------------------------

_cm3_4_bools := [
	["change_control.representatives.security_member", "no security representative on the configuration change control element"],
	["change_control.representatives.privacy_member", "no privacy representative on the configuration change control element"],
]

_cm3_4_missing := _bool_missing(_paths(_cm3_4_bools))

_cm3_4_unmet := _bool_false(_cm3_4_bools)

violation contains msg if {
	count(_cm3_4_missing | _cm3_4_unmet) > 0
	msg := sprintf("NIST CM-3(4): %s", [_detail(_cm3_4_missing, _cm3_4_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# CM-4(2) Verification of Controls: after changes, the impacted controls are verified as implemented correctly,
# operating as intended and producing the desired outcome.
# Facts: security_impact_analysis.control_verification.changes_without_verification (number of implemented
#        changes in the review period with no post-change control verification; must be 0).
# ---------------------------------------------------------------------------------------------------------------

_cm4_2_zeros := [["security_impact_analysis.control_verification.changes_without_verification", "%v changes implemented without verification of the impacted controls"]]

_cm4_2_missing := _zero_missing(_paths(_cm4_2_zeros))

_cm4_2_unmet := _zero_unmet(_cm4_2_zeros)

violation contains msg if {
	count(_cm4_2_missing | _cm4_2_unmet) > 0
	msg := sprintf("NIST CM-4(2): %s", [_detail(_cm4_2_missing, _cm4_2_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# CM-7(1) Periodic Review: the system is reviewed at the organization-defined frequency for unnecessary or
# nonsecure functions, ports, protocols, software and services, and those found are disabled or removed.
# Facts: least_functionality.periodic_review.days_since_last + .odp.frequency_days;
#        least_functionality.periodic_review.unnecessary_items_enabled (number of items the last review found
#        unnecessary or nonsecure that are still enabled; must be 0).
# ---------------------------------------------------------------------------------------------------------------

_cm7_1_zeros := [["least_functionality.periodic_review.unnecessary_items_enabled", "%v unnecessary or nonsecure functions, ports, protocols, software or services still enabled"]]

_cm7_1_missing := _freq_missing("least_functionality.periodic_review") | _zero_missing(_paths(_cm7_1_zeros))

_cm7_1_unmet := _overdue("least_functionality.periodic_review", "least functionality last reviewed") | _zero_unmet(_cm7_1_zeros)

violation contains msg if {
	count(_cm7_1_missing | _cm7_1_unmet) > 0
	msg := sprintf("NIST CM-7(1): %s", [_detail(_cm7_1_missing, _cm7_1_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# CM-7(2) Prevent Program Execution: program execution is prevented in accordance with the organization's
# software usage rules.
# Facts: least_functionality.program_execution.prevention_enforced (boolean: an execution-control mechanism such
#        as fapolicyd, AppLocker or WDAC is in enforcing mode).
# ---------------------------------------------------------------------------------------------------------------

_cm7_2_bools := [["least_functionality.program_execution.prevention_enforced", "program execution not prevented according to the software usage rules"]]

_cm7_2_missing := _bool_missing(_paths(_cm7_2_bools))

_cm7_2_unmet := _bool_false(_cm7_2_bools)

violation contains msg if {
	count(_cm7_2_missing | _cm7_2_unmet) > 0
	msg := sprintf("NIST CM-7(2): %s", [_detail(_cm7_2_missing, _cm7_2_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# CM-7(5) Authorized Software — Allow-by-exception: authorized software is identified, a deny-all,
# permit-by-exception policy governs execution, and the list is reviewed at the organization-defined frequency.
# Facts: least_functionality.authorized_software.list_defined, .deny_all_permit_by_exception (booleans);
#        least_functionality.authorized_software.list_review.days_since_last + .list_review.odp.frequency_days.
# ---------------------------------------------------------------------------------------------------------------

_cm7_5_bools := [
	["least_functionality.authorized_software.list_defined", "authorized software programs not identified"],
	["least_functionality.authorized_software.deny_all_permit_by_exception", "software execution not governed by a deny-all, permit-by-exception policy"],
]

_cm7_5_missing := _bool_missing(_paths(_cm7_5_bools)) | _freq_missing("least_functionality.authorized_software.list_review")

_cm7_5_unmet := _bool_false(_cm7_5_bools) | _overdue("least_functionality.authorized_software.list_review", "authorized software list last reviewed")

violation contains msg if {
	count(_cm7_5_missing | _cm7_5_unmet) > 0
	msg := sprintf("NIST CM-7(5): %s", [_detail(_cm7_5_missing, _cm7_5_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# CM-8(1) Updates During Installation and Removal: the component inventory is updated as part of installations,
# removals and system updates.
# Facts: system_component_inventory.updates.changes_not_reflected (number of component installations, removals
#        or updates in the review period not reflected in the inventory; must be 0).
# ---------------------------------------------------------------------------------------------------------------

_cm8_1_zeros := [["system_component_inventory.updates.changes_not_reflected", "%v component installations, removals or updates not reflected in the inventory"]]

_cm8_1_missing := _zero_missing(_paths(_cm8_1_zeros))

_cm8_1_unmet := _zero_unmet(_cm8_1_zeros)

violation contains msg if {
	count(_cm8_1_missing | _cm8_1_unmet) > 0
	msg := sprintf("NIST CM-8(1): %s", [_detail(_cm8_1_missing, _cm8_1_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# CM-8(3) Automated Unauthorized Component Detection: unauthorized hardware, software and firmware are detected by
# automated mechanisms at the organization-defined frequency, and the organization-defined actions are taken.
# Facts: system_component_inventory.unauthorized_detection.automated (boolean);
#        system_component_inventory.unauthorized_detection.scan.days_since_last + .scan.odp.frequency_days;
#        system_component_inventory.unauthorized_detection.detected_without_action (number of unauthorized
#        components detected with no organization-defined action taken; must be 0).
# ---------------------------------------------------------------------------------------------------------------

_cm8_3_bools := [["system_component_inventory.unauthorized_detection.automated", "unauthorized components not detected by an automated mechanism"]]

_cm8_3_zeros := [["system_component_inventory.unauthorized_detection.detected_without_action", "%v unauthorized components detected without the organization-defined action"]]

_cm8_3_missing := (_bool_missing(_paths(_cm8_3_bools)) | _freq_missing("system_component_inventory.unauthorized_detection.scan")) | _zero_missing(_paths(_cm8_3_zeros))

_cm8_3_unmet := (_bool_false(_cm8_3_bools) | _overdue("system_component_inventory.unauthorized_detection.scan", "unauthorized component detection last run")) | _zero_unmet(_cm8_3_zeros)

violation contains msg if {
	count(_cm8_3_missing | _cm8_3_unmet) > 0
	msg := sprintf("NIST CM-8(3): %s", [_detail(_cm8_3_missing, _cm8_3_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# CM-12 Information Location: the location of the organization-defined information and the components that
# process and store it are documented, as are the users with access to them and changes of location.
# Facts: information_location.locations_documented, .users_with_access_documented, .location_changes_documented
#        (booleans).
# ---------------------------------------------------------------------------------------------------------------

_cm12_bools := [
	["information_location.locations_documented", "location of the organization-defined information and its components not documented"],
	["information_location.users_with_access_documented", "users with access to the components holding the information not documented"],
	["information_location.location_changes_documented", "changes to the location of the information not documented"],
]

_cm12_missing := _bool_missing(_paths(_cm12_bools))

_cm12_unmet := _bool_false(_cm12_bools)

violation contains msg if {
	count(_cm12_missing | _cm12_unmet) > 0
	msg := sprintf("NIST CM-12: %s", [_detail(_cm12_missing, _cm12_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# CM-12(1) Automated Tools to Support Information Location: automated tools identify the organization-defined
# information types on the organization-defined components.
# Facts: information_location.automated_discovery.tool_in_use (boolean: a data discovery or classification tool
#        runs); information_location.automated_discovery.components_not_scanned (number of organization-defined
#        components the tool does not scan; must be 0).
# ---------------------------------------------------------------------------------------------------------------

_cm12_1_bools := [["information_location.automated_discovery.tool_in_use", "no automated tool identifies the organization-defined information"]]

_cm12_1_zeros := [["information_location.automated_discovery.components_not_scanned", "%v organization-defined components not scanned by the automated information-location tool"]]

_cm12_1_missing := _bool_missing(_paths(_cm12_1_bools)) | _zero_missing(_paths(_cm12_1_zeros))

_cm12_1_unmet := _bool_false(_cm12_1_bools) | _zero_unmet(_cm12_1_zeros)

violation contains msg if {
	count(_cm12_1_missing | _cm12_1_unmet) > 0
	msg := sprintf("NIST CM-12(1): %s", [_detail(_cm12_1_missing, _cm12_1_unmet)])
}

# ===============================================================================================================
# Base controls CM-13 and CM-14, and the High-baseline enhancements.
# ===============================================================================================================

# ---------------------------------------------------------------------------------------------------------------
# CM-13 Data Action Mapping: a map of the system's data actions (collection, processing, retention, disclosure,
# disposal of personally identifiable information) is developed and documented.
# Facts: data_action_map.documented (boolean: the map exists in the privacy or architecture record);
#        data_action_map.data_actions_not_mapped (number of data actions in the system's processing inventory
#        with no entry in the map; must be 0).
# ---------------------------------------------------------------------------------------------------------------

_cm13_bools := [["data_action_map.documented", "no map of system data actions developed and documented"]]

_cm13_zeros := [["data_action_map.data_actions_not_mapped", "%v system data actions not in the data action map"]]

_cm13_missing := _bool_missing(_paths(_cm13_bools)) | _zero_missing(_paths(_cm13_zeros))

_cm13_unmet := _bool_false(_cm13_bools) | _zero_unmet(_cm13_zeros)

violation contains msg if {
	count(_cm13_missing | _cm13_unmet) > 0
	msg := sprintf("NIST CM-13: %s", [_detail(_cm13_missing, _cm13_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# CM-14 Signed Components: installation of the organization-defined software and firmware components is blocked
# unless the component carries a digital signature from an organization-approved certificate.
# Facts: signed_components.signature_verification_enforced (boolean: the installer refuses unsigned or untrusted
#        components, e.g. dnf gpgcheck=1 with approved keys, UEFI Secure Boot, an admission policy that verifies
#        image signatures); signed_components.installed_without_verified_signature (number of installed
#        organization-defined components with no verified approved signature; must be 0).
# ---------------------------------------------------------------------------------------------------------------

_cm14_bools := [["signed_components.signature_verification_enforced", "installation of the organization-defined components not blocked without a verified approved signature"]]

_cm14_zeros := [["signed_components.installed_without_verified_signature", "%v organization-defined components installed without a verified signature from an approved certificate"]]

_cm14_missing := _bool_missing(_paths(_cm14_bools)) | _zero_missing(_paths(_cm14_zeros))

_cm14_unmet := _bool_false(_cm14_bools) | _zero_unmet(_cm14_zeros)

violation contains msg if {
	count(_cm14_missing | _cm14_unmet) > 0
	msg := sprintf("NIST CM-14: %s", [_detail(_cm14_missing, _cm14_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# CM-3(1) Automated Documentation, Notification, and Prohibition of Changes: an automated change management
# mechanism documents proposed changes, notifies the approval authorities and requests approval, highlights
# proposals not approved or disapproved within the organization-defined time period, blocks changes until
# approved, documents every change, and notifies the organization-defined personnel when approved changes are
# completed.
# Facts (booleans, from the change management tool configuration) under change_control.automation:
#        documents_proposed_changes, notifies_approval_authorities, prohibits_unapproved_changes,
#        documents_all_changes, notifies_on_completion;
#        change_control.automation.highlight_after_days (the tool's configured age at which an undecided proposal
#        is highlighted) against change_control.automation.odp.time_period_days (organization-defined period);
#        configured above the organization-defined period is a finding.
# ---------------------------------------------------------------------------------------------------------------

_cm3_1_bools := [
	["change_control.automation.documents_proposed_changes", "proposed changes not documented by an automated mechanism"],
	["change_control.automation.notifies_approval_authorities", "approval authorities not notified of proposed changes by an automated mechanism"],
	["change_control.automation.prohibits_unapproved_changes", "changes not prohibited by an automated mechanism until approved"],
	["change_control.automation.documents_all_changes", "changes not all documented by an automated mechanism"],
	["change_control.automation.notifies_on_completion", "organization-defined personnel not notified by an automated mechanism when approved changes are completed"],
]

_cm3_1_highlight := _get("change_control.automation.highlight_after_days")

_cm3_1_period := _get("change_control.automation.odp.time_period_days")

_cm3_1_num_missing := {_path(p) |
	some pair in [["change_control.automation.highlight_after_days", _cm3_1_highlight], ["change_control.automation.odp.time_period_days", _cm3_1_period]]
	not _nonneg(pair[1])
	p := pair[0]
}

_cm3_1_late := {msg |
	is_number(_cm3_1_highlight)
	is_number(_cm3_1_period)
	_cm3_1_highlight > _cm3_1_period
	msg := sprintf("undecided proposed changes highlighted after %v days; the organization-defined time period is %v days", [_cm3_1_highlight, _cm3_1_period])
}

_cm3_1_missing := _bool_missing(_paths(_cm3_1_bools)) | _cm3_1_num_missing

_cm3_1_unmet := _bool_false(_cm3_1_bools) | _cm3_1_late

violation contains msg if {
	count(_cm3_1_missing | _cm3_1_unmet) > 0
	msg := sprintf("NIST CM-3(1): %s", [_detail(_cm3_1_missing, _cm3_1_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# CM-3(6) Cryptography Management: the cryptographic mechanisms that provide the organization-defined controls
# are under configuration management.
# Facts: change_control.cryptography.mechanisms_not_under_cm (number of cryptographic mechanisms in scope, such as
#        crypto policies, key stores, certificates and TLS configurations, with no configuration management
#        record; must be 0).
# ---------------------------------------------------------------------------------------------------------------

_cm3_6_zeros := [["change_control.cryptography.mechanisms_not_under_cm", "%v cryptographic mechanisms providing the organization-defined controls not under configuration management"]]

_cm3_6_missing := _zero_missing(_paths(_cm3_6_zeros))

_cm3_6_unmet := _zero_unmet(_cm3_6_zeros)

violation contains msg if {
	count(_cm3_6_missing | _cm3_6_unmet) > 0
	msg := sprintf("NIST CM-3(6): %s", [_detail(_cm3_6_missing, _cm3_6_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# CM-4(1) Separate Test Environments: changes are analyzed in a test environment separate from the operational
# environment before they are implemented.
# Facts: security_impact_analysis.test_environment.separate (boolean: a test environment exists that is separate
#        from production); security_impact_analysis.test_environment.changes_not_analyzed (number of changes
#        implemented in the review period with no record of analysis in the separate test environment; must be 0).
# ---------------------------------------------------------------------------------------------------------------

_cm4_1_bools := [["security_impact_analysis.test_environment.separate", "no test environment separate from the operational environment"]]

_cm4_1_zeros := [["security_impact_analysis.test_environment.changes_not_analyzed", "%v changes implemented without analysis in a separate test environment"]]

_cm4_1_missing := _bool_missing(_paths(_cm4_1_bools)) | _zero_missing(_paths(_cm4_1_zeros))

_cm4_1_unmet := _bool_false(_cm4_1_bools) | _zero_unmet(_cm4_1_zeros)

violation contains msg if {
	count(_cm4_1_missing | _cm4_1_unmet) > 0
	msg := sprintf("NIST CM-4(1): %s", [_detail(_cm4_1_missing, _cm4_1_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# CM-5(1) Automated Access Enforcement and Audit Records: access restrictions for change are enforced by an
# automated mechanism, and the enforcement actions generate audit records automatically.
# Facts: access_restrictions_for_change.automation.enforced, .audit_records_generated (booleans, from the change
#        pipeline or privileged access tool configuration).
# ---------------------------------------------------------------------------------------------------------------

_cm5_1_bools := [
	["access_restrictions_for_change.automation.enforced", "access restrictions for change not enforced by an automated mechanism"],
	["access_restrictions_for_change.automation.audit_records_generated", "enforcement actions do not generate audit records automatically"],
]

_cm5_1_missing := _bool_missing(_paths(_cm5_1_bools))

_cm5_1_unmet := _bool_false(_cm5_1_bools)

violation contains msg if {
	count(_cm5_1_missing | _cm5_1_unmet) > 0
	msg := sprintf("NIST CM-5(1): %s", [_detail(_cm5_1_missing, _cm5_1_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# CM-5(5) Privilege Limitation for Production and Operation: privileges to change production components and
# system-related information are limited, and reviewed at the organization-defined frequency.
# Facts: access_restrictions_for_change.production_privileges.unapproved_holders (number of accounts holding
#        production change privileges without an approved need; must be 0);
#        access_restrictions_for_change.production_privileges.review.days_since_last + .review.odp.frequency_days.
# ---------------------------------------------------------------------------------------------------------------

_cm5_5_zeros := [["access_restrictions_for_change.production_privileges.unapproved_holders", "%v accounts hold production change privileges without an approved need"]]

_cm5_5_missing := _zero_missing(_paths(_cm5_5_zeros)) | _freq_missing("access_restrictions_for_change.production_privileges.review")

_cm5_5_unmet := _zero_unmet(_cm5_5_zeros) | _overdue("access_restrictions_for_change.production_privileges.review", "production change privileges last reviewed")

violation contains msg if {
	count(_cm5_5_missing | _cm5_5_unmet) > 0
	msg := sprintf("NIST CM-5(5): %s", [_detail(_cm5_5_missing, _cm5_5_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# CM-6(1) Automated Management, Application, and Verification: configuration settings for the organization-defined
# components are managed, applied and verified by automated mechanisms.
# Facts: configuration_settings.automation.automated (boolean: a configuration management tool applies and
#        verifies the settings, e.g. Ansible with a compliance scan); configuration_settings.automation
#        .components_not_managed (number of organization-defined components the mechanism does not cover; must be 0).
# ---------------------------------------------------------------------------------------------------------------

_cm6_1_bools := [["configuration_settings.automation.automated", "configuration settings not managed, applied and verified by an automated mechanism"]]

_cm6_1_zeros := [["configuration_settings.automation.components_not_managed", "%v organization-defined components not covered by the automated configuration mechanism"]]

_cm6_1_missing := _bool_missing(_paths(_cm6_1_bools)) | _zero_missing(_paths(_cm6_1_zeros))

_cm6_1_unmet := _bool_false(_cm6_1_bools) | _zero_unmet(_cm6_1_zeros)

violation contains msg if {
	count(_cm6_1_missing | _cm6_1_unmet) > 0
	msg := sprintf("NIST CM-6(1): %s", [_detail(_cm6_1_missing, _cm6_1_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# CM-6(2) Respond to Unauthorized Changes: the organization-defined actions are taken in response to unauthorized
# changes to the organization-defined configuration settings.
# Facts: configuration_settings.unauthorized_changes.response_configured (boolean: drift detection triggers the
#        organization-defined response, e.g. alert, revert, ticket); configuration_settings.unauthorized_changes
#        .detected_without_response (number of unauthorized changes detected in the review period with no recorded
#        response; must be 0).
# ---------------------------------------------------------------------------------------------------------------

_cm6_2_bools := [["configuration_settings.unauthorized_changes.response_configured", "no organization-defined response configured for unauthorized configuration changes"]]

_cm6_2_zeros := [["configuration_settings.unauthorized_changes.detected_without_response", "%v unauthorized configuration changes detected without the organization-defined response"]]

_cm6_2_missing := _bool_missing(_paths(_cm6_2_bools)) | _zero_missing(_paths(_cm6_2_zeros))

_cm6_2_unmet := _bool_false(_cm6_2_bools) | _zero_unmet(_cm6_2_zeros)

violation contains msg if {
	count(_cm6_2_missing | _cm6_2_unmet) > 0
	msg := sprintf("NIST CM-6(2): %s", [_detail(_cm6_2_missing, _cm6_2_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# CM-8(2) Automated Maintenance: the component inventory is kept current, complete, accurate and available by an
# automated mechanism.
# Facts: system_component_inventory.automation.automated (boolean: discovery or CMDB synchronisation maintains the
#        inventory); system_component_inventory.automation.components_not_covered (number of components the
#        mechanism does not discover or reconcile; must be 0).
# ---------------------------------------------------------------------------------------------------------------

_cm8_2_bools := [["system_component_inventory.automation.automated", "component inventory not maintained by an automated mechanism"]]

_cm8_2_zeros := [["system_component_inventory.automation.components_not_covered", "%v components not covered by the automated inventory mechanism"]]

_cm8_2_missing := _bool_missing(_paths(_cm8_2_bools)) | _zero_missing(_paths(_cm8_2_zeros))

_cm8_2_unmet := _bool_false(_cm8_2_bools) | _zero_unmet(_cm8_2_zeros)

violation contains msg if {
	count(_cm8_2_missing | _cm8_2_unmet) > 0
	msg := sprintf("NIST CM-8(2): %s", [_detail(_cm8_2_missing, _cm8_2_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# CM-8(4) Accountability Information: the inventory identifies, by the organization-defined attribute (name,
# position or role), the individuals responsible and accountable for administering each component.
# Facts: system_component_inventory.accountability.components_without_responsible_individual (number of inventory
#        records with no responsible individual identified; must be 0).
# ---------------------------------------------------------------------------------------------------------------

_cm8_4_zeros := [["system_component_inventory.accountability.components_without_responsible_individual", "%v inventory components with no responsible and accountable individual identified"]]

_cm8_4_missing := _zero_missing(_paths(_cm8_4_zeros))

_cm8_4_unmet := _zero_unmet(_cm8_4_zeros)

violation contains msg if {
	count(_cm8_4_missing | _cm8_4_unmet) > 0
	msg := sprintf("NIST CM-8(4): %s", [_detail(_cm8_4_missing, _cm8_4_unmet)])
}

compliant if count(violation) == 0

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {
	"CM-1", "CM-2", "CM-2(2)", "CM-2(3)", "CM-2(7)", "CM-3", "CM-3(1)", "CM-3(2)", "CM-3(4)", "CM-3(6)", "CM-4",
	"CM-4(1)", "CM-4(2)", "CM-5", "CM-5(1)", "CM-5(5)", "CM-6", "CM-6(1)", "CM-6(2)", "CM-7", "CM-7(1)", "CM-7(2)",
	"CM-7(5)", "CM-8", "CM-8(1)", "CM-8(2)", "CM-8(3)", "CM-8(4)", "CM-9", "CM-10", "CM-11", "CM-12", "CM-12(1)",
	"CM-13", "CM-14",
}

compliance_report := {
	"family": "CM",
	"name": "Configuration Management",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
