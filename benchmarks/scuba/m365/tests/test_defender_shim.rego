# Tests for the deprecated scuba_m365.defender compatibility shim and the
# orchestrator's deprecated scuba.defender.* input path (ScubaGear v2.0.0
# replaced MS.DEFENDER with MS.SECURITYSUITE). Fixtures are the compliant
# inputs of the defender and securitysuite unit-test packages.
package scuba_m365.defender_shim_test

import data.scuba_m365.defender
import data.scuba_m365.defender_test
import data.scuba_m365.main
import data.scuba_m365.securitysuite_test
import rego.v1

legacy_input := defender_test.compliant_input

ss_input := securitysuite_test.compliant_input

_LEGACY_PATH := "scuba.defender (deprecated; one-to-one fields only)"

_flip(path) := json.patch(legacy_input, [{"op": "replace", "path": path, "value": false}])

# Old field -> [MS.DEFENDER id, MS.SECURITYSUITE successor id].
one_to_one_fields := {
	"/scuba/defender/impersonation/user_protection_sensitive": ["MS.DEFENDER.2.1v1", "MS.SECURITYSUITE.2.1v1"],
	"/scuba/defender/impersonation/domain_protection_owned": ["MS.DEFENDER.2.2v1", "MS.SECURITYSUITE.2.2v1"],
	"/scuba/defender/impersonation/domain_protection_partners": ["MS.DEFENDER.2.3v1", "MS.SECURITYSUITE.2.3v1"],
	"/scuba/defender/safe_attachments/spo_odb_teams_enabled": ["MS.DEFENDER.3.1v1", "MS.SECURITYSUITE.1.4v1"],
	"/scuba/defender/dlp/custom_pii_policy": ["MS.DEFENDER.4.1v2", "MS.SECURITYSUITE.3.1v1"],
	"/scuba/defender/dlp/applied_all_workloads": ["MS.DEFENDER.4.2v1", "MS.SECURITYSUITE.3.2v1"],
	"/scuba/defender/dlp/block_everyone_action": ["MS.DEFENDER.4.3v1", "MS.SECURITYSUITE.3.3v1"],
	"/scuba/defender/dlp/user_notifications": ["MS.DEFENDER.4.4v1", "MS.SECURITYSUITE.3.4v1"],
	"/scuba/defender/dlp/restricted_apps_blocked": ["MS.DEFENDER.4.6v1", "MS.SECURITYSUITE.3.5v1"],
	"/scuba/defender/alerts/routed_to_monitored_target": ["MS.DEFENDER.5.2v1", "MS.SECURITYSUITE.4.2v1"],
	"/scuba/defender/audit/unified_logging_enabled": ["MS.DEFENDER.6.1v1", "MS.SECURITYSUITE.5.1v1"],
}

# Facts with no one-to-one successor: they drive the old id only.
legacy_only_fields := {
	"/scuba/defender/presets/standard_strict_enabled": "MS.DEFENDER.1.1v1",
	"/scuba/defender/presets/eop_all_users": "MS.DEFENDER.1.2v1",
	"/scuba/defender/presets/atp_all_users": "MS.DEFENDER.1.3v1",
	"/scuba/defender/presets/eop_sensitive_strict": "MS.DEFENDER.1.4v1",
	"/scuba/defender/presets/atp_sensitive_strict": "MS.DEFENDER.1.5v1",
	"/scuba/defender/dlp/restricted_apps_list": "MS.DEFENDER.4.5v1",
	"/scuba/defender/alerts/required_exo_alerts_enabled": "MS.DEFENDER.5.1v1",
	"/scuba/defender/audit/retention_meets_m2131": "MS.DEFENDER.6.3v1",
}

_ss_ids(violations) := {id |
	some m in violations
	startswith(m, "SCuBA MS.SECURITYSUITE.")
	id := split(m, " ")[1]
}

# ── Shim report ──────────────────────────────────────────────────────────────

test_shim_compliant_and_carries_deprecation_notice if {
	r := defender.compliance_report with input as legacy_input
	r.compliant == true
	r.violation_count == 0
	r.controls_evaluated == 19
	r.baseline == "MS.DEFENDER"
	r.deprecated == "MS.DEFENDER baseline removed upstream in ScubaGear v2.0.0; use scuba_m365.securitysuite; this shim is removed in the next minor release"
	r.successor == "scuba_m365.securitysuite"
}

test_shim_notice_present_on_empty_input if {
	r := defender.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 19
	contains(r.deprecated, "ScubaGear v2.0.0")
}

test_shim_successor_ids_cover_all_19 if {
	r := defender.compliance_report with input as {}
	count(r.successor_ids) == 19
	count([k | some k, v in r.successor_ids; v != null]) == 11
	r.successor_ids["MS.DEFENDER.3.1v1"] == "MS.SECURITYSUITE.1.4v1"
	r.successor_ids["MS.DEFENDER.4.5v1"] == null
}

# Each one-to-one fact, flipped false, fires exactly its old id (evaluated by
# the Security Suite rule) in the shim, and its successor id in main.
test_shim_one_to_one_flip_fires_old_and_successor_id if {
	every path, ids in one_to_one_fields {
		v := defender.violations with input as _flip(path)
		count(v) == 1
		some m in v
		startswith(m, sprintf("SCuBA %s ", [ids[0]]))
		contains(m, sprintf("[evaluated as %s]", [ids[1]]))
		r := main.compliance_report with input as _flip(path)
		ids[1] in _ss_ids(r.violations)
	}
}

test_shim_legacy_only_flip_fires_old_id_only if {
	every path, id in legacy_only_fields {
		v := defender.violations with input as _flip(path)
		count(v) == 1
		some m in v
		startswith(m, sprintf("SCuBA %s ", [id]))
		not contains(m, "[evaluated as")
	}
}

test_shim_string_true_is_not_evidence if {
	inp := json.patch(legacy_input, [{"op": "replace", "path": "/scuba/defender/dlp/custom_pii_policy", "value": "true"}])
	v := defender.violations with input as inp
	count(v) == 1
	some m in v
	startswith(m, "SCuBA MS.DEFENDER.4.1v2 ")
}

# The shim reads scuba.defender.* only; new-format input does not satisfy it.
test_shim_ignores_securitysuite_input if {
	r := defender.compliance_report with input as ss_input
	r.violation_count == 19
}

# ── Orchestrator input paths ─────────────────────────────────────────────────

# Legacy-only input, every old fact true: the 11 translated Security Suite
# policies pass, the 13 with no legacy fact fail closed, Defender is never
# counted, and the report says which path was used.
test_main_legacy_only_input_uses_defender_path if {
	r := main.compliance_report with input as legacy_input
	r.securitysuite_input_path == _LEGACY_PATH
	contains(r.input_note, "deprecated scuba.defender")
	r.compliant == false
	r.policies_evaluated == 109
	r.accounting_balanced == true
	r.product_summary["MS.SECURITYSUITE"].violation_count == 13
	not r.product_summary["MS.DEFENDER"]
	count([m | some m in r.violations; startswith(m, "SCuBA MS.DEFENDER.")]) == 0
	_ss_ids(r.violations) == {
		"MS.SECURITYSUITE.1.1v1", "MS.SECURITYSUITE.1.2v1", "MS.SECURITYSUITE.1.3v1",
		"MS.SECURITYSUITE.2.4v1", "MS.SECURITYSUITE.4.1v1", "MS.SECURITYSUITE.5.2v1",
		"MS.SECURITYSUITE.6.1v1", "MS.SECURITYSUITE.6.2v1", "MS.SECURITYSUITE.7.1v1",
		"MS.SECURITYSUITE.7.2v1", "MS.SECURITYSUITE.7.3v1", "MS.SECURITYSUITE.8.1v1",
		"MS.SECURITYSUITE.8.2v1",
	}
}

# An empty legacy object is not evidence: all 24 Security Suite policies fire.
test_main_empty_defender_object_fails_all_securitysuite if {
	r := main.compliance_report with input as {"scuba": {"defender": {}}}
	r.securitysuite_input_path == _LEGACY_PATH
	r.product_summary["MS.SECURITYSUITE"].violation_count == 24
	r.violation_count == 109
}

# scuba.securitysuite wins over scuba.defender when both are sent.
test_main_securitysuite_input_wins_over_defender if {
	inp := json.patch(ss_input, [{"op": "add", "path": "/scuba/defender", "value": {}}])
	r := main.compliance_report with input as inp
	r.securitysuite_input_path == "scuba.securitysuite"
	r.input_note == ""
	r.product_summary["MS.SECURITYSUITE"].violation_count == 0
}

test_main_no_input_path_fails_closed if {
	r := main.compliance_report with input as {}
	r.securitysuite_input_path == "none"
	r.violation_count == 109
	r.compliant == false
}
