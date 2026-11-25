package cis_palo_alto_panos_test

import rego.v1

# Hand-written (not touched by tools/cis_generators/gen_palo_alto.py): wrong-typed, null and removed facts never
# pass. Data-driven over every leaf of the green fixture, so a fact added to the fixture is covered without a new test.

_passes(inp) if {
	r := data.cis_palo_alto_panos.main.compliance_report with input as inp
	_report_passes(r)
}

_report_passes(r) if r.compliant == true

_report_passes(r) if r.failed_controls == 0

_report_passes(r) if r.compliance_percentage >= 100

_leaves := [[path, v] | walk(green, [path, v]); not is_object(v); not is_array(v)]

_yn(v) if {
	is_string(v)
	v in {"yes", "no"}
}

# two values that are not evidence for a fact of this leaf's type (two per leaf keeps each test short)
_wrong(v) := [sprintf("%v", [v]), null] if is_number(v)

_wrong(v) := ["true", null] if is_boolean(v)

_wrong(v) := ["enabled", 1] if _yn(v)

# fixture leaves no recommendation reads: PAN-OS settings the benchmark does not check
_unread := {
	["panos_config", "network", "profiles", "interface_management", 0, "ping"],
	["panos_config", "network", "profiles", "interface_management", 0, "https"],
	["panos_config", "profiles", "data_filtering", 0, "rules", 0, "block_threshold"],
}

_kind(v) := "number" if is_number(v)

_kind(v) := "boolean" if is_boolean(v)

_kind(v) := "yes/no" if _yn(v)

_survivors(kind) := {[path, json.marshal(nv)] |
	some [path, v] in _leaves
	_kind(v) == kind
	not path in _unread
	some nv in _wrong(v)
	_passes(json.patch(green, [{"op": "replace", "path": path, "value": nv}]))
}

# User-ID on a trusted zone is optional: without it 2.3 and 2.4 have nothing to check
_optional := {["panos_config", "zone", 0, "enable_user_identification"]}

_removal_survivors := {path |
	some [path, v] in _leaves
	not path in _unread
	v in {"yes", true}
	not path in _optional
	_passes(json.patch(green, [{"op": "remove", "path": path}]))
}

test_no_number_of_another_type_passes if {
	count([1 | some [_, v] in _leaves; is_number(v)]) > 30
	count(_survivors("number")) == 0
}

test_no_yes_no_of_another_type_passes if {
	count([1 | some [_, v] in _leaves; _yn(v)]) > 40
	count(_survivors("yes/no")) == 0
}

test_no_attestation_of_another_type_passes if {
	count([1 | some [_, v] in _leaves; is_boolean(v)]) == 13
	count(_survivors("boolean")) == 0
}

test_no_removed_required_leaf_passes if count(_removal_survivors) == 0

_vs(inp) := v if v := data.cis_palo_alto_panos.violations with input as inp

_r(inp) := r if r := data.cis_palo_alto_panos.main.compliance_report with input as inp

# the same configuration with JSON booleans in place of "yes" / "no" reads the same
_as_booleans := json.patch(green, [{"op": "replace", "path": path, "value": v == "yes"} |
	some [path, v] in _leaves
	_yn(v)
])

test_json_booleans_read_as_yes_no if {
	r := _r(_as_booleans)
	r.total_controls == 79
	r.failed_controls == 0
	r.compliant == true
	l1 := _r(json.patch(_as_booleans, [{"op": "add", "path": "/cis_profile", "value": {"level": 1}}]))
	l1.total_controls == 69
	l1.failed_controls == 0
}

test_number_as_string_is_evidence_invalid if {
	vs := _vs(json.patch(green, [{"op": "replace", "path": "/panos_config/mgt_config/password_complexity/minimum_length", "value": "14"}]))
	"1.3.2: evidence invalid — panos_config.mgt_config.password_complexity.minimum_length must be a number, got \"14\"" in vs
	not "1.3.2: admin passwords must be at least 12 characters long" in vs
}

test_yes_no_of_another_type_is_evidence_invalid if {
	# a value that is neither yes nor no used to read as "no", which passed the checks that want "no"
	vs := _vs(json.patch(green, [{"op": "replace", "path": "/panos_config/user_id/setting/enable_probing", "value": "enabled"}]))
	"2.2: evidence invalid — panos_config.user_id.setting.enable_probing must be \"yes\" or \"no\", got \"enabled\"" in vs
	lic := _vs(json.patch(green, [{"op": "replace", "path": "/panos_config/licenses/0/expired", "value": null}]))
	"6.8: evidence invalid — panos_config.licenses.0.expired must be \"yes\" or \"no\", got null" in lic
}

test_rule_field_of_the_wrong_type_is_evidence_invalid if {
	# a single-member list collapsed to a string would drop the rule from the Internet-bound set
	vs := _vs(json.patch(green, [{"op": "replace", "path": "/panos_config/rulebase/security/0/to", "value": "untrust"}]))
	"6.5: evidence invalid — panos_config.rulebase.security.0.to must be a list, got \"untrust\"" in vs
}

test_empty_profile_list_is_a_failed_control_not_missing_evidence if {
	vs := _vs(json.patch(green, [{"op": "replace", "path": "/panos_config/profiles/virus", "value": []}]))
	"6.1: antivirus decoders must reset both ends for signature and WildFire actions (imap and pop3 may alert) (no antivirus profile configured)" in vs
	"6.2: every allow rule must carry an antivirus profile (no antivirus profile configured)" in vs
	every v in vs { not contains(v, "evidence missing") }
	every kind in ["virus", "spyware", "vulnerability", "url_filtering", "data_filtering", "wildfire_analysis"] {
		e := _vs(json.patch(green, [{"op": "replace", "path": concat("/", ["/panos_config/profiles", kind]), "value": []}]))
		count(e) > 0
		every v in e { endswith(v, "profile configured)") }
	}
}

test_absent_profile_list_is_still_missing_evidence if {
	vs := _vs(json.patch(green, [{"op": "remove", "path": "/panos_config/profiles/virus"}]))
	"6.1: evidence missing — panos_config.profiles.virus not collected" in vs
	every v in vs { not contains(v, "profile configured)") }
}

test_empty_profile_list_without_the_license_does_not_apply if {
	# 6.22 applies with Advanced Threat Prevention only; no licence and no profiles is not a finding
	inp := json.patch(green, [
		{"op": "replace", "path": "/panos_config/licenses", "value": [{"feature": "PAN-DB URL Filtering", "expired": "no"}]},
		{"op": "replace", "path": "/panos_config/profiles/vulnerability", "value": []},
	])
	not has("6.22", inp)
	has("6.6", inp)
}

test_licenses_not_collected_is_missing_evidence if {
	vs := _vs(json.patch(green, [{"op": "remove", "path": "/panos_config/licenses"}]))
	"6.8: evidence missing — panos_config.licenses not collected" in vs
	"6.22: evidence missing — panos_config.{licenses,profiles.vulnerability} not collected" in vs
}

_level(lv) := json.patch(green, [{"op": "add", "path": "/cis_profile", "value": {"level": lv}}])

test_level_must_be_the_number_1_or_2 if {
	every lv in ["2", "1", 3, 0, null, true, "L2"] {
		r := _r(_level(lv))
		r.compliant == false
		r.level == 2
		r.total_controls == 79
		r.failed_controls == 10
		r.compliance_percentage < 100
		some v in r.violations
		startswith(v, "cis_profile.level: evidence invalid — cis_profile.level must be the number 1 or 2, got ")
	}
	s := _r(_level("2"))
	"1.1.1.2: evidence invalid — cis_profile.level must be the number 1 or 2, got \"2\", so this Level 2 recommendation could not be scoped" in s.violations
	n := _r(json.patch(green, [{"op": "add", "path": "/cis_profile", "value": "2"}]))
	n.compliant == false
	n.failed_controls == 10
}

test_level_numbers_and_absent_level_are_valid if {
	_r(_level(2)).failed_controls == 0
	_r(_level(2)).total_controls == 79
	_r(_level(1)).failed_controls == 0
	_r(_level(1)).total_controls == 69
	_r(green).total_controls == 79
	_r(green).compliant == true
	o := _r(json.patch(green, [{"op": "add", "path": "/cis_profile", "value": {}}]))
	o.total_controls == 79
	o.compliant == true
}

test_report_counts_hold_on_bad_input if {
	every inp in [{}, {"panos_config": null}, {"panos_config": "yes"}, {"panos_config": {}}, _level("2"), {"cis_profile": {"level": "1"}}] {
		r := _r(inp)
		r.compliant == false
		r.passed_controls + r.failed_controls == r.total_controls
		r.failed_controls > 0
	}
}

# ── yes/no facts whose passing state is "no" ──────────────────────────────────────────────────────────────────────
# The running configuration leaves out a setting that is at its default, so an absent key in a collected section is
# the device default. That passes only where the PAN-OS default is the state the recommendation asks for.

_set(path, v) := json.patch(green, [{"op": "add", "path": path, "value": v}])

_rm(path) := json.patch(green, [{"op": "remove", "path": path}])

# 2.2 (probing off) and 3.3 (preemption off): PAN-OS default is off, CIS lists the default as "not configured"
_default_no := {
	"2.2": {"leaf": "/panos_config/user_id/setting/enable_probing", "section": "/panos_config/user_id/setting"},
	"3.3": {
		"leaf": "/panos_config/deviceconfig/high_availability/election_option/preemptive",
		"section": "/panos_config/deviceconfig/high_availability",
	},
}

test_default_no_facts_pass_on_no_false_and_the_device_default if {
	every id, f in _default_no {
		every v in ["no", "No", false] { not has(id, _set(f.leaf, v)) }
		not has(id, _rm(f.leaf))
		_r(_rm(f.leaf)).compliant == true
	}
	# 3.3 with the whole election_option element at its defaults
	not has("3.3", _rm("/panos_config/deviceconfig/high_availability/election_option"))
}

test_default_no_facts_fail_on_yes_and_true if {
	every id, f in _default_no {
		every v in ["yes", "YES", true] { has(id, _set(f.leaf, v)) }
	}
}

test_default_no_facts_of_another_type_are_evidence_invalid if {
	every id, f in _default_no {
		every v in [null, "false", "disabled", 0, ""] {
			vs := _vs(_set(f.leaf, v))
			some m in vs
			startswith(m, sprintf("%s: evidence invalid — ", [id]))
		}
	}
}

test_default_no_facts_are_missing_evidence_without_their_section if {
	every id, f in _default_no {
		vs := _vs(_rm(f.section))
		some m in vs
		startswith(m, sprintf("%s: evidence missing — ", [id]))
	}
}

# 6.11: "log container page only" is ON by default (PAN-OS web interface help, URL Filtering Settings), so a URL
# filtering profile that does not state it is logging container pages only and fails
test_log_container_page_only_absent_is_the_unsafe_default if {
	p := "/panos_config/profiles/url_filtering/0/log_container_page_only"
	every v in ["no", false] { not has("6.11", _set(p, v)) }
	"6.11: URL filtering profiles must log User-Agent, Referer and X-Forwarded-For on every page" in _vs(_rm(p))
	_r(_rm(p)).compliant == false
	every v in ["yes", true] { has("6.11", _set(p, v)) }
	some m in _vs(_set(p, null))
	startswith(m, "6.11: evidence invalid — ")
}

# a licence entry states feature and expired (`request license info` returns both); without `expired` it used to
# read as a valid licence and passed 6.8
test_licence_entry_without_expired_or_feature_is_evidence_invalid if {
	vs := _vs(_rm("/panos_config/licenses/0/expired"))
	"6.8: evidence invalid — panos_config.licenses.0.expired must be \"yes\" or \"no\", got nothing (the entry does not state it)" in vs
	_r(_rm("/panos_config/licenses/0/expired")).compliant == false
	every i in [0, 1, 2] {
		every k in ["expired", "feature"] {
			r := _r(_rm(sprintf("/panos_config/licenses/%d/%s", [i, k])))
			r.compliant == false
			every id in ["6.8", "6.22", "6.23", "6.24", "6.25"] {
				some m in r.violations
				startswith(m, sprintf("%s: evidence invalid — panos_config.licenses.%d.%s must be ", [id, i, k]))
			}
		}
	}
	some m in _vs(_set("/panos_config/licenses/0", "PAN-DB URL Filtering"))
	startswith(m, "6.8: evidence invalid — panos_config.licenses.0 must be a licence entry")
}

test_licence_expired_no_and_false_are_valid_and_yes_fails if {
	every v in ["no", false] { _r(_set("/panos_config/licenses/0/expired", v)).compliant == true }
	every v in ["yes", true] { has("6.8", _set("/panos_config/licenses/0/expired", v)) }
}

# every "no" / false leaf of the green fixture, removed: only the facts whose PAN-OS default is "no" may pass
_default_no_leaves := {
	["panos_config", "user_id", "setting", "enable_probing"],
	["panos_config", "deviceconfig", "high_availability", "election_option", "preemptive"],
	["panos_config", "deviceconfig", "setting", "wildfire", "session_info_select", "exclude_src_ip"],
}

test_only_default_no_leaves_pass_when_removed if {
	nos := {path | some [path, v] in _leaves; v == "no"}
	count(nos) >= 7
	survivors := {path | some path in nos; _passes(json.patch(green, [{"op": "remove", "path": path}]))}
	survivors == _default_no_leaves
	b := {path | some path in nos; _passes(json.patch(_as_booleans, [{"op": "remove", "path": path}]))}
	b == _default_no_leaves
}
