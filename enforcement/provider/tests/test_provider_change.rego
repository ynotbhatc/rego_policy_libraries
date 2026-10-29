# Tests for the provider change gate (enforcement/provider/provider_change.rego).
#
# Every fixture under tests/fixtures/<name>/input.json is a complete CONTRACTS.md §4 document;
# the directory name ends in _allow or _deny, the decision the gate must return for it.
package provider_change.main_test

import data.provider_change.main
import rego.v1

# OPA mounts a data file at its directory path relative to the load root, so where the
# fixtures land depends on how `opa test` was invoked. Exactly one of these resolves per run:
#   opa test .                               (CI)   -> data.enforcement.provider.tests.fixtures
#   opa test enforcement                            -> data.provider.tests.fixtures
#   opa test enforcement/provider                   -> data.tests.fixtures
fixtures := data.enforcement.provider.tests.fixtures

fixtures := data.provider.tests.fixtures

fixtures := data.tests.fixtures

fixture(name) := fixtures[name]

decide(name) := d if {
	d := main.decision with input as fixture(name)
}

# Shallow replacement of top-level keys. object.union merges recursively, so a test that
# wants to swap planned_state or config wholesale must drop the old key first.
_with(doc, overrides) := object.union(object.remove(doc, object.keys(overrides)), overrides)

_marker := "__SENSITIVE__"

# ---------------------------------------------------------------------------
# Decision shape and fail-closed defaults
# ---------------------------------------------------------------------------

test_decision_has_exactly_the_contract_keys if {
	d := decide("well_formed_allow")
	object.keys(d) == {"allow", "reasons", "policy_version", "evaluated_rules"}
	is_boolean(d.allow)
	is_array(d.reasons)
	d.policy_version == "1.0.0"
	is_number(d.evaluated_rules)
}

test_empty_input_is_denied_with_reasons if {
	d := main.decision with input as {}
	d.allow == false
	count(d.reasons) == 4
	every r in d.reasons {
		startswith(r, "PC-000:")
	}
	d.evaluated_rules == 1
}

test_no_input_at_all_still_decides if {
	d := main.decision with input as null
	d.allow == false
	count(d.reasons) > 0
}

test_compliance_report_fails_closed_on_empty_input if {
	r := main.compliance_report with input as {}
	r.compliant == false
	count(r.violations) > 0
	r.decision == main.decision with input as {}
}

test_well_formed_document_is_allowed if {
	d := decide("well_formed_allow")
	d.allow
	d.reasons == []
}

# ---------------------------------------------------------------------------
# Every fixture decides as its name says, and no reason ever echoes a masked value
# ---------------------------------------------------------------------------

_expected(name) if endswith(name, "_allow")

_expected(name) := false if endswith(name, "_deny")

_names := {name | some name in object.keys(fixtures)}

test_fixture_directory_is_populated if {
	count(_names) >= 40
}

test_every_fixture_name_declares_its_decision if {
	every name in _names {
		is_boolean(_expected(name)) # undefined for a name without an _allow / _deny suffix
	}
}

test_every_fixture_decides_as_named if {
	every name in _names {
		decide(name).allow == _expected(name)
	}
}

_consistent(d) if {
	d.allow
	count(d.reasons) == 0
}

_consistent(d) if {
	not d.allow
	count(d.reasons) > 0
}

test_allow_is_true_only_when_deny_is_empty if {
	every name in _names {
		_consistent(decide(name))
	}
}

test_no_reason_ever_echoes_a_sensitive_value if {
	every name in _names {
		d := decide(name)
		every r in d.reasons {
			not contains(r, _marker)
		}
	}
}

test_reasons_are_sorted_and_deterministic if {
	every name in _names {
		d := decide(name)
		d.reasons == sort(d.reasons)
	}
}

# ---------------------------------------------------------------------------
# PC-000 — malformed input
# ---------------------------------------------------------------------------

test_pc000_missing_kind if {
	d := decide("malformed_missing_kind_deny")
	not d.allow
	d.reasons == ["PC-000: malformed input — kind must be \"provider_change\""]
}

test_pc000_wrong_kind if {
	d := decide("malformed_wrong_kind_deny")
	not d.allow
	count(d.reasons) == 1
	contains(d.reasons[0], "kind must be")
}

test_pc000_missing_version if {
	d := decide("malformed_missing_version_deny")
	not d.allow
	d.reasons == ["PC-000: malformed input — version must be one of [1]"]
}

test_pc000_unsupported_version if {
	d := decide("malformed_unsupported_version_deny")
	not d.allow
	count(d.reasons) == 1
	contains(d.reasons[0], "version must be one of [1]")
}

test_pc000_missing_action if {
	d := decide("malformed_missing_action_deny")
	not d.allow
	d.reasons == ["PC-000: malformed input — action must be one of create, update, replace, delete, no-op"]
}

test_pc000_unknown_action if {
	d := decide("malformed_unknown_action_deny")
	not d.allow
	count(d.reasons) == 1
	contains(d.reasons[0], "action must be one of")
}

test_pc000_missing_resource_type if {
	d := decide("malformed_missing_resource_type_deny")
	not d.allow
	d.reasons == ["PC-000: malformed input — resource_type must be a non-empty string"]
	d.evaluated_rules == 1
}

test_pc000_version_as_string_is_malformed if {
	doc := _with(fixture("well_formed_allow"), {"version": "1"})
	d := main.decision with input as doc
	not d.allow
	contains(d.reasons[0], "version must be one of [1]")
}

test_pc000_empty_resource_type_is_malformed if {
	doc := _with(fixture("well_formed_allow"), {"resource_type": ""})
	d := main.decision with input as doc
	not d.allow
	contains(d.reasons[0], "resource_type must be a non-empty string")
}

# ---------------------------------------------------------------------------
# PC-001 — public S3 ACL
# ---------------------------------------------------------------------------

test_pc001_public_read_acl_denied if {
	d := decide("s3_public_acl_deny")
	not d.allow
	d.reasons == ["PC-001: aws_s3_bucket aws_s3_bucket.evidence grants public access through its ACL (acl=public-read)"]
}

test_pc001_private_acl_allowed if {
	decide("s3_private_acl_allow").allow
}

test_pc001_bucket_acl_resource_authenticated_read_denied if {
	d := decide("s3_bucket_acl_resource_public_deny")
	not d.allow
	some r in d.reasons
	startswith(r, "PC-001:")
	contains(r, "acl=authenticated-read")
}

test_pc001_grant_to_allusers_denied if {
	d := decide("s3_bucket_acl_grant_allusers_deny")
	not d.allow
	some r in d.reasons
	startswith(r, "PC-001:")
	contains(r, "AllUsers")
}

test_pc001_grant_to_owner_allowed if {
	decide("s3_bucket_acl_grant_owner_allow").allow
}

test_pc001_public_read_write_in_config_only_denied if {
	doc := _with(fixture("well_formed_allow"), {
		"planned_state": {"bucket": "evidence", "acl": null, "tags": {"owner": "o", "environment": "e"}},
		"config": {"bucket": "evidence", "acl": "public-read-write", "tags": {"owner": "o", "environment": "e"}},
		"unknown_paths": ["acl"],
	})
	d := main.decision with input as doc
	not d.allow
	some r in d.reasons
	contains(r, "acl=public-read-write")
}

test_pc001_does_not_apply_to_delete if {
	doc := _with(fixture("s3_public_acl_deny"), {"action": "delete", "planned_state": null, "config": {}})
	d := main.decision with input as doc
	d.allow
}

# ---------------------------------------------------------------------------
# PC-002 — public access block
# ---------------------------------------------------------------------------

test_pc002_one_flag_off_denied if {
	d := decide("s3_public_access_block_off_deny")
	not d.allow
	d.reasons == ["PC-002: aws_s3_bucket_public_access_block aws_s3_bucket_public_access_block.evidence leaves public access protection off (block_public_policy is false or not set)"]
}

test_pc002_all_flags_on_allowed if {
	decide("s3_public_access_block_on_allow").allow
}

test_pc002_absent_flag_fails_closed if {
	doc := fixture("s3_public_access_block_on_allow")
	planned := object.remove(doc.planned_state, ["ignore_public_acls"])
	config := object.remove(doc.config, ["ignore_public_acls"])
	patched := _with(doc, {"planned_state": planned, "config": config})
	d := main.decision with input as patched
	not d.allow
	count(d.reasons) == 1
	contains(d.reasons[0], "ignore_public_acls is false or not set")
}

test_pc002_all_four_off_gives_four_reasons if {
	doc := fixture("s3_public_access_block_on_allow")
	off := {"block_public_acls": false, "block_public_policy": false, "ignore_public_acls": false, "restrict_public_buckets": false}
	d := main.decision with input as _with(doc, {
		"planned_state": object.union(doc.planned_state, off),
		"config": object.union(doc.config, off),
	})
	count(d.reasons) == 4
}

# ---------------------------------------------------------------------------
# PC-003 — ingress from the whole internet
# ---------------------------------------------------------------------------

test_pc003_aws_sg_inline_ingress_world_denied if {
	d := decide("aws_sg_world_ingress_deny")
	not d.allow
	d.reasons == ["PC-003: aws_security_group aws_security_group.web allows ingress from the whole internet (0.0.0.0/0)"]
}

test_pc003_aws_sg_scoped_ingress_allowed if {
	decide("aws_sg_scoped_ingress_allow").allow
}

test_pc003_aws_sg_rule_ipv6_world_denied if {
	d := decide("aws_sg_rule_world_ipv6_deny")
	not d.allow
	some r in d.reasons
	contains(r, "(::/0)")
}

test_pc003_aws_sg_rule_egress_is_not_ingress if {
	decide("aws_sg_rule_egress_world_allow").allow
}

test_pc003_aws_vpc_ingress_rule_world_denied if {
	d := decide("aws_vpc_sg_ingress_rule_world_deny")
	not d.allow
	some r in d.reasons
	startswith(r, "PC-003:")
	contains(r, "0.0.0.0/0")
}

test_pc003_aws_vpc_ingress_rule_scoped_allowed if {
	decide("aws_vpc_sg_ingress_rule_scoped_allow").allow
}

test_pc003_azure_inbound_allow_from_internet_denied if {
	d := decide("azure_nsg_rule_internet_inbound_deny")
	not d.allow
	d.reasons == ["PC-003: azurerm_network_security_rule azurerm_network_security_rule.ssh allows inbound traffic from the whole internet (source Internet)"]
}

test_pc003_azure_outbound_is_not_ingress if {
	decide("azure_nsg_rule_internet_outbound_allow").allow
}

test_pc003_azure_deny_rule_is_not_an_exposure if {
	decide("azure_nsg_rule_internet_denyrule_allow").allow
}

test_pc003_azure_star_in_prefix_list_denied if {
	doc := fixture("azure_nsg_rule_internet_inbound_deny")
	patched := object.union(doc.planned_state, {"source_address_prefix": null, "source_address_prefixes": ["10.0.0.0/8", "*"]})
	d := main.decision with input as _with(doc, {"planned_state": patched, "config": patched})
	not d.allow
	some r in d.reasons
	contains(r, "(source *)")
}

test_pc003_gcp_world_ingress_with_allow_denied if {
	d := decide("gcp_firewall_world_ingress_deny")
	not d.allow
	d.reasons == ["PC-003: google_compute_firewall google_compute_firewall.ssh allows ingress from the whole internet (source range 0.0.0.0/0)"]
}

test_pc003_gcp_deny_only_firewall_allowed if {
	decide("gcp_firewall_world_deny_only_allow").allow
}

test_pc003_gcp_scoped_ingress_allowed if {
	decide("gcp_firewall_scoped_ingress_allow").allow
}

test_pc003_gcp_disabled_firewall_is_not_an_exposure if {
	doc := fixture("gcp_firewall_world_ingress_deny")
	patched := object.union(doc.planned_state, {"disabled": true})
	d := main.decision with input as _with(doc, {"planned_state": patched, "config": patched})
	d.allow
}

test_pc003_gcp_egress_firewall_is_not_ingress if {
	doc := fixture("gcp_firewall_world_ingress_deny")
	patched := object.union(doc.planned_state, {"direction": "EGRESS", "source_ranges": [], "destination_ranges": ["0.0.0.0/0"]})
	d := main.decision with input as _with(doc, {"planned_state": patched, "config": patched})
	d.allow
}

# ---------------------------------------------------------------------------
# PC-004 — protected resources
# ---------------------------------------------------------------------------

test_pc004_protected_delete_denied if {
	d := decide("protected_delete_deny")
	not d.allow
	d.reasons == ["PC-004: aws_db_instance aws_db_instance.ledger is tagged protected=true and the plan would delete it"]
}

test_pc004_protected_replace_denied if {
	d := decide("protected_replace_deny")
	not d.allow
	some r in d.reasons
	endswith(r, "the plan would replace it")
}

test_pc004_protected_gcp_labels_denied if {
	d := decide("protected_labels_gcp_delete_deny")
	not d.allow
	some r in d.reasons
	startswith(r, "PC-004:")
}

test_pc004_protected_update_in_place_allowed if {
	decide("protected_update_allow").allow
}

test_pc004_unprotected_delete_allowed if {
	decide("unprotected_delete_allow").allow
}

test_pc004_protected_false_is_not_protected if {
	decide("protected_false_delete_allow").allow
}

test_pc004_boolean_true_and_mixed_case_count if {
	doc := fixture("unprotected_delete_allow")
	every value in [true, "True", "TRUE"] {
		tags := object.union(doc.prior_state.tags, {"Protected": value})
		d := main.decision with input as _with(doc, {"prior_state": object.union(doc.prior_state, {"tags": tags, "tags_all": tags})})
		not d.allow
	}
}

test_pc004_masked_protected_tag_cannot_protect_but_never_leaks if {
	doc := fixture("protected_delete_deny")
	tags := object.union(doc.prior_state.tags, {"protected": _marker})
	d := main.decision with input as _with(doc, {"prior_state": object.union(doc.prior_state, {"tags": tags, "tags_all": tags})})
	every r in d.reasons {
		not contains(r, _marker)
	}
}

test_pc004_protected_in_planned_only_does_not_apply if {
	doc := fixture("unprotected_delete_allow")
	d := main.decision with input as _with(doc, {"planned_state": {"tags": {"protected": "true"}}})
	d.allow
}

# ---------------------------------------------------------------------------
# PC-005 — required tags
# ---------------------------------------------------------------------------

test_pc005_missing_owner_denied if {
	d := decide("tags_missing_owner_deny")
	not d.allow
	d.reasons == ["PC-005: aws_instance aws_instance.web is missing required tag \"owner\" (looked in tags, tags_all and labels)"]
}

test_pc005_missing_both_gives_two_reasons if {
	d := decide("tags_missing_both_deny")
	not d.allow
	count(d.reasons) == 2
	some r1 in d.reasons
	contains(r1, "\"owner\"")
	some r2 in d.reasons
	contains(r2, "\"environment\"")
}

test_pc005_tags_present_allowed if {
	decide("tags_present_allow").allow
}

test_pc005_tags_all_counts if {
	decide("tags_present_in_tags_all_only_allow").allow
}

test_pc005_azure_missing_environment_denied if {
	d := decide("azure_tags_missing_environment_deny")
	not d.allow
	some r in d.reasons
	contains(r, "azurerm_storage_account")
	contains(r, "\"environment\"")
}

test_pc005_gcp_labels_count if {
	decide("gcp_labels_present_allow").allow
}

test_pc005_empty_value_is_missing if {
	d := decide("tags_empty_value_deny")
	not d.allow
	some r in d.reasons
	contains(r, "\"owner\"")
}

test_pc005_delete_needs_no_tags if {
	decide("tags_delete_needs_none_allow").allow
}

test_pc005_untaggable_type_is_out_of_scope if {
	decide("untaggable_type_no_tags_allow").allow
}

test_pc005_noop_is_out_of_scope if {
	decide("noop_action_allow").allow
}

test_pc005_tag_keys_match_case_insensitively if {
	doc := fixture("tags_missing_both_deny")
	tags := {"Owner": "platform-team", "ENVIRONMENT": "test"}
	d := main.decision with input as _with(doc, {
		"planned_state": object.union(doc.planned_state, {"tags": tags}),
		"config": object.union(doc.config, {"tags": tags}),
	})
	d.allow
}

test_pc005_masked_tag_value_counts_as_present if {
	decide("sensitive_values_masked_allow").allow
}

test_pc005_taggable_set_is_data_and_overridable if {
	doc := fixture("untaggable_type_no_tags_allow")
	d := main.decision with input as doc
		with data.provider_change.main.taggable_resource_types as {"aws_s3_bucket_versioning"}
	not d.allow
	count(d.reasons) == 2
}

# ---------------------------------------------------------------------------
# PC-006 — IAM console access
# ---------------------------------------------------------------------------

test_pc006_login_profile_create_denied if {
	d := decide("iam_login_profile_create_deny")
	not d.allow
	d.reasons == ["PC-006: creating aws_iam_user_login_profile aws_iam_user_login_profile.alice grants an IAM user console access"]
}

test_pc006_login_profile_delete_allowed if {
	decide("iam_login_profile_delete_allow").allow
}

test_pc006_iam_user_with_login_profile_denied if {
	d := decide("iam_user_with_login_profile_deny")
	not d.allow
	d.reasons == ["PC-006: creating aws_iam_user aws_iam_user.alice with a login profile grants console access"]
}

test_pc006_plain_iam_user_allowed if {
	decide("iam_user_plain_allow").allow
}

test_pc006_empty_login_profile_is_not_console_access if {
	doc := fixture("iam_user_plain_allow")
	every empty in [null, false, [], {}, ""] {
		d := main.decision with input as _with(doc, {"config": object.union(doc.config, {"login_profile": empty})})
		d.allow
	}
}

test_pc006_update_of_iam_user_is_out_of_scope if {
	doc := fixture("iam_user_with_login_profile_deny")
	d := main.decision with input as _with(doc, {"action": "update", "prior_state": doc.planned_state})
	d.allow
}

# ---------------------------------------------------------------------------
# Sensitive values
# ---------------------------------------------------------------------------

test_sensitive_values_never_decide_or_appear if {
	d := decide("sensitive_values_masked_allow")
	d.allow
	d.reasons == []
}

test_sensitive_sibling_values_do_not_hide_a_protected_tag if {
	d := decide("sensitive_protected_tag_delete_deny")
	not d.allow
	some r in d.reasons
	startswith(r, "PC-004:")
	not contains(r, _marker)
}

# ---------------------------------------------------------------------------
# evaluated_rules
# ---------------------------------------------------------------------------

test_evaluated_rules_counts_rules_in_scope if {
	# aws_s3_bucket create: PC-000, PC-001 (type), PC-005 (taggable) -> 3
	decide("well_formed_allow").evaluated_rules == 3

	# aws_instance delete: PC-000, PC-004 -> 2
	decide("unprotected_delete_allow").evaluated_rules == 2

	# aws_security_group create: PC-000, PC-003, PC-005 -> 3
	decide("aws_sg_world_ingress_deny").evaluated_rules == 3

	# aws_iam_user create: PC-000, PC-005, PC-006 -> 3
	decide("iam_user_plain_allow").evaluated_rules == 3

	# no-op: only PC-000
	decide("noop_action_allow").evaluated_rules == 1
}

test_rule_catalog_titles_match_reason_prefixes if {
	every id, _ in main.rule_catalog {
		regex.match(`^PC-\d{3}$`, id)
	}
	count(main.rule_catalog) == 7
}
