# METADATA
# title: "CIS Oracle Cloud Infrastructure Foundations Benchmark v3.1"
# custom:
#   class: security
#   framework: cis_oci
#   source: cis
#   domains: [cloud, oracle]
#   coverage:
#     checks: 55
#     cited: 54
#     expected: 54
#     found: 54
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_oci.main

# CIS Oracle Cloud Infrastructure Foundations Benchmark v3.1 (CIS lists 3.1.1 as current)
# 54 recommendations across 6 sections: 1 IAM (17), 2 Networking (8), 3 Compute (3),
# 4 Logging and Monitoring (18), 5 Storage (6), 6 Asset Management (2).
# Recommendation ids and titles from the public Prowler mapping of v3.1.0 (Apache-2.0,
# prowler/compliance/oraclecloud/cis_3.1_oraclecloud.json); the fact each one reads is
# the OCI resource the benchmark's audit procedure inspects.
#
# Input contract (facts the collector supplies from the OCI APIs; every list may be empty, but must be
# sent: an absent or null list was not collected and is reported as missing evidence. Booleans are the
# JSON booleans and numbers are JSON numbers; a string in their place is reported and never passes):
#   input.oci.iam.password_policy        : {minimum_length, max_age_days, reuse_prevented}
#   input.oci.iam.users[]                : {name, email, console_password, mfa_enabled, is_tenancy_admin,
#                                           api_keys[{age_days}], customer_secret_keys[{age_days}],
#                                           auth_tokens[{age_days}], db_passwords[{age_days}],
#                                           last_activity_days, active}
#   input.oci.iam.policies[]             : {name, statements[]}
#   input.oci.iam.dynamic_groups[]       : {name}
#   input.oci.iam.compartments[]         : {name, root}
#   input.oci.iam.root_compartment_resources[] : resources whose compartment is the root
#   input.oci.network.security_lists[]   : {vcn, is_default, ingress[{source, protocol, port_min, port_max}]}
#   input.oci.network.security_groups[]  : {ingress[{source, protocol, port_min, port_max}]}
#   input.oci.network.subnets[]          : {flow_logs_enabled}
#   input.oci.integration_instances[] / analytics_instances[] / autonomous_databases[] : {network_access}
#                                           ("private" | "allowlist" | "public")
#   input.oci.compute.instances[]        : {legacy_imds_endpoints_disabled, secure_boot_enabled,
#                                           in_transit_encryption_enabled}
#   input.oci.tagging.default_tags[]     : tag defaults applied at the root compartment
#   input.oci.notifications.topics[]     : {subscriptions}
#   input.oci.events.rules[]             : {enabled, event_types[], has_notification_action}
#   input.oci.cloud_guard                : {enabled, reporting_region, target_root}
#   input.oci.kms.keys[]                 : {customer_managed, rotation_interval_days}
#   input.oci.object_storage.buckets[]   : {public_access_type, kms_key_id, versioning, write_logging_enabled}
#   input.oci.block_storage.volumes[] / boot_volumes[] : {kms_key_id}
#   input.oci.file_storage.file_systems[] : {kms_key_id}

import rego.v1

default compliant := false

compliant if {
	input.oci
	count(violations) == 0
}

# ── helpers ──────────────────────────────────────────────────────────────────

_internet(src) if src == "0.0.0.0/0"

_internet(src) if src == "::/0"

# a rule opens `port` to the internet when its range covers the port (protocol "all" or tcp)
_opens(rule, port) if {
	_internet(rule.source)
	rule.protocol in {"all", "6", "tcp", "TCP"}
	_covers(rule, port)
}

_covers(rule, port) if {
	is_number(rule.port_min)
	is_number(rule.port_max)
	rule.port_min <= port
	rule.port_max >= port
}

# a rule with no port range covers every port
_covers(rule, _) if object.get(rule, "port_min", null) == null

# a bound that is not a number cannot be compared, so the rule is read as covering the port
_covers(rule, _) if {
	some bound in ["port_min", "port_max"]
	value := object.get(rule, bound, null)
	value != null
	not is_number(value)
}

# an enabled Events rule with a Notifications action covering every listed event type
_notified(types) if {
	some r in input.oci.events.rules
	r.enabled == true
	r.has_notification_action == true
	every t in types {
		t in r.event_types
	}
}

_rotated(keys, days) if {
	every k in keys {
		is_number(k.age_days)
		k.age_days <= days
	}
}

_all_cmk(items) if {
	every i in items {
		object.get(i, "kms_key_id", "") != ""
		i.kms_key_id != null
	}
}

# a number at or above / at or below the bound; a string, null or a missing value is neither
_at_least(value, bound) if {
	is_number(value)
	value >= bound
}

_at_most(value, bound) if {
	is_number(value)
	value <= bound
}

# ── Section 1: Identity and Access Management ────────────────────────────────

violations contains "1.1: service level admins must be created to manage resources of particular service" if {
	not _service_level_admin_policy
}

# RE2 has no lookaround: capture the group name and compare it
_group_statement(s, verb_re) := g if {
	m := regex.find_all_string_submatch_n(concat("", ["(?i)^allow group (\\S+) to ", verb_re]), s, 1)
	g := lower(m[0][1])
}

_service_level_admin_policy if {
	some p in input.oci.iam.policies
	some s in p.statements
	g := _group_statement(s, `manage \S+-family in `)
	g != "administrators"
}

violations contains "1.2: permissions on all resources must be given only to the tenancy administrator group" if {
	some p in input.oci.iam.policies
	some s in p.statements
	g := _group_statement(s, `manage all-resources in tenancy`)
	g != "administrators"
}

violations contains "1.3: checked condition — IAM administrators cannot update tenancy Administrators group" if {
	some p in input.oci.iam.policies
	some s in p.statements
	g := _group_statement(s, `(manage|use) (groups|users) in tenancy`)
	g != "administrators"
	not contains(lower(s), "target.group.name != 'administrators'")
}

violations contains "1.4: checked condition — IAM password policy requires minimum length of 14 or greater" if {
	not _at_least(object.get(input, ["oci", "iam", "password_policy", "minimum_length"], null), 14)
}

violations contains "1.5: checked condition — IAM password policy expires passwords within 365 days" if {
	not _at_most(object.get(input, ["oci", "iam", "password_policy", "max_age_days"], null), 365)
}

violations contains "1.6: checked condition — IAM password policy prevents password reuse" if {
	not input.oci.iam.password_policy.reuse_prevented == true
}

violations contains sprintf("1.7: MFA must be turned on for all users with a console password (%s)", [u.name]) if {
	some u in input.oci.iam.users
	u.console_password == true
	not u.mfa_enabled == true
}

violations contains sprintf("1.8: checked condition — user API keys rotate within 90 days (%s)", [u.name]) if {
	some u in input.oci.iam.users
	not _rotated(object.get(u, "api_keys", []), 90)
}

violations contains sprintf("1.9: checked condition — user customer secret keys rotate within 90 days (%s)", [u.name]) if {
	some u in input.oci.iam.users
	not _rotated(object.get(u, "customer_secret_keys", []), 90)
}

violations contains sprintf("1.10: checked condition — user auth tokens rotate within 90 days (%s)", [u.name]) if {
	some u in input.oci.iam.users
	not _rotated(object.get(u, "auth_tokens", []), 90)
}

violations contains sprintf("1.11: checked condition — user IAM Database Passwords rotate within 90 days (%s)", [u.name]) if {
	some u in input.oci.iam.users
	not _rotated(object.get(u, "db_passwords", []), 90)
}

violations contains sprintf("1.12: API keys must be not created for tenancy administrator users (%s)", [u.name]) if {
	some u in input.oci.iam.users
	u.is_tenancy_admin == true
	count(object.get(u, "api_keys", [])) > 0
}

violations contains sprintf("1.13: all OCI IAM local user accounts must have a valid and current email address (%s)", [u.name]) if {
	some u in input.oci.iam.users
	not regex.match(`^[^@\s]+@[^@\s]+\.[^@\s]+$`, object.get(u, "email", ""))
}

violations contains "1.14: Instance Principal authentication must be used for OCI instances, OCI Cloud Databases and OCI Functions to access OCI resources" if {
	count(input.oci.iam.dynamic_groups) == 0
}

violations contains "1.15: checked condition — storage service-level admins cannot delete resources they manage" if {
	some p in input.oci.iam.policies
	some s in p.statements
	g := _group_statement(s, `manage (volume-family|object-family|file-family|buckets|objects|volumes) in `)
	g != "administrators"
	not contains(lower(s), "request.permission")
}

violations contains sprintf("1.16: OCI IAM credentials unused for 45 days or more must be turned off (%s)", [u.name]) if {
	some u in input.oci.iam.users
	u.active == true
	not _at_most(object.get(u, "last_activity_days", null), 44)
}

violations contains sprintf("1.17: there must be only one active API Key for any single OCI IAM user (%s)", [u.name]) if {
	some u in input.oci.iam.users
	count(object.get(u, "api_keys", [])) > 1
}

# ── Section 2: Networking ────────────────────────────────────────────────────

violations contains "2.1: checked condition — no security lists allow ingress from 0.0.0.0/0 to port 22" if {
	some sl in input.oci.network.security_lists
	some r in sl.ingress
	_opens(r, 22)
}

violations contains "2.2: checked condition — no security lists allow ingress from 0.0.0.0/0 to port 3389" if {
	some sl in input.oci.network.security_lists
	some r in sl.ingress
	_opens(r, 3389)
}

violations contains "2.3: checked condition — no network security groups allow ingress from 0.0.0.0/0 to port 22" if {
	some g in input.oci.network.security_groups
	some r in g.ingress
	_opens(r, 22)
}

violations contains "2.4: checked condition — no network security groups allow ingress from 0.0.0.0/0 to port 3389" if {
	some g in input.oci.network.security_groups
	some r in g.ingress
	_opens(r, 3389)
}

violations contains sprintf("2.5: checked condition — the default security list of every VCN restricts all traffic except ICMP (%s)", [sl.vcn]) if {
	some sl in input.oci.network.security_lists
	sl.is_default == true
	some r in sl.ingress
	not object.get(r, "protocol", "all") in {"1", "icmp", "ICMP", "58", "icmpv6"}
}

violations contains "2.6: Oracle Integration Cloud (OIC) access must be restricted to allowed sources" if {
	some i in input.oci.integration_instances
	i.network_access == "public"
}

violations contains "2.7: Oracle Analytics Cloud (OAC) access must be restricted to allowed sources or deployed within a Virtual Cloud Network" if {
	some i in input.oci.analytics_instances
	i.network_access == "public"
}

violations contains "2.8: Oracle Autonomous Shared Databases (ADB) access must be restricted to allowed sources or deployed within a Virtual Cloud Network" if {
	some d in input.oci.autonomous_databases
	d.network_access == "public"
}

# ── Section 3: Compute ───────────────────────────────────────────────────────

violations contains "3.1: Compute Instance Legacy Metadata service endpoint must be turned off" if {
	some i in input.oci.compute.instances
	not i.legacy_imds_endpoints_disabled == true
}

violations contains "3.2: Secure Boot must be turned on for Compute Instance" if {
	some i in input.oci.compute.instances
	not i.secure_boot_enabled == true
}

violations contains "3.3: In-transit Encryption must be turned on for Compute Instance" if {
	some i in input.oci.compute.instances
	not i.in_transit_encryption_enabled == true
}

# ── Section 4: Logging and Monitoring ────────────────────────────────────────

violations contains "4.1: default tags must be used on resources" if {
	count(input.oci.tagging.default_tags) == 0
}

violations contains "4.2: Create at least one notification topic and subscription to receive monitoring alerts" if {
	not _topic_with_subscription
}

_topic_with_subscription if {
	some t in input.oci.notifications.topics
	is_number(t.subscriptions)
	t.subscriptions > 0
}

violations contains "4.3: a notification must be explicitly configured for Identity Provider changes" if {
	not _notified(["com.oraclecloud.identitycontrolplane.createidentityprovider", "com.oraclecloud.identitycontrolplane.deleteidentityprovider", "com.oraclecloud.identitycontrolplane.updateidentityprovider"])
}

violations contains "4.4: a notification must be explicitly configured for IdP group mapping changes" if {
	not _notified(["com.oraclecloud.identitycontrolplane.createidpgroupmapping", "com.oraclecloud.identitycontrolplane.deleteidpgroupmapping", "com.oraclecloud.identitycontrolplane.updateidpgroupmapping"])
}

violations contains "4.5: a notification must be explicitly configured for IAM group changes" if {
	not _notified(["com.oraclecloud.identitycontrolplane.creategroup", "com.oraclecloud.identitycontrolplane.deletegroup", "com.oraclecloud.identitycontrolplane.updategroup"])
}

violations contains "4.6: a notification must be explicitly configured for IAM policy changes" if {
	not _notified(["com.oraclecloud.identitycontrolplane.createpolicy", "com.oraclecloud.identitycontrolplane.deletepolicy", "com.oraclecloud.identitycontrolplane.updatepolicy"])
}

violations contains "4.7: a notification must be explicitly configured for user changes" if {
	not _notified(["com.oraclecloud.identitycontrolplane.createuser", "com.oraclecloud.identitycontrolplane.deleteuser", "com.oraclecloud.identitycontrolplane.updateuser", "com.oraclecloud.identitycontrolplane.updateusercapabilities", "com.oraclecloud.identitycontrolplane.updateuserstate"])
}

violations contains "4.8: a notification must be explicitly configured for VCN changes" if {
	not _notified(["com.oraclecloud.virtualnetwork.createvcn", "com.oraclecloud.virtualnetwork.deletevcn", "com.oraclecloud.virtualnetwork.updatevcn"])
}

violations contains "4.9: a notification must be explicitly configured for changes to route tables" if {
	not _notified(["com.oraclecloud.virtualnetwork.changeroutetablecompartment", "com.oraclecloud.virtualnetwork.createroutetable", "com.oraclecloud.virtualnetwork.deleteroutetable", "com.oraclecloud.virtualnetwork.updateroutetable"])
}

violations contains "4.10: a notification must be explicitly configured for security list changes" if {
	not _notified(["com.oraclecloud.virtualnetwork.changesecuritylistcompartment", "com.oraclecloud.virtualnetwork.createsecuritylist", "com.oraclecloud.virtualnetwork.deletesecuritylist", "com.oraclecloud.virtualnetwork.updatesecuritylist"])
}

violations contains "4.11: a notification must be explicitly configured for network security group changes" if {
	not _notified(["com.oraclecloud.virtualnetwork.changenetworksecuritygroupcompartment", "com.oraclecloud.virtualnetwork.createnetworksecuritygroup", "com.oraclecloud.virtualnetwork.deletenetworksecuritygroup", "com.oraclecloud.virtualnetwork.updatenetworksecuritygroup"])
}

violations contains "4.12: a notification must be explicitly configured for changes to network gateways" if {
	not _notified(["com.oraclecloud.virtualnetwork.createdrg", "com.oraclecloud.virtualnetwork.deletedrg", "com.oraclecloud.virtualnetwork.updatedrg", "com.oraclecloud.virtualnetwork.createinternetgateway", "com.oraclecloud.virtualnetwork.deleteinternetgateway", "com.oraclecloud.virtualnetwork.updateinternetgateway", "com.oraclecloud.virtualnetwork.createnatgateway", "com.oraclecloud.virtualnetwork.deletenatgateway", "com.oraclecloud.virtualnetwork.updatenatgateway", "com.oraclecloud.virtualnetwork.createservicegateway", "com.oraclecloud.virtualnetwork.deleteservicegateway", "com.oraclecloud.virtualnetwork.updateservicegateway", "com.oraclecloud.virtualnetwork.createlocalpeeringgateway", "com.oraclecloud.virtualnetwork.deletelocalpeeringgateway", "com.oraclecloud.virtualnetwork.updatelocalpeeringgateway"])
}

violations contains "4.13: VCN flow logging must be turned on for all subnets" if {
	some s in input.oci.network.subnets
	not s.flow_logs_enabled == true
}

violations contains "4.14: Cloud Guard must be turned on in the root compartment of the tenancy" if {
	not _cloud_guard_root
}

_cloud_guard_root if {
	input.oci.cloud_guard.enabled == true
	input.oci.cloud_guard.target_root == true
}

violations contains "4.15: a notification must be explicitly configured for Oracle Cloud Guard problems detected" if {
	not _notified(["com.oraclecloud.cloudguard.problemdetected"])
}

violations contains "4.16: customer created Customer Managed Key (CMK) must be rotated at least annually" if {
	some k in input.oci.kms.keys
	k.customer_managed == true
	not _at_most(object.get(k, "rotation_interval_days", null), 365)
}

violations contains "4.17: write level Object Storage logging must be turned on for all buckets" if {
	some b in input.oci.object_storage.buckets
	not b.write_logging_enabled == true
}

violations contains "4.18: a notification must be explicitly configured for Local OCI User Authentication" if {
	not _notified(["com.oraclecloud.identitysignon.interactivelogin"])
}

# ── Section 5: Storage ───────────────────────────────────────────────────────

violations contains "5.1.1: no Object Storage buckets must be publicly visible" if {
	some b in input.oci.object_storage.buckets
	object.get(b, "public_access_type", "unknown") != "NoPublicAccess"
}

violations contains "5.1.2: Object Storage Buckets must be encrypted with a Customer Managed Key (CMK)" if {
	not _all_cmk(input.oci.object_storage.buckets)
}

violations contains "5.1.3: Versioning must be turned on for Object Storage Buckets" if {
	some b in input.oci.object_storage.buckets
	object.get(b, "versioning", "Disabled") != "Enabled"
}

violations contains "5.2.1: Block Volumes must be encrypted with Customer Managed Keys (CMK)" if {
	not _all_cmk(input.oci.block_storage.volumes)
}

violations contains "5.2.2: boot volumes must be encrypted with Customer Managed Key (CMK)" if {
	not _all_cmk(input.oci.block_storage.boot_volumes)
}

violations contains "5.3.1: File Storage Systems must be encrypted with Customer Managed Keys (CMK)" if {
	not _all_cmk(input.oci.file_storage.file_systems)
}

# ── Section 6: Asset Management ──────────────────────────────────────────────

violations contains "6.1: Create at least one compartment in your tenancy to store cloud resources" if {
	count([c | some c in input.oci.iam.compartments; c.root == false]) == 0
}

violations contains "6.2: no resources must be created in the root compartment" if {
	count(input.oci.iam.root_compartment_resources) > 0
}

# ── fail-closed: without tenancy facts the benchmark reports a violation, never compliance ──

violations contains "CIS OCI: FAIL-CLOSED - facts 'input.oci' were not supplied; the tenancy was not evaluated" if {
	not input.oci
}

# ── evidence: a fact of the wrong type, or a list that was not collected, is a finding ──────────────
# Each entry is reported under the first recommendation that reads it. A list with nothing in it is sent
# as an empty list; a list that is absent or null was not collected, and its recommendations are not met.

_lists := {
	"iam.users": "1.7", "iam.policies": "1.1", "iam.dynamic_groups": "1.14", "iam.compartments": "6.1",
	"iam.root_compartment_resources": "6.2", "network.security_lists": "2.1", "network.security_groups": "2.3",
	"network.subnets": "4.13", "integration_instances": "2.6", "analytics_instances": "2.7",
	"autonomous_databases": "2.8", "compute.instances": "3.1", "tagging.default_tags": "4.1",
	"notifications.topics": "4.2", "events.rules": "4.3", "kms.keys": "4.16", "object_storage.buckets": "4.17",
	"block_storage.volumes": "5.2.1", "block_storage.boot_volumes": "5.2.2", "file_storage.file_systems": "5.3.1",
}

_fact(path) := object.get(input, array.concat(["oci"], split(path, ".")), null)

violations contains sprintf("%s: evidence missing: oci.%s not collected (a list; empty when there are none)", [id, path]) if {
	input.oci
	some path, id in _lists
	_fact(path) == null
}

violations contains sprintf("%s: oci.%s is not a list (got %s)", [id, path, type_name(_fact(path))]) if {
	some path, id in _lists
	_fact(path) != null
	not is_array(_fact(path))
}

# fields read from each item of a list: [recommendation, list, field, type, must be present]
_fields := [
	["1.7", "iam.users", "console_password", "boolean", true],
	["1.7", "iam.users", "mfa_enabled", "boolean", true],
	["1.12", "iam.users", "is_tenancy_admin", "boolean", true],
	["1.16", "iam.users", "active", "boolean", true],
	["1.16", "iam.users", "last_activity_days", "number", false],
	["6.1", "iam.compartments", "root", "boolean", true],
	["2.5", "network.security_lists", "is_default", "boolean", true],
	["4.13", "network.subnets", "flow_logs_enabled", "boolean", true],
	["3.1", "compute.instances", "legacy_imds_endpoints_disabled", "boolean", true],
	["3.2", "compute.instances", "secure_boot_enabled", "boolean", true],
	["3.3", "compute.instances", "in_transit_encryption_enabled", "boolean", true],
	["4.2", "notifications.topics", "subscriptions", "number", false],
	["4.3", "events.rules", "enabled", "boolean", false],
	["4.3", "events.rules", "has_notification_action", "boolean", false],
	["4.16", "kms.keys", "customer_managed", "boolean", true],
	["4.16", "kms.keys", "rotation_interval_days", "number", false],
	["4.17", "object_storage.buckets", "write_logging_enabled", "boolean", true],
]

violations contains sprintf("%s: evidence missing: oci.%s[%d].%s not collected", [id, path, i, field]) if {
	some [id, path, field, _, true] in _fields
	is_array(_fact(path))
	some i, item in _fact(path)
	object.get(item, field, null) == null
}

violations contains sprintf("%s: oci.%s[%d].%s is not a %s (got %s)", [id, path, i, field, type, type_name(value)]) if {
	some [id, path, field, type, _] in _fields
	is_array(_fact(path))
	some i, item in _fact(path)
	value := object.get(item, field, null)
	value != null
	type_name(value) != type
}

# the password policy is one object, not a list
_policy_fields := [["1.4", "minimum_length", "number"], ["1.5", "max_age_days", "number"], ["1.6", "reuse_prevented", "boolean"]]

violations contains sprintf("%s: evidence missing: oci.iam.password_policy.%s not collected", [id, field]) if {
	input.oci
	some [id, field, _] in _policy_fields
	_fact(sprintf("iam.password_policy.%s", [field])) == null
}

violations contains sprintf("%s: oci.iam.password_policy.%s is not a %s (got %s)", [id, field, type, type_name(value)]) if {
	some [id, field, type] in _policy_fields
	value := _fact(sprintf("iam.password_policy.%s", [field]))
	value != null
	type_name(value) != type
}

# ingress port bounds, when a rule carries them, are numbers
violations contains sprintf("%s: oci.%s[%d].ingress[%d].%s is not a number (got %s)", [id, path, i, j, bound, type_name(value)]) if {
	some path, id in {"network.security_lists": "2.1", "network.security_groups": "2.3"}
	is_array(_fact(path))
	some i, item in _fact(path)
	some j, rule in item.ingress
	some bound in ["port_min", "port_max"]
	value := object.get(rule, bound, null)
	value != null
	not is_number(value)
}

# ── report ───────────────────────────────────────────────────────────────────

sections := {
	"1": "Identity and Access Management", "2": "Networking", "3": "Compute",
	"4": "Logging and Monitoring", "5": "Storage", "6": "Asset Management",
}

level_2 := {"1.15", "3.1", "3.2", "4.13", "4.17", "5.1.2", "5.1.3", "5.2.1", "5.2.2", "5.3.1"}

compliance_report := {
	"benchmark": "CIS Oracle Cloud Infrastructure Foundations Benchmark v3.1",
	"total_controls": 54,
	"standard_total": 54,
	"standard_total_source": "CIS OCI Foundations Benchmark v3.1.0, 54 recommendations (Prowler mapping cis_3.1_oraclecloud.json)",
	"level_2_recommendations": level_2,
	"sections": sections,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
