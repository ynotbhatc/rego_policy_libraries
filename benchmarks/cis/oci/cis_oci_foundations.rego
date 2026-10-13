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
#     as_of: v2.4.1
package cis_oci.main

# CIS Oracle Cloud Infrastructure Foundations Benchmark v3.1 (CIS lists 3.1.1 as current)
# 54 recommendations across 6 sections: 1 IAM (17), 2 Networking (8), 3 Compute (3),
# 4 Logging and Monitoring (18), 5 Storage (6), 6 Asset Management (2).
# Recommendation ids and titles from the public Prowler mapping of v3.1.0 (Apache-2.0,
# prowler/compliance/oraclecloud/cis_3.1_oraclecloud.json); the fact each one reads is
# the OCI resource the benchmark's audit procedure inspects.
#
# Input contract (facts the collector supplies from the OCI APIs; every list may be empty):
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
	rule.port_min <= port
	rule.port_max >= port
}

# a rule with no port range covers every port
_opens(rule, _) if {
	_internet(rule.source)
	rule.protocol in {"all", "6", "tcp", "TCP"}
	not rule.port_min
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
		object.get(k, "age_days", 99999) <= days
	}
}

_all_cmk(items) if {
	every i in items {
		object.get(i, "kms_key_id", "") != ""
		i.kms_key_id != null
	}
}

# ── Section 1: Identity and Access Management ────────────────────────────────

violations contains "1.1: Ensure service level admins are created to manage resources of particular service" if {
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

violations contains "1.2: Ensure permissions on all resources are given only to the tenancy administrator group" if {
	some p in input.oci.iam.policies
	some s in p.statements
	g := _group_statement(s, `manage all-resources in tenancy`)
	g != "administrators"
}

violations contains "1.3: Ensure IAM administrators cannot update tenancy Administrators group" if {
	some p in input.oci.iam.policies
	some s in p.statements
	g := _group_statement(s, `(manage|use) (groups|users) in tenancy`)
	g != "administrators"
	not contains(lower(s), "target.group.name != 'administrators'")
}

violations contains "1.4: Ensure IAM password policy requires minimum length of 14 or greater" if {
	not object.get(input.oci.iam.password_policy, "minimum_length", 0) >= 14
}

violations contains "1.5: Ensure IAM password policy expires passwords within 365 days" if {
	not object.get(input.oci.iam.password_policy, "max_age_days", 99999) <= 365
}

violations contains "1.6: Ensure IAM password policy prevents password reuse" if {
	not input.oci.iam.password_policy.reuse_prevented
}

violations contains sprintf("1.7: Ensure MFA is enabled for all users with a console password (%s)", [u.name]) if {
	some u in input.oci.iam.users
	u.console_password == true
	not u.mfa_enabled
}

violations contains sprintf("1.8: Ensure user API keys rotate within 90 days (%s)", [u.name]) if {
	some u in input.oci.iam.users
	not _rotated(object.get(u, "api_keys", []), 90)
}

violations contains sprintf("1.9: Ensure user customer secret keys rotate within 90 days (%s)", [u.name]) if {
	some u in input.oci.iam.users
	not _rotated(object.get(u, "customer_secret_keys", []), 90)
}

violations contains sprintf("1.10: Ensure user auth tokens rotate within 90 days (%s)", [u.name]) if {
	some u in input.oci.iam.users
	not _rotated(object.get(u, "auth_tokens", []), 90)
}

violations contains sprintf("1.11: Ensure user IAM Database Passwords rotate within 90 days (%s)", [u.name]) if {
	some u in input.oci.iam.users
	not _rotated(object.get(u, "db_passwords", []), 90)
}

violations contains sprintf("1.12: Ensure API keys are not created for tenancy administrator users (%s)", [u.name]) if {
	some u in input.oci.iam.users
	u.is_tenancy_admin == true
	count(object.get(u, "api_keys", [])) > 0
}

violations contains sprintf("1.13: Ensure all OCI IAM local user accounts have a valid and current email address (%s)", [u.name]) if {
	some u in input.oci.iam.users
	not regex.match(`^[^@\s]+@[^@\s]+\.[^@\s]+$`, object.get(u, "email", ""))
}

violations contains "1.14: Ensure Instance Principal authentication is used for OCI instances, OCI Cloud Databases and OCI Functions to access OCI resources" if {
	count(input.oci.iam.dynamic_groups) == 0
}

violations contains "1.15: Ensure storage service-level admins cannot delete resources they manage" if {
	some p in input.oci.iam.policies
	some s in p.statements
	g := _group_statement(s, `manage (volume-family|object-family|file-family|buckets|objects|volumes) in `)
	g != "administrators"
	not contains(lower(s), "request.permission")
}

violations contains sprintf("1.16: Ensure OCI IAM credentials unused for 45 days or more are disabled (%s)", [u.name]) if {
	some u in input.oci.iam.users
	u.active == true
	object.get(u, "last_activity_days", 99999) >= 45
}

violations contains sprintf("1.17: Ensure there is only one active API Key for any single OCI IAM user (%s)", [u.name]) if {
	some u in input.oci.iam.users
	count(object.get(u, "api_keys", [])) > 1
}

# ── Section 2: Networking ────────────────────────────────────────────────────

violations contains "2.1: Ensure no security lists allow ingress from 0.0.0.0/0 to port 22" if {
	some sl in input.oci.network.security_lists
	some r in sl.ingress
	_opens(r, 22)
}

violations contains "2.2: Ensure no security lists allow ingress from 0.0.0.0/0 to port 3389" if {
	some sl in input.oci.network.security_lists
	some r in sl.ingress
	_opens(r, 3389)
}

violations contains "2.3: Ensure no network security groups allow ingress from 0.0.0.0/0 to port 22" if {
	some g in input.oci.network.security_groups
	some r in g.ingress
	_opens(r, 22)
}

violations contains "2.4: Ensure no network security groups allow ingress from 0.0.0.0/0 to port 3389" if {
	some g in input.oci.network.security_groups
	some r in g.ingress
	_opens(r, 3389)
}

violations contains sprintf("2.5: Ensure the default security list of every VCN restricts all traffic except ICMP (%s)", [sl.vcn]) if {
	some sl in input.oci.network.security_lists
	sl.is_default == true
	some r in sl.ingress
	not object.get(r, "protocol", "all") in {"1", "icmp", "ICMP", "58", "icmpv6"}
}

violations contains "2.6: Ensure Oracle Integration Cloud (OIC) access is restricted to allowed sources" if {
	some i in input.oci.integration_instances
	i.network_access == "public"
}

violations contains "2.7: Ensure Oracle Analytics Cloud (OAC) access is restricted to allowed sources or deployed within a Virtual Cloud Network" if {
	some i in input.oci.analytics_instances
	i.network_access == "public"
}

violations contains "2.8: Ensure Oracle Autonomous Shared Databases (ADB) access is restricted to allowed sources or deployed within a Virtual Cloud Network" if {
	some d in input.oci.autonomous_databases
	d.network_access == "public"
}

# ── Section 3: Compute ───────────────────────────────────────────────────────

violations contains "3.1: Ensure Compute Instance Legacy Metadata service endpoint is disabled" if {
	some i in input.oci.compute.instances
	not i.legacy_imds_endpoints_disabled
}

violations contains "3.2: Ensure Secure Boot is enabled on Compute Instance" if {
	some i in input.oci.compute.instances
	not i.secure_boot_enabled
}

violations contains "3.3: Ensure In-transit Encryption is enabled on Compute Instance" if {
	some i in input.oci.compute.instances
	not i.in_transit_encryption_enabled
}

# ── Section 4: Logging and Monitoring ────────────────────────────────────────

violations contains "4.1: Ensure default tags are used on resources" if {
	count(input.oci.tagging.default_tags) == 0
}

violations contains "4.2: Create at least one notification topic and subscription to receive monitoring alerts" if {
	not _topic_with_subscription
}

_topic_with_subscription if {
	some t in input.oci.notifications.topics
	t.subscriptions > 0
}

violations contains "4.3: Ensure a notification is configured for Identity Provider changes" if {
	not _notified(["com.oraclecloud.identitycontrolplane.createidentityprovider", "com.oraclecloud.identitycontrolplane.deleteidentityprovider", "com.oraclecloud.identitycontrolplane.updateidentityprovider"])
}

violations contains "4.4: Ensure a notification is configured for IdP group mapping changes" if {
	not _notified(["com.oraclecloud.identitycontrolplane.createidpgroupmapping", "com.oraclecloud.identitycontrolplane.deleteidpgroupmapping", "com.oraclecloud.identitycontrolplane.updateidpgroupmapping"])
}

violations contains "4.5: Ensure a notification is configured for IAM group changes" if {
	not _notified(["com.oraclecloud.identitycontrolplane.creategroup", "com.oraclecloud.identitycontrolplane.deletegroup", "com.oraclecloud.identitycontrolplane.updategroup"])
}

violations contains "4.6: Ensure a notification is configured for IAM policy changes" if {
	not _notified(["com.oraclecloud.identitycontrolplane.createpolicy", "com.oraclecloud.identitycontrolplane.deletepolicy", "com.oraclecloud.identitycontrolplane.updatepolicy"])
}

violations contains "4.7: Ensure a notification is configured for user changes" if {
	not _notified(["com.oraclecloud.identitycontrolplane.createuser", "com.oraclecloud.identitycontrolplane.deleteuser", "com.oraclecloud.identitycontrolplane.updateuser", "com.oraclecloud.identitycontrolplane.updateusercapabilities", "com.oraclecloud.identitycontrolplane.updateuserstate"])
}

violations contains "4.8: Ensure a notification is configured for VCN changes" if {
	not _notified(["com.oraclecloud.virtualnetwork.createvcn", "com.oraclecloud.virtualnetwork.deletevcn", "com.oraclecloud.virtualnetwork.updatevcn"])
}

violations contains "4.9: Ensure a notification is configured for changes to route tables" if {
	not _notified(["com.oraclecloud.virtualnetwork.changeroutetablecompartment", "com.oraclecloud.virtualnetwork.createroutetable", "com.oraclecloud.virtualnetwork.deleteroutetable", "com.oraclecloud.virtualnetwork.updateroutetable"])
}

violations contains "4.10: Ensure a notification is configured for security list changes" if {
	not _notified(["com.oraclecloud.virtualnetwork.changesecuritylistcompartment", "com.oraclecloud.virtualnetwork.createsecuritylist", "com.oraclecloud.virtualnetwork.deletesecuritylist", "com.oraclecloud.virtualnetwork.updatesecuritylist"])
}

violations contains "4.11: Ensure a notification is configured for network security group changes" if {
	not _notified(["com.oraclecloud.virtualnetwork.changenetworksecuritygroupcompartment", "com.oraclecloud.virtualnetwork.createnetworksecuritygroup", "com.oraclecloud.virtualnetwork.deletenetworksecuritygroup", "com.oraclecloud.virtualnetwork.updatenetworksecuritygroup"])
}

violations contains "4.12: Ensure a notification is configured for changes to network gateways" if {
	not _notified(["com.oraclecloud.virtualnetwork.createdrg", "com.oraclecloud.virtualnetwork.deletedrg", "com.oraclecloud.virtualnetwork.updatedrg", "com.oraclecloud.virtualnetwork.createinternetgateway", "com.oraclecloud.virtualnetwork.deleteinternetgateway", "com.oraclecloud.virtualnetwork.updateinternetgateway", "com.oraclecloud.virtualnetwork.createnatgateway", "com.oraclecloud.virtualnetwork.deletenatgateway", "com.oraclecloud.virtualnetwork.updatenatgateway", "com.oraclecloud.virtualnetwork.createservicegateway", "com.oraclecloud.virtualnetwork.deleteservicegateway", "com.oraclecloud.virtualnetwork.updateservicegateway", "com.oraclecloud.virtualnetwork.createlocalpeeringgateway", "com.oraclecloud.virtualnetwork.deletelocalpeeringgateway", "com.oraclecloud.virtualnetwork.updatelocalpeeringgateway"])
}

violations contains "4.13: Ensure VCN flow logging is enabled for all subnets" if {
	some s in input.oci.network.subnets
	not s.flow_logs_enabled
}

violations contains "4.14: Ensure Cloud Guard is enabled in the root compartment of the tenancy" if {
	not _cloud_guard_root
}

_cloud_guard_root if {
	input.oci.cloud_guard.enabled == true
	input.oci.cloud_guard.target_root == true
}

violations contains "4.15: Ensure a notification is configured for Oracle Cloud Guard problems detected" if {
	not _notified(["com.oraclecloud.cloudguard.problemdetected"])
}

violations contains "4.16: Ensure customer created Customer Managed Key (CMK) is rotated at least annually" if {
	some k in input.oci.kms.keys
	k.customer_managed == true
	not object.get(k, "rotation_interval_days", 99999) <= 365
}

violations contains "4.17: Ensure write level Object Storage logging is enabled for all buckets" if {
	some b in input.oci.object_storage.buckets
	not b.write_logging_enabled
}

violations contains "4.18: Ensure a notification is configured for Local OCI User Authentication" if {
	not _notified(["com.oraclecloud.identitysignon.interactivelogin"])
}

# ── Section 5: Storage ───────────────────────────────────────────────────────

violations contains "5.1.1: Ensure no Object Storage buckets are publicly visible" if {
	some b in input.oci.object_storage.buckets
	object.get(b, "public_access_type", "unknown") != "NoPublicAccess"
}

violations contains "5.1.2: Ensure Object Storage Buckets are encrypted with a Customer Managed Key (CMK)" if {
	not _all_cmk(input.oci.object_storage.buckets)
}

violations contains "5.1.3: Ensure Versioning is Enabled for Object Storage Buckets" if {
	some b in input.oci.object_storage.buckets
	object.get(b, "versioning", "Disabled") != "Enabled"
}

violations contains "5.2.1: Ensure Block Volumes are encrypted with Customer Managed Keys (CMK)" if {
	not _all_cmk(input.oci.block_storage.volumes)
}

violations contains "5.2.2: Ensure boot volumes are encrypted with Customer Managed Key (CMK)" if {
	not _all_cmk(input.oci.block_storage.boot_volumes)
}

violations contains "5.3.1: Ensure File Storage Systems are encrypted with Customer Managed Keys (CMK)" if {
	not _all_cmk(input.oci.file_storage.file_systems)
}

# ── Section 6: Asset Management ──────────────────────────────────────────────

violations contains "6.1: Create at least one compartment in your tenancy to store cloud resources" if {
	count([c | some c in input.oci.iam.compartments; not c.root]) == 0
}

violations contains "6.2: Ensure no resources are created in the root compartment" if {
	count(input.oci.iam.root_compartment_resources) > 0
}

# ── fail-closed: without tenancy facts the benchmark reports a violation, never compliance ──

violations contains "CIS OCI: FAIL-CLOSED - facts 'input.oci' were not supplied; the tenancy was not evaluated" if {
	not input.oci
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
