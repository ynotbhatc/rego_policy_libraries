package cis_oci.main_test

import rego.v1

import data.cis_oci.main

green := {"oci": {
	"iam": {
		"password_policy": {"minimum_length": 14, "max_age_days": 365, "reuse_prevented": true},
		"users": [{"name": "alice", "email": "alice@example.com", "console_password": true, "mfa_enabled": true, "is_tenancy_admin": false, "api_keys": [{"age_days": 30}], "customer_secret_keys": [], "auth_tokens": [], "db_passwords": [], "last_activity_days": 3, "active": true}],
		"policies": [{"name": "svc", "statements": ["Allow group NetworkAdmins to manage virtual-network-family in tenancy", "Allow group StorageAdmins to manage volume-family in tenancy where request.permission != 'VOLUME_DELETE'"]}],
		"dynamic_groups": [{"name": "instances"}],
		"compartments": [{"name": "root", "root": true}, {"name": "prod", "root": false}],
		"root_compartment_resources": [],
	},
	"network": {
		"security_lists": [{"vcn": "vcn1", "is_default": true, "ingress": [{"source": "0.0.0.0/0", "protocol": "1"}]}, {"vcn": "vcn1", "is_default": false, "ingress": [{"source": "10.0.0.0/8", "protocol": "6", "port_min": 22, "port_max": 22}]}],
		"security_groups": [{"ingress": [{"source": "10.0.0.0/8", "protocol": "6", "port_min": 3389, "port_max": 3389}]}],
		"subnets": [{"flow_logs_enabled": true}],
	},
	"integration_instances": [{"network_access": "private"}],
	"analytics_instances": [{"network_access": "allowlist"}],
	"autonomous_databases": [{"network_access": "private"}],
	"compute": {"instances": [{"legacy_imds_endpoints_disabled": true, "secure_boot_enabled": true, "in_transit_encryption_enabled": true}]},
	"tagging": {"default_tags": ["Oracle-Tags.CreatedBy"]},
	"notifications": {"topics": [{"subscriptions": 2}]},
	"events": {"rules": [{"enabled": true, "has_notification_action": true, "event_types": [
		"com.oraclecloud.identitycontrolplane.createidentityprovider", "com.oraclecloud.identitycontrolplane.deleteidentityprovider", "com.oraclecloud.identitycontrolplane.updateidentityprovider",
		"com.oraclecloud.identitycontrolplane.createidpgroupmapping", "com.oraclecloud.identitycontrolplane.deleteidpgroupmapping", "com.oraclecloud.identitycontrolplane.updateidpgroupmapping",
		"com.oraclecloud.identitycontrolplane.creategroup", "com.oraclecloud.identitycontrolplane.deletegroup", "com.oraclecloud.identitycontrolplane.updategroup",
		"com.oraclecloud.identitycontrolplane.createpolicy", "com.oraclecloud.identitycontrolplane.deletepolicy", "com.oraclecloud.identitycontrolplane.updatepolicy",
		"com.oraclecloud.identitycontrolplane.createuser", "com.oraclecloud.identitycontrolplane.deleteuser", "com.oraclecloud.identitycontrolplane.updateuser", "com.oraclecloud.identitycontrolplane.updateusercapabilities", "com.oraclecloud.identitycontrolplane.updateuserstate",
		"com.oraclecloud.virtualnetwork.createvcn", "com.oraclecloud.virtualnetwork.deletevcn", "com.oraclecloud.virtualnetwork.updatevcn",
		"com.oraclecloud.virtualnetwork.changeroutetablecompartment", "com.oraclecloud.virtualnetwork.createroutetable", "com.oraclecloud.virtualnetwork.deleteroutetable", "com.oraclecloud.virtualnetwork.updateroutetable",
		"com.oraclecloud.virtualnetwork.changesecuritylistcompartment", "com.oraclecloud.virtualnetwork.createsecuritylist", "com.oraclecloud.virtualnetwork.deletesecuritylist", "com.oraclecloud.virtualnetwork.updatesecuritylist",
		"com.oraclecloud.virtualnetwork.changenetworksecuritygroupcompartment", "com.oraclecloud.virtualnetwork.createnetworksecuritygroup", "com.oraclecloud.virtualnetwork.deletenetworksecuritygroup", "com.oraclecloud.virtualnetwork.updatenetworksecuritygroup",
		"com.oraclecloud.virtualnetwork.createdrg", "com.oraclecloud.virtualnetwork.deletedrg", "com.oraclecloud.virtualnetwork.updatedrg", "com.oraclecloud.virtualnetwork.createinternetgateway", "com.oraclecloud.virtualnetwork.deleteinternetgateway", "com.oraclecloud.virtualnetwork.updateinternetgateway", "com.oraclecloud.virtualnetwork.createnatgateway", "com.oraclecloud.virtualnetwork.deletenatgateway", "com.oraclecloud.virtualnetwork.updatenatgateway", "com.oraclecloud.virtualnetwork.createservicegateway", "com.oraclecloud.virtualnetwork.deleteservicegateway", "com.oraclecloud.virtualnetwork.updateservicegateway", "com.oraclecloud.virtualnetwork.createlocalpeeringgateway", "com.oraclecloud.virtualnetwork.deletelocalpeeringgateway", "com.oraclecloud.virtualnetwork.updatelocalpeeringgateway",
		"com.oraclecloud.cloudguard.problemdetected", "com.oraclecloud.identitysignon.interactivelogin",
	]}]},
	"cloud_guard": {"enabled": true, "target_root": true},
	"kms": {"keys": [{"customer_managed": true, "rotation_interval_days": 365}]},
	"object_storage": {"buckets": [{"public_access_type": "NoPublicAccess", "kms_key_id": "ocid1.key.a", "versioning": "Enabled", "write_logging_enabled": true}]},
	"block_storage": {"volumes": [{"kms_key_id": "ocid1.key.a"}], "boot_volumes": [{"kms_key_id": "ocid1.key.a"}]},
	"file_storage": {"file_systems": [{"kms_key_id": "ocid1.key.a"}]},
}}

test_green_tenancy_is_compliant if {
	r := main.compliance_report with input as green
	r.compliant == true
	count(r.violations) == 0
}

test_fail_closed_on_empty_input if {
	r := main.compliance_report with input as {}
	r.compliant == false
	count(r.violations) > 0
}

test_ssh_open_to_internet_is_2_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oci/network/security_lists/1/ingress/0/source", "value": "0.0.0.0/0"}])
	v := main.violations with input as bad
	"2.1: Ensure no security lists allow ingress from 0.0.0.0/0 to port 22" in v
	not main.compliant with input as bad
}

test_public_bucket_is_5_1_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oci/object_storage/buckets/0/public_access_type", "value": "ObjectRead"}])
	"5.1.1: Ensure no Object Storage buckets are publicly visible" in main.violations with input as bad
}

test_missing_mfa_names_the_user if {
	bad := json.patch(green, [{"op": "replace", "path": "/oci/iam/users/0/mfa_enabled", "value": false}])
	"1.7: Ensure MFA is enabled for all users with a console password (alice)" in main.violations with input as bad
}

test_missing_event_rule_is_4_6 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oci/events/rules/0/enabled", "value": false}])
	"4.6: Ensure a notification is configured for IAM policy changes" in main.violations with input as bad
}

test_every_recommendation_has_a_rule if {
	# the 54 ids the benchmark carries must each appear in a violation on a broken tenancy
	broken := {"oci": {"iam": {"password_policy": {}, "users": [{"name": "x", "console_password": true, "is_tenancy_admin": true, "api_keys": [{"age_days": 200}, {"age_days": 1}], "customer_secret_keys": [{"age_days": 200}], "auth_tokens": [{"age_days": 200}], "db_passwords": [{"age_days": 200}], "last_activity_days": 90, "active": true}], "policies": [{"name": "p", "statements": ["Allow group Devs to manage all-resources in tenancy", "Allow group Devs to manage groups in tenancy", "Allow group Devs to manage buckets in tenancy"]}], "dynamic_groups": [], "compartments": [{"name": "root", "root": true}], "root_compartment_resources": ["ocid1.instance.x"]},
		"network": {"security_lists": [{"vcn": "v", "is_default": true, "ingress": [{"source": "0.0.0.0/0", "protocol": "all"}]}], "security_groups": [{"ingress": [{"source": "0.0.0.0/0", "protocol": "all"}]}], "subnets": [{"flow_logs_enabled": false}]},
		"integration_instances": [{"network_access": "public"}], "analytics_instances": [{"network_access": "public"}], "autonomous_databases": [{"network_access": "public"}],
		"compute": {"instances": [{}]}, "tagging": {"default_tags": []}, "notifications": {"topics": []}, "events": {"rules": []}, "cloud_guard": {"enabled": false},
		"kms": {"keys": [{"customer_managed": true, "rotation_interval_days": 730}]},
		"object_storage": {"buckets": [{"public_access_type": "ObjectRead", "kms_key_id": "", "versioning": "Disabled", "write_logging_enabled": false}]},
		"block_storage": {"volumes": [{"kms_key_id": ""}], "boot_volumes": [{"kms_key_id": ""}]}, "file_storage": {"file_systems": [{"kms_key_id": ""}]}}}
	v := main.violations with input as broken
	ids := {id | some m in v; id := split(m, ":")[0]}
	count(ids) == 54
}
