package cis_kubernetes.l2_test

import rego.v1

# Validation fix 2026-10-17: flag checks using `!=` / to_number() / contains() were undefined
# (= pass) when the flag was absent.

good_api := {
	"anonymous-auth": "false",
	"kubelet-certificate-authority": "/ca",
	"enable-admission-plugins": "NodeRestriction, EventRateLimit,AlwaysPullImages",
	"audit-log-maxage": "30",
	"audit-log-maxbackup": "10",
	"audit-log-maxsize": "100",
	"audit-policy-file": "/p",
	"service-account-lookup": "true",
	"encryption-provider-config": "/e",
}

good := {
	"api_server_flags": good_api,
	"controller_manager_flags": {"profiling": "false", "use-service-account-credentials": "true", "feature-gates": "RotateKubeletServerCertificate=true"},
	"scheduler_flags": {"profiling": "false"},
	"etcd_flags": {"cert-file": "c", "client-cert-auth": "true", "peer-cert-file": "p", "peer-client-cert-auth": "true"},
	"kubelet_flags": {"anonymous-auth": "false", "protect-kernel-defaults": "true", "event-qps": "0", "tls-cert-file": "c", "rotate-certificates": "true", "feature-gates": "RotateKubeletServerCertificate=true"},
	"audit_policy": {"metadata_level_configured": true, "request_response_configured": true},
}

with_api(flags) := object.union(object.remove(good, ["api_server_flags"]), {"api_server_flags": flags})

test_good_compliant if {
	data.cis_kubernetes.l2.compliant with input as good
}

test_missing_admission_plugin_violates if {
	not data.cis_kubernetes.l2.compliant with input as with_api(object.remove(good_api, ["enable-admission-plugins"]))
}

test_eventratelimit_only_is_not_enough if {
	v := data.cis_kubernetes.l2.violations with input as with_api(object.union(good_api, {"enable-admission-plugins": "EventRateLimit"}))
	"CIS L2 1.2.11: API server admission control: AlwaysPullImages enabled" in v
}

test_missing_anonymous_auth_violates if {
	v := data.cis_kubernetes.l2.violations with input as with_api(object.remove(good_api, ["anonymous-auth"]))
	"CIS L2 1.2.1: API server anonymous-auth flag must be false" in v
}

test_missing_audit_maxage_violates if {
	v := data.cis_kubernetes.l2.violations with input as with_api(object.remove(good_api, ["audit-log-maxage"]))
	"CIS L2 1.2.22: API server --audit-log-maxage set to 30 or more days" in v
}

test_low_audit_maxage_violates if {
	v := data.cis_kubernetes.l2.violations with input as with_api(object.union(good_api, {"audit-log-maxage": "7"}))
	"CIS L2 1.2.22: API server --audit-log-maxage set to 30 or more days" in v
}

test_non_numeric_maxsize_violates if {
	v := data.cis_kubernetes.l2.violations with input as with_api(object.union(good_api, {"audit-log-maxsize": "lots"}))
	"CIS L2 1.2.24: API server --audit-log-maxsize set to 100 MB or more" in v
}

test_nonzero_insecure_port_violates if {
	v := data.cis_kubernetes.l2.violations with input as with_api(object.union(good_api, {"insecure-port": "8080"}))
	"CIS L2 1.2.19: API server --insecure-port set to 0" in v
}

test_missing_kubelet_gate_violates if {
	inp := object.union(object.remove(good, ["kubelet_flags"]), {"kubelet_flags": {"anonymous-auth": "false", "protect-kernel-defaults": "true", "event-qps": "0", "tls-cert-file": "c", "rotate-certificates": "true"}})
	not data.cis_kubernetes.l2.compliant with input as inp
}

test_missing_section_evidence_violates if {
	v := data.cis_kubernetes.l2.violations with input as object.remove(good, ["scheduler_flags"])
	"CIS L2: evidence missing — scheduler_flags not collected" in v
}

test_empty_input_report_populated if {
	r := data.cis_kubernetes.l2.compliance_report with input as {}
	r.l2_compliant == false
	r.l2_violations > 0
}

# Decisions 2026-10-19: 4.2.9 accepts 0 or >= 5; 1.2.19 absent flag still passes.
with_qps(q) := object.union(object.remove(good, ["kubelet_flags"]), {"kubelet_flags": object.union(good.kubelet_flags, {"event-qps": q})})

test_event_qps_default_5_accepted if {
	data.cis_kubernetes.l2.compliant with input as with_qps("5")
}

test_event_qps_high_accepted if {
	data.cis_kubernetes.l2.compliant with input as with_qps("50")
}

test_event_qps_between_zero_and_five_violates if {
	not data.cis_kubernetes.l2.compliant with input as with_qps("3")
}

test_event_qps_unset_violates if {
	i := object.union(object.remove(good, ["kubelet_flags"]), {"kubelet_flags": object.remove(good.kubelet_flags, ["event-qps"])})
	not data.cis_kubernetes.l2.compliant with input as i
}

test_insecure_port_absent_still_passes if {
	not "CIS L2 1.2.19: API server --insecure-port set to 0" in data.cis_kubernetes.l2.violations with input as good
}
