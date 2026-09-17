package k8s_pss.main_test

import data.k8s_pss.main
import rego.v1

# ── Fail-closed ──────────────────────────────────────────────────────────────

test_no_manifest_is_not_a_pass if {
	r := main.compliance_report with input as {}
	r.compliant == false
	r.baseline_compliant == false
	r.restricted_compliant == false
	some v in r.violations
	contains(v, "fail-closed")
}

test_default_target_profile_is_restricted if {
	r := main.compliance_report with input as {}
	r.target_profile == "restricted"
}

# ── A pod meeting the Restricted profile ─────────────────────────────────────

restricted_pod := {"pod": {
	"metadata": {"name": "web"},
	"spec": {
		"securityContext": {
			"runAsNonRoot": true,
			"seccompProfile": {"type": "RuntimeDefault"},
		},
		"containers": [{
			"name": "app",
			"image": "registry.access.redhat.com/ubi9/ubi-minimal:latest",
			"ports": [{"containerPort": 8080}],
			"securityContext": {
				"allowPrivilegeEscalation": false,
				"capabilities": {"drop": ["ALL"]},
			},
		}],
		"volumes": [{"name": "scratch", "emptyDir": {}}],
	},
}}

test_restricted_compliant_pod if {
	r := main.compliance_report with input as restricted_pod
	r.compliant == true
	r.baseline_compliant == true
	r.restricted_compliant == true
	r.violation_count == 0
	r.pod_name == "web"
}

# ── A pod meeting Baseline but not Restricted ────────────────────────────────

baseline_only_pod := {"pod": {
	"metadata": {"name": "legacy"},
	"spec": {
		"containers": [{
			"name": "app",
			"image": "registry.access.redhat.com/ubi9/ubi:latest",
		}],
	},
}}

test_baseline_only_pod_fails_restricted_by_default if {
	r := main.compliance_report with input as baseline_only_pod
	r.baseline_compliant == true
	r.restricted_compliant == false
	r.compliant == false
	r.restricted_additional_violation_count > 0
}

test_baseline_only_pod_passes_when_targeting_baseline if {
	r := main.compliance_report with input as object.union(baseline_only_pod, {"pss_profile": "baseline"})
	r.target_profile == "baseline"
	r.compliant == true
	r.violation_count == 0
}

# ── Targeted baseline violations ─────────────────────────────────────────────

test_privileged_container_fails_baseline if {
	bad := json.patch(restricted_pod, [{
		"op": "replace",
		"path": "/pod/spec/containers/0/securityContext",
		"value": {"privileged": true, "allowPrivilegeEscalation": false, "capabilities": {"drop": ["ALL"]}},
	}])
	r := main.compliance_report with input as bad
	r.baseline_compliant == false
	some v in r.violations
	contains(v, "(privileged)")
}

test_hostpath_volume_fails_baseline if {
	bad := json.patch(restricted_pod, [{
		"op": "replace",
		"path": "/pod/spec/volumes",
		"value": [{"name": "host", "hostPath": {"path": "/etc"}}],
	}])
	r := main.compliance_report with input as bad
	r.baseline_compliant == false
	some v in r.violations
	contains(v, "hostPath")
}

test_host_network_fails_baseline if {
	bad := json.patch(restricted_pod, [{
		"op": "add",
		"path": "/pod/spec/hostNetwork",
		"value": true,
	}])
	r := main.compliance_report with input as bad
	r.baseline_compliant == false
}

test_disallowed_capability_fails_baseline if {
	bad := json.patch(restricted_pod, [{
		"op": "replace",
		"path": "/pod/spec/containers/0/securityContext/capabilities",
		"value": {"drop": ["ALL"], "add": ["SYS_ADMIN"]},
	}])
	r := main.compliance_report with input as bad
	r.baseline_compliant == false
	some v in r.violations
	contains(v, "SYS_ADMIN")
}

test_unsafe_sysctl_fails_baseline if {
	bad := json.patch(restricted_pod, [{
		"op": "add",
		"path": "/pod/spec/securityContext/sysctls",
		"value": [{"name": "kernel.msgmax", "value": "65536"}],
	}])
	r := main.compliance_report with input as bad
	r.baseline_compliant == false
	some v in r.violations
	contains(v, "kernel.msgmax")
}

test_seccomp_unconfined_fails_baseline if {
	bad := json.patch(restricted_pod, [{
		"op": "replace",
		"path": "/pod/spec/securityContext/seccompProfile",
		"value": {"type": "Unconfined"},
	}])
	r := main.compliance_report with input as bad
	r.baseline_compliant == false
}

# ── Targeted restricted violations ───────────────────────────────────────────

test_run_as_root_user_fails_restricted if {
	bad := json.patch(restricted_pod, [{
		"op": "add",
		"path": "/pod/spec/containers/0/securityContext/runAsUser",
		"value": 0,
	}])
	r := main.compliance_report with input as bad
	r.restricted_compliant == false
	some v in r.violations
	contains(v, "runAsUser=0")
}

test_container_nonroot_false_overrides_pod_level if {
	bad := json.patch(restricted_pod, [{
		"op": "add",
		"path": "/pod/spec/containers/0/securityContext/runAsNonRoot",
		"value": false,
	}])
	r := main.compliance_report with input as bad
	r.restricted_compliant == false
	some v in r.violations
	contains(v, "run-as-nonroot")
}

test_secret_volume_allowed_in_restricted if {
	ok := json.patch(restricted_pod, [{
		"op": "replace",
		"path": "/pod/spec/volumes",
		"value": [{"name": "creds", "secret": {"secretName": "app-creds"}}],
	}])
	r := main.compliance_report with input as ok
	r.restricted_compliant == true
}

test_added_capability_beyond_netbind_fails_restricted if {
	bad := json.patch(restricted_pod, [{
		"op": "replace",
		"path": "/pod/spec/containers/0/securityContext/capabilities",
		"value": {"drop": ["ALL"], "add": ["CHOWN"]},
	}])
	r := main.compliance_report with input as bad
	# CHOWN is baseline-allowed but restricted only permits NET_BIND_SERVICE.
	r.baseline_compliant == true
	r.restricted_compliant == false
}
