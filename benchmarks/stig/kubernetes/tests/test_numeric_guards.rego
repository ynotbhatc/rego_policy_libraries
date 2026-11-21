package stig.kubernetes.numeric_guards_test

import rego.v1

# Type traps (#300): a cluster version or a group-range minimum that is not a number must not pass.

test_000460_passes_on_a_parsed_version if {
	data.stig.kubernetes.core.r_cntr_k8_000460 with input as {"cluster": {"version": "v1.30.2"}}
}

test_000460_type_traps_do_not_pass if {
	every v in ["1", null, "x", 1] {
		not data.stig.kubernetes.core.r_cntr_k8_000460 with input as {"cluster": {"version": v}}
		data.stig.kubernetes.core.status_r_cntr_k8_000460 == "Open" with input as {"cluster": {"version": v}}
	}
}

test_002010_passes_on_numeric_group_minimums if {
	data.stig.kubernetes.core.r_cntr_k8_002010 with input as {
		"cluster": {"version": "v1.24.9"},
		"pod_security": {"policies": [{
			"runAsUser": {"rule": "MustRunAsNonRoot"},
			"supplementalGroups": {"ranges": [{"min": 1}]},
			"fsGroup": {"ranges": [{"min": 1}]},
		}]},
	}
}

test_002010_type_traps_do_not_pass if {
	every v in ["1", null, "x"] {
		not data.stig.kubernetes.core.r_cntr_k8_002010 with input as {
			"cluster": {"version": "v1.24.9"},
			"pod_security": {"policies": [{
				"runAsUser": {"rule": "MustRunAsNonRoot"},
				"supplementalGroups": {"ranges": [{"min": v}]},
				"fsGroup": {"ranges": [{"min": 1}]},
			}]},
		}
		not data.stig.kubernetes.core.r_cntr_k8_002010 with input as {
			"cluster": {"version": "v1.24.9"},
			"pod_security": {"policies": [{
				"runAsUser": {"rule": "MustRunAsNonRoot"},
				"supplementalGroups": {"ranges": [{"min": 1}]},
				"fsGroup": {"ranges": [{"min": v}]},
			}]},
		}
	}
}
