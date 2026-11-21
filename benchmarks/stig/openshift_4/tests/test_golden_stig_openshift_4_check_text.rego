# Golden cases for the DISA STIG for Red Hat OpenShift Container Platform 4.x (V2R7), built from the rule's check text
# (a US Government work). Each block cites the rule and vulnerability id and quotes one short phrase of the check text.
# Values are the strings the commands print.
#
# Hand-written: tools/stig_generators/gen_openshift_stig.py writes test_core_rules.rego, never this file.
package stig.openshift_4.golden_test

import rego.v1

# CNTR-OS-000400 (V-257540): "has a value of > 600"
# The finding clause names only a missing, commented-out or larger value: 0 passes (aligned 2026-11-21)
test_golden_cntr_os_000400_0_passes if {
	data.stig.openshift_4.core.status_cntr_os_000400 == "Not_a_Finding" with input as {
		"openshift": {"virtualization_enabled": false},
		"rhcos": {"nodes": [{"name": "worker-0", "sshd_config": {"PermitRootLogin": "no", "ClientAliveCountMax": "0", "ClientAliveInterval": "0"}}]},
	}
}

test_golden_cntr_os_000400_600_passes if {
	data.stig.openshift_4.core.status_cntr_os_000400 == "Not_a_Finding" with input as {
		"openshift": {"virtualization_enabled": false},
		"rhcos": {"nodes": [{"name": "worker-0", "sshd_config": {"PermitRootLogin": "no", "ClientAliveCountMax": "0", "ClientAliveInterval": "600"}}]},
	}
}

test_golden_cntr_os_000400_601_is_a_finding if {
	data.stig.openshift_4.core.status_cntr_os_000400 == "Open" with input as {
		"openshift": {"virtualization_enabled": false},
		"rhcos": {"nodes": [{"name": "worker-0", "sshd_config": {"PermitRootLogin": "no", "ClientAliveCountMax": "0", "ClientAliveInterval": "601"}}]},
	}
}

# A negative value is not a time sshd accepts: it stays a finding
test_golden_cntr_os_000400_negative_is_a_finding if {
	data.stig.openshift_4.core.status_cntr_os_000400 == "Open" with input as {
		"openshift": {"virtualization_enabled": false},
		"rhcos": {"nodes": [{"name": "worker-0", "sshd_config": {"PermitRootLogin": "no", "ClientAliveCountMax": "0", "ClientAliveInterval": "-1"}}]},
	}
}

# One node with ClientAliveInterval missing fails the cluster
test_golden_cntr_os_000400_missing_interval_is_a_finding if {
	data.stig.openshift_4.core.status_cntr_os_000400 == "Open" with input as {
		"openshift": {"virtualization_enabled": false},
		"rhcos": {"nodes": [
			{"name": "worker-0", "sshd_config": {"PermitRootLogin": "no", "ClientAliveCountMax": "0", "ClientAliveInterval": "0"}},
			{"name": "master-0", "sshd_config": {"PermitRootLogin": "no", "ClientAliveCountMax": "0"}},
		]},
	}
}
