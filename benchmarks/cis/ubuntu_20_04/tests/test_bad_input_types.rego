package cis_ubuntu_20_04.bad_input_types_test

# A yes/no fact passes only as the boolean true. Each path below was read with a bare `not input.<path>`,
# which is false for any string, number or null, so "false", "true", 0, 1 and null all read as true and
# the finding vanished. For every path and every such value the section must report at least one finding
# it does not report when the fact is true, and every finding it reports when the fact is false.
#
# Not covered here (the same change, but the rule reports only together with other facts, so an input
# holding the one fact shows nothing either way): aide.cron_configured, aide.database_exists, aide.systemd_timer_configured, chronyd.has_time_sources, chronyd.service_active, cron.crond_running, initial_setup.aide_cron_configured, initial_setup.gdm_banner_configured, initial_setup.gdm_screen_lock_enabled, initial_setup.gui_required, ip_forwarding.ipv4_compliant, ip_forwarding.ipv6_compliant, ipv6.disabled, rsyslog.remote_logging_configured, rsyslog.service_active, rsyslog.service_enabled, timesyncd.service_active, ungrouped_files.compliant, unowned_files.compliant, world_writable.compliant.

import rego.v1

bad_values := ["false", "true", "no", "yes", 0, 1, null]

nest(path, v) := {path[0]: v} if count(path) == 1

nest(path, v) := {path[0]: {path[1]: v}} if count(path) == 2

nest(path, v) := {path[0]: {path[1]: {path[2]: v}}} if count(path) == 3

apparmor_paths := [["apparmor", "installed"], ["apparmor", "utils_installed"], ["apparmor", "bootloader_enabled"], ["apparmor", "service_active"], ["apparmor", "service_enabled"]]

test_apparmor_wrong_type_is_not_true if {
	every path in apparmor_paths {
		as_true := {v | some v in data.cis_ubuntu_20_04.apparmor.violations with input as nest(path, true)}
		as_false := {v | some v in data.cis_ubuntu_20_04.apparmor.violations with input as nest(path, false)}
		count(as_false - as_true) > 0
		every bad in bad_values {
			got := {v | some v in data.cis_ubuntu_20_04.apparmor.violations with input as nest(path, bad)}
			count(got - as_true) > 0
			count(as_false - got) == 0
		}
	}
}

auditd_paths := [["packages", "auditd"], ["packages", "audit"]]

test_auditd_wrong_type_is_not_true if {
	every path in auditd_paths {
		as_true := {v | some v in data.cis_ubuntu_20_04.auditd.violations with input as nest(path, true)}
		as_false := {v | some v in data.cis_ubuntu_20_04.auditd.violations with input as nest(path, false)}
		count(as_false - as_true) > 0
		every bad in bad_values {
			got := {v | some v in data.cis_ubuntu_20_04.auditd.violations with input as nest(path, bad)}
			count(got - as_true) > 0
			count(as_false - got) == 0
		}
	}
}

boot_security_paths := [["aide", "installed"], ["grub", "password_configured"], ["grub", "sulogin_configured"], ["process_hardening", "aslr_enabled"], ["process_hardening", "ptrace_scope_restricted"], ["apparmor", "bootloader_enabled"]]

test_boot_security_wrong_type_is_not_true if {
	every path in boot_security_paths {
		as_true := {v | some v in data.cis_ubuntu_20_04.boot_security.violations with input as nest(path, true)}
		as_false := {v | some v in data.cis_ubuntu_20_04.boot_security.violations with input as nest(path, false)}
		count(as_false - as_true) > 0
		every bad in bad_values {
			got := {v | some v in data.cis_ubuntu_20_04.boot_security.violations with input as nest(path, bad)}
			count(got - as_true) > 0
			count(as_false - got) == 0
		}
	}
}

cron_paths := [["cron", "crond_enabled"], ["cron", "cron_allow_exists"], ["cron", "at_allow_exists"]]

test_cron_wrong_type_is_not_true if {
	every path in cron_paths {
		as_true := {v | some v in data.cis_ubuntu_20_04.cron.violations with input as nest(path, true)}
		as_false := {v | some v in data.cis_ubuntu_20_04.cron.violations with input as nest(path, false)}
		count(as_false - as_true) > 0
		every bad in bad_values {
			got := {v | some v in data.cis_ubuntu_20_04.cron.violations with input as nest(path, bad)}
			count(got - as_true) > 0
			count(as_false - got) == 0
		}
	}
}

file_permissions_paths := [["ssh_private_keys", "all_compliant"]]

test_file_permissions_wrong_type_is_not_true if {
	every path in file_permissions_paths {
		as_true := {v | some v in data.cis_ubuntu_20_04.file_permissions.violations with input as nest(path, true)}
		as_false := {v | some v in data.cis_ubuntu_20_04.file_permissions.violations with input as nest(path, false)}
		count(as_false - as_true) > 0
		every bad in bad_values {
			got := {v | some v in data.cis_ubuntu_20_04.file_permissions.violations with input as nest(path, bad)}
			count(got - as_true) > 0
			count(as_false - got) == 0
		}
	}
}

initial_setup_paths := [["initial_setup", "aide_installed"], ["initial_setup", "grub_password_configured"], ["initial_setup", "grub_owner_root"], ["initial_setup", "aslr_enabled"], ["initial_setup", "ptrace_scope_restricted"], ["initial_setup", "motd_exists"], ["initial_setup", "issue_exists"], ["initial_setup", "issue_net_exists"]]

test_initial_setup_wrong_type_is_not_true if {
	every path in initial_setup_paths {
		as_true := {v | some v in data.cis_ubuntu_20_04.initial_setup.violations with input as nest(path, true)}
		as_false := {v | some v in data.cis_ubuntu_20_04.initial_setup.violations with input as nest(path, false)}
		count(as_false - as_true) > 0
		every bad in bad_values {
			got := {v | some v in data.cis_ubuntu_20_04.initial_setup.violations with input as nest(path, bad)}
			count(got - as_true) > 0
			count(as_false - got) == 0
		}
	}
}

logging_paths := [["rsyslog", "installed"], ["journald", "service_active"], ["logrotate", "installed"]]

test_logging_wrong_type_is_not_true if {
	every path in logging_paths {
		as_true := {v | some v in data.cis_ubuntu_20_04.logging.violations with input as nest(path, true)}
		as_false := {v | some v in data.cis_ubuntu_20_04.logging.violations with input as nest(path, false)}
		count(as_false - as_true) > 0
		every bad in bad_values {
			got := {v | some v in data.cis_ubuntu_20_04.logging.violations with input as nest(path, bad)}
			count(got - as_true) > 0
			count(as_false - got) == 0
		}
	}
}

network_paths := [["wireless_interfaces", "compliant"], ["firewall", "active"]]

test_network_wrong_type_is_not_true if {
	every path in network_paths {
		as_true := {v | some v in data.cis_ubuntu_20_04.network.violations with input as nest(path, true)}
		as_false := {v | some v in data.cis_ubuntu_20_04.network.violations with input as nest(path, false)}
		count(as_false - as_true) > 0
		every bad in bad_values {
			got := {v | some v in data.cis_ubuntu_20_04.network.violations with input as nest(path, bad)}
			count(got - as_true) > 0
			count(as_false - got) == 0
		}
	}
}

pam_paths := [["pam", "faillock_configured"], ["pam", "remember_configured"], ["pam", "tmout_configured"]]

test_pam_wrong_type_is_not_true if {
	every path in pam_paths {
		as_true := {v | some v in data.cis_ubuntu_20_04.pam.violations with input as nest(path, true)}
		as_false := {v | some v in data.cis_ubuntu_20_04.pam.violations with input as nest(path, false)}
		count(as_false - as_true) > 0
		every bad in bad_values {
			got := {v | some v in data.cis_ubuntu_20_04.pam.violations with input as nest(path, bad)}
			count(got - as_true) > 0
			count(as_false - got) == 0
		}
	}
}

services_paths := [["time_synchronization", "has_active_service"], ["time_synchronization", "compliant"]]

test_services_wrong_type_is_not_true if {
	every path in services_paths {
		as_true := {v | some v in data.cis_ubuntu_20_04.services.violations with input as nest(path, true)}
		as_false := {v | some v in data.cis_ubuntu_20_04.services.violations with input as nest(path, false)}
		count(as_false - as_true) > 0
		every bad in bad_values {
			got := {v | some v in data.cis_ubuntu_20_04.services.violations with input as nest(path, bad)}
			count(got - as_true) > 0
			count(as_false - got) == 0
		}
	}
}

sudo_paths := [["sudo", "installed"], ["sudo", "use_pty"], ["sudo", "logfile_configured"], ["sudo", "su_restricted"]]

test_sudo_wrong_type_is_not_true if {
	every path in sudo_paths {
		as_true := {v | some v in data.cis_ubuntu_20_04.sudo.violations with input as nest(path, true)}
		as_false := {v | some v in data.cis_ubuntu_20_04.sudo.violations with input as nest(path, false)}
		count(as_false - as_true) > 0
		every bad in bad_values {
			got := {v | some v in data.cis_ubuntu_20_04.sudo.violations with input as nest(path, bad)}
			count(got - as_true) > 0
			count(as_false - got) == 0
		}
	}
}
