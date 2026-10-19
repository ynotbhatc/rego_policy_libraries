package cis_ubuntu_22_04.logging_test

import rego.v1

# Validation fix 2026-10-17: string compare of FileCreateMode ("640" flagged, absent passed) and
# absent journald / log-permission evidence passed.

pkg := data.cis_ubuntu_22_04.logging

good := {
	"rsyslog": {"installed": true, "service_active": true, "service_enabled": true, "file_create_mode": "0640", "logging_rules_count": 6},
	"journald": {"service_active": true, "compress_enabled": "yes", "forward_to_syslog": "yes", "storage_mode": "persistent"},
	"logrotate": {"installed": true},
	"log_file_permissions": {"analysis": []},
	"excessive_permissions": {"files": []},
}

with_rsyslog(r) := object.union(object.remove(good, ["rsyslog"]), {"rsyslog": r})

test_good_compliant if {
	pkg.compliant with input as good
}

test_mode_without_leading_zero_ok if {
	pkg.compliant with input as with_rsyslog(object.union(good.rsyslog, {"file_create_mode": "640"}))
}

test_mode_0600_ok if {
	pkg.compliant with input as with_rsyslog(object.union(good.rsyslog, {"file_create_mode": "0600"}))
}

test_mode_0644_violates if {
	not pkg.compliant with input as with_rsyslog(object.union(good.rsyslog, {"file_create_mode": "0644"}))
}

test_mode_absent_violates if {
	not pkg.compliant with input as with_rsyslog(object.remove(good.rsyslog, ["file_create_mode"]))
}

test_rules_count_absent_violates if {
	not pkg.compliant with input as with_rsyslog(object.remove(good.rsyslog, ["logging_rules_count"]))
}

test_journald_fields_absent_violate if {
	j := {"service_active": true}
	v := pkg.journald_violations with input as object.union(object.remove(good, ["journald"]), {"journald": j})
	count(v) == 3
}

test_log_permission_sections_absent_violate if {
	v := pkg.log_file_violations with input as object.remove(object.remove(good, ["log_file_permissions"]), ["excessive_permissions"])
	count(v) == 2
}

# Decisions 2026-10-19: logrotate has its own count, not counted under rsyslog.
test_logrotate_missing_counted_in_own_section if {
	i := object.union(object.remove(good, ["logrotate"]), {"logrotate": {"installed": false}})
	r := pkg.report with input as i
	r.rsyslog_violations == 0
	r.logrotate_violations == 1
	r.total_violations == 1
	not pkg.compliant with input as i
}
