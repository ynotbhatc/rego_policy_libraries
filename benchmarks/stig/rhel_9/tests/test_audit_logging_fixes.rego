package stig.rhel_9.audit_logging_fixes_test

import rego.v1

mk(m) := {"auditd_config": {"log_dir_permissions": m}}

test_log_dir_0750_ok if data.stig.rhel_9.audit_logging.audit_log_dir_permissions_ok with input as mk("0750")

test_log_dir_750_ok if data.stig.rhel_9.audit_logging.audit_log_dir_permissions_ok with input as mk("750")

test_log_dir_stricter_0700_ok if data.stig.rhel_9.audit_logging.audit_log_dir_permissions_ok with input as mk("0700")

test_log_dir_stricter_0640_ok if data.stig.rhel_9.audit_logging.audit_log_dir_permissions_ok with input as mk("0640")

test_log_dir_0755_open if not data.stig.rhel_9.audit_logging.audit_log_dir_permissions_ok with input as mk("0755")

test_log_dir_unparsable_open if not data.stig.rhel_9.audit_logging.audit_log_dir_permissions_ok with input as mk("rwx")

test_log_dir_status_open_when_too_loose if data.stig.rhel_9.audit_logging.status_rhel_09_653020 == "Open" with input as mk("0777")

test_log_dir_status_nf_when_stricter if data.stig.rhel_9.audit_logging.status_rhel_09_653020 == "Not_a_Finding" with input as mk("0700")
