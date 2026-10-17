package cis.apache_2_4_test

import rego.v1

p := data.cis.apache_2_4

test_absolute_allowed_home_passes if {
	p.apache_user_home_non_privileged with input as {"apache": {"system": {"apache_user": {"home_directory": "/var/www"}}}}
}

test_root_home_fails if {
	not p.apache_user_home_non_privileged with input as {"apache": {"system": {"apache_user": {"home_directory": "/root/apache"}}}}
}

perms(mode) := {"apache": {"file_permissions": {
	"server_root": {"mode": mode},
	"config_files": {"mode": "640"},
	"document_root": {"mode": mode},
}}}

test_other_write_bit_detected_without_digit_2 if {
	not p.other_write_access_restricted with input as perms("0646")
	not p.other_write_access_restricted with input as perms("0777")
}

test_no_other_write_ok if {
	p.other_write_access_restricted with input as perms("0750")
	p.other_write_access_restricted with input as perms("0755")
}

test_group_write_detected_without_digit_2 if {
	not p.apache_group_write_restricted with input as perms("0777")
	not p.apache_group_write_restricted with input as perms("0770")
	not p.docroot_group_write_properly_restricted with input as perms("0770")
	not p.group_write_access_restricted with input as perms("0775")
	not p.docroot_group_write_restricted with input as perms("0775")
}

test_group_write_absent_ok if {
	p.apache_group_write_restricted with input as perms("0755")
	p.docroot_group_write_properly_restricted with input as perms("0750")
	p.group_write_access_restricted with input as perms("755")
	p.docroot_group_write_restricted with input as perms("0750")
}

ssl(proto) := {"apache": {"config": {"ssl": {"protocol": proto}}}}

test_tls12_and_13_not_flagged_as_tlsv1 if {
	p.insecure_protocols_disabled with input as ssl("-all +TLSv1.2 +TLSv1.3")
	p.insecure_protocols_disabled with input as ssl("TLSv1.2 TLSv1.3")
}

test_real_insecure_protocols_flagged if {
	not p.insecure_protocols_disabled with input as ssl("-all +TLSv1 +TLSv1.2")
	not p.insecure_protocols_disabled with input as ssl("+TLSv1.1 +TLSv1.2")
	not p.insecure_protocols_disabled with input as ssl("all")
	not p.insecure_protocols_disabled with input as ssl("+SSLv3")
}

test_all_with_removals_ok if {
	p.insecure_protocols_disabled with input as ssl("all -SSLv3 -TLSv1 -TLSv1.1")
}

dirs(d) := {"apache": {"config": {"directory_access": d}}}

test_string_options_are_evaluated if {
	not p.directory_browsing_restricted with input as dirs({"/var/www": {"options": "Indexes"}})
	not p.directory_browsing_restricted with input as dirs({"/var/www": {"options": "FollowSymLinks +Indexes"}})
	not p.ssi_disabled with input as dirs({"/var/www": {"options": "Includes"}})
	not p.cgi_execution_disabled with input as dirs({"/var/www": {"options": "ExecCGI"}})
	not p.follow_symlinks_disabled with input as dirs({"/var/www": {"options": "FollowSymLinks"}})
}

test_array_options_still_evaluated if {
	not p.directory_browsing_restricted with input as dirs({"/var/www": {"options": ["Indexes"]}})
	p.directory_browsing_restricted with input as dirs({"/var/www": {"options": ["FollowSymLinks"]}})
}

test_options_all_enables_everything if {
	not p.directory_browsing_restricted with input as dirs({"/var/www": {"options": "All"}})
}

test_removed_option_not_counted if {
	p.directory_browsing_restricted with input as dirs({"/var/www": {"options": "-Indexes"}})
}

test_options_files_restricted_requires_every_directory if {
	not p.options_files_restricted with input as dirs({"/": {"options": "None"}, "/var/www": {"options": "Indexes FollowSymLinks ExecCGI"}})
	p.options_files_restricted with input as dirs({"/": {"options": "None"}, "/var/www": {"options": "MultiViews"}})
	p.options_files_restricted with input as dirs({"/": {"options": "None"}})
}

test_debian_service_account_accepted if {
	p.apache_runs_non_root with input as {"apache": {"config": {"user": "www-data", "group": "www-data"}}}
	p.apache_non_privileged_user with input as {"apache": {"process": {"user": "www-data", "group": "www-data"}}}
	not p.apache_runs_non_root with input as {"apache": {"config": {"user": "root", "group": "root"}}}
	not p.apache_runs_non_root with input as {"apache": {"config": {"user": "daemon", "group": "daemon"}}}
}

test_custom_index_html_not_flagged_as_default if {
	p.default_html_removed with input as {"apache": {"content": {"html_files": [{"name": "index.html", "is_default": false}]}}}
	not p.default_html_removed with input as {"apache": {"content": {"html_files": [{"name": "index.html"}]}}}
	not p.default_html_removed with input as {"apache": {"content": {"html_files": [{"name": "welcome.html", "is_default": true}]}}}
}
