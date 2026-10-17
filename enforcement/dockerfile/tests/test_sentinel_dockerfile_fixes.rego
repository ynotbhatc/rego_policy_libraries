package sentinel.dockerfile_fixes_test

import rego.v1

df := data.sentinel.dockerfile

has(vs, code) if {
	some v in vs
	startswith(v, code)
}

ins(cmd, value) := {"cmd": cmd, "value": value}

test_user_root_group_form_violates if has(df.violation_df_002, "SENTINEL-DF-002") with input as {"instructions": [ins("USER", "root:root")]}

test_user_zero_group_form_violates if has(df.violation_df_002, "SENTINEL-DF-002") with input as {"instructions": [ins("USER", "0:0")]}

test_user_nonroot_group_form_ok if count(df.violation_df_002) == 0 with input as {"instructions": [ins("USER", "app:app")]}

test_user_uid_group_ok if count(df.violation_df_002) == 0 with input as {"instructions": [ins("USER", "1001:1001")]}

test_apt_no_install_recommends_still_needs_pin if has(df.violation_df_005, "SENTINEL-DF-005") with input as {"instructions": [ins("RUN", "apt-get install -y --no-install-recommends nginx")]}

test_apt_pinned_ok if count(df.violation_df_005) == 0 with input as {"instructions": [ins("RUN", "apt-get install -y nginx=1.24.0")]}

test_expose_multiple_ports_privileged_violates if has(df.violation_df_010, "SENTINEL-DF-010") with input as {"instructions": [ins("EXPOSE", "8080 80")]}

test_expose_privileged_with_proto_in_later_token_violates if has(df.violation_df_010, "SENTINEL-DF-010") with input as {"instructions": [ins("EXPOSE", "8080/tcp 443/tcp")]}

test_expose_range_starting_privileged_violates if has(df.violation_df_010, "SENTINEL-DF-010") with input as {"instructions": [ins("EXPOSE", "80-90")]}

test_expose_unprivileged_ok if count(df.violation_df_010) == 0 with input as {"instructions": [ins("EXPOSE", "8080/tcp 8443")]}

test_expose_single_privileged_violates if has(df.violation_df_010, "SENTINEL-DF-010") with input as {"instructions": [ins("EXPOSE", "80")]}

test_result_defined_when_noncompliant if {
	r := df.result with input as {"instructions": [ins("USER", "root")]}
	r.compliant == false
	r.violation_count > 0
}

test_result_compliant_when_clean if {
	r := df.result with input as {"instructions": [
		ins("FROM", "registry.access.redhat.com/ubi9/ubi:9.4"),
		ins("USER", "1001"),
		ins("HEALTHCHECK", "CMD curl -f http://localhost:8080/ || exit 1"),
	]}
	r.compliant == true
}
