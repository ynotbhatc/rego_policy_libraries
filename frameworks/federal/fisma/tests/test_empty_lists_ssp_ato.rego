package fisma.empty_lists_test

import rego.v1

# Weekly audit 2026-11-23 follow-up: lists guarded by `count(x) >= 0` in fisma.ssp and fisma.ato.

_conn := {"source": "web", "destination": "db", "protocol": "tcp", "port": 5432, "security_controls_applied": true}

_net_ok(n) if {
	data.fisma.ssp.network_architecture_documented with input as {"ssp": {"environment": {"network": object.union(
		{"architecture_diagram_current": true, "network_topology_documented": true},
		n,
	)}}}
}

# NIST SP 800-53 Rev 5 PL-2a: describe "any dependencies on or connections to other systems or system components".
test_empty_network_connections_need_explicit_statement if {
	not _net_ok({"network_connections": []})
	not _net_ok({"network_connections": [], "has_network_connections": true})
	not _net_ok({"network_connections": [], "has_network_connections": "false"})
	_net_ok({"network_connections": [], "has_network_connections": false})
}

test_network_connections_must_be_an_array_and_consistent if {
	_net_ok({"network_connections": [_conn]})
	_net_ok({"network_connections": [object.union(_conn, {"port": "5432"})], "has_network_connections": true})
	not _net_ok({"network_connections": [_conn], "has_network_connections": false})
	not _net_ok({"has_network_connections": false})
	not _net_ok({"network_connections": null, "has_network_connections": false})
	not _net_ok({"network_connections": {}, "has_network_connections": false})
	not _net_ok({"network_connections": [object.union(_conn, {"source": 1})]})
	not _net_ok({"network_connections": [object.union(_conn, {"port": null})]})
	not _net_ok({"network_connections": [object.union(_conn, {"security_controls_applied": "true"})]})
}

_vuln_ok(v) if {
	data.fisma.ato.vulnerability_assessment_current with input as {"ato": {"risk_assessment": {"vulnerabilities": object.union(
		{
			"vulnerability_scan_current": true,
			"penetration_test_current": true,
			"configuration_review_current": true,
			"code_review_conducted": true,
		},
		v,
	)}}}
}

# NIST SP 800-53 Rev 5 RA-5: a current scan can find nothing, so an empty list is a result; anything that is not a
# list is not a scan result.
test_identified_vulnerabilities_must_be_an_array if {
	_vuln_ok({"identified_vulnerabilities": []})
	_vuln_ok({"identified_vulnerabilities": ["CVE-2026-0001"]})
	not _vuln_ok({})
	not _vuln_ok({"identified_vulnerabilities": null})
	not _vuln_ok({"identified_vulnerabilities": "none"})
	not _vuln_ok({"identified_vulnerabilities": {}})
}
