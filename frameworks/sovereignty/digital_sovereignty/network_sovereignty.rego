package digital_sovereignty.network_sovereignty

import rego.v1

# Digital Sovereignty — Network Sovereignty
# Ensures network traffic does not traverse foreign jurisdictions uncontrolled,
# DNS is under organisational control, and communication paths are known.
#
# Input schema:
#   input.approved_jurisdictions[]
#   input.network_segments[]
#     .segment_id, .segment_name
#     .location_country
#     .traffic_inspected                 — bool
#     .encrypted_in_transit              — bool
#     .routing_policy_documented         — bool
#   input.bgp_configuration
#     .autonomous_system_number_owned    — bool
#     .route_filtering_enabled           — bool
#     .rpki_deployed                     — bool (Resource Public Key Infrastructure)
#     .route_origin_validation           — bool
#     .peer_list_reviewed_date
#     .routes_documented                 — bool
#   input.dns_configuration
#     .resolver_location_country
#     .resolver_under_org_control        — bool
#     .dnssec_enabled                    — bool
#     .dns_over_https_or_tls             — bool
#     .public_dns_providers_blocked      — bool # prevents use of 8.8.8.8 etc.
#     .zone_transfers_controlled         — bool
#     .dns_logs_retained_days
#   input.internet_egress
#     .single_controlled_egress_point    — bool
#     .egress_country                    — country of egress point
#     .traffic_inspected_at_egress       — bool
#     .allowed_destinations_documented   — bool
#     .blocked_destinations_documented   — bool
#   input.traffic_routing
#     .sensitive_traffic_transits_foreign_country   — bool
#     .foreign_countries_transited[]
#     .traffic_routed_over_approved_paths — bool
#     .encrypted_if_transits_foreign     — bool
#   input.network_monitoring
#     .netflow_collection_enabled        — bool
#     .deep_packet_inspection.enabled    — bool
#     .anomaly_detection_enabled         — bool
#     .foreign_destination_alerting      — bool
#     .retention_days
#   input.submarine_cables                          # relevant for nation-state level
#     .transit_paths_documented          — bool
#     .avoid_hostile_jurisdiction_cables — bool
#   input.private_connectivity
#     .dedicated_links_for_sensitive.used — bool
#     .vpn_used_for_sensitive            — bool
#     .vpn_termination_country

# =============================================================================
# DNS SOVEREIGNTY
# =============================================================================

# DNS resolver must be under organisational control
dns_under_org_control if {
	input.dns_configuration.resolver_under_org_control == true
}

# DNS resolver must be in approved jurisdiction
dns_resolver_in_jurisdiction if {
	input.dns_configuration.resolver_location_country in input.approved_jurisdictions
}

# DNSSEC must be enabled
dnssec_enabled if {
	input.dns_configuration.dnssec_enabled == true
}

# DNS logs must be retained for security analysis
dns_logs_retained if {
	input.dns_configuration.dns_logs_retained_days >= 90
}

# Uncontrolled public DNS resolvers must be blocked
public_dns_blocked if {
	input.dns_configuration.public_dns_providers_blocked == true
}

# DNS zone transfers controlled
dns_zone_transfers_controlled if {
	input.dns_configuration.zone_transfers_controlled == true
}

# =============================================================================
# ROUTING SOVEREIGNTY
# =============================================================================

# BGP route origin validation must be deployed
rpki_deployed if {
	input.bgp_configuration.rpki_deployed == true
	input.bgp_configuration.route_origin_validation == true
}

# BGP route filtering must be enabled
bgp_route_filtering if {
	input.bgp_configuration.route_filtering_enabled == true
	input.bgp_configuration.routes_documented == true
}

# BGP peers must be reviewed
bgp_peers_reviewed if {
	last_review_ns := time.parse_rfc3339_ns(input.bgp_configuration.peer_list_reviewed_date)
	age_days := (time.now_ns() - last_review_ns) / (24 * 60 * 60 * 1000000000)
	age_days <= 180
}

# =============================================================================
# TRAFFIC ROUTING CONTROLS
# =============================================================================

# Sensitive traffic must not transit foreign countries unencrypted
sensitive_traffic_protected if {
	not input.traffic_routing.sensitive_traffic_transits_foreign_country
} else if {
	input.traffic_routing.sensitive_traffic_transits_foreign_country == true
	input.traffic_routing.encrypted_if_transits_foreign == true
}

# All traffic must route over documented approved paths
traffic_routed_over_approved_paths if {
	input.traffic_routing.traffic_routed_over_approved_paths == true
}

# =============================================================================
# INTERNET EGRESS
# =============================================================================

# All internet egress must pass through a controlled, inspected point
egress_controlled if {
	input.internet_egress.single_controlled_egress_point == true
	input.internet_egress.traffic_inspected_at_egress == true
}

# Egress point must be in approved jurisdiction
egress_in_jurisdiction if {
	input.internet_egress.egress_country in input.approved_jurisdictions
}

# Allowed/blocked destination policies must be documented
egress_policy_documented if {
	input.internet_egress.allowed_destinations_documented == true
	input.internet_egress.blocked_destinations_documented == true
}

# =============================================================================
# NETWORK MONITORING
# =============================================================================

# Network flow data must be collected and retained
netflow_monitoring if {
	input.network_monitoring.netflow_collection_enabled == true
	input.network_monitoring.retention_days >= 90
}

# Anomaly detection must be active
network_anomaly_detection if {
	input.network_monitoring.anomaly_detection_enabled == true
}

# Alert on connections to foreign/unapproved destinations
foreign_destination_alerting if {
	input.network_monitoring.foreign_destination_alerting == true
}

# =============================================================================
# PRIVATE CONNECTIVITY
# =============================================================================

# Sensitive inter-site traffic must use dedicated links or encrypted VPN
sensitive_traffic_private if {
	input.private_connectivity.dedicated_links_for_sensitive.used == true
} else if {
	input.private_connectivity.vpn_used_for_sensitive == true
	input.private_connectivity.vpn_termination_country in input.approved_jurisdictions
}

# =============================================================================
# NETWORK SEGMENT CONTROLS
# =============================================================================

# All network segments must have routing policies documented
network_segments_documented if {
	violations := [seg |
		seg := input.network_segments[_]
		not seg.routing_policy_documented == true
	]
	count(violations) == 0
}

# Segments handling regulated data must encrypt traffic
regulated_segments_encrypted if {
	violations := [seg |
		seg := input.network_segments[_]
		seg.handles_regulated_data == true
		not seg.encrypted_in_transit == true
	]
	count(violations) == 0
}

# All segments must be in approved jurisdictions
segments_in_approved_jurisdictions if {
	violations := [seg |
		seg := input.network_segments[_]
		seg.handles_regulated_data == true
		not seg.location_country in input.approved_jurisdictions
	]
	count(violations) == 0
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not dns_under_org_control
	v := {
		"domain": "network_sovereignty",
		"control": "NS-001",
		"severity": "high",
		"description": "DNS resolver not under organisational control — metadata exposed to third party",
		"remediation": "Deploy organisation-controlled DNS resolver within approved jurisdiction",
	}
}

violations contains v if {
	not dns_resolver_in_jurisdiction
	v := {
		"domain": "network_sovereignty",
		"control": "NS-002",
		"severity": "high",
		"description": concat("", ["DNS resolver located outside approved jurisdiction: ", input.dns_configuration.resolver_location_country]),
		"remediation": "Move DNS resolver to approved jurisdiction",
	}
}

violations contains v if {
	not dnssec_enabled
	v := {
		"domain": "network_sovereignty",
		"control": "NS-003",
		"severity": "medium",
		"description": "DNSSEC not enabled — DNS responses can be spoofed",
		"remediation": "Enable DNSSEC for all managed zones and validate signatures at resolver",
	}
}

violations contains v if {
	not public_dns_blocked
	v := {
		"domain": "network_sovereignty",
		"control": "NS-004",
		"severity": "medium",
		"description": "Public DNS resolvers (8.8.8.8, 1.1.1.1, etc.) not blocked — traffic metadata leaks",
		"remediation": "Block outbound DNS (UDP/TCP 53) to all but approved resolvers via firewall policy",
	}
}

violations contains v if {
	not rpki_deployed
	v := {
		"domain": "network_sovereignty",
		"control": "NS-005",
		"severity": "medium",
		"description": "RPKI/route origin validation not deployed — BGP hijacking risk",
		"remediation": "Deploy Resource Public Key Infrastructure (RPKI) with route origin validation",
	}
}

violations contains v if {
	not sensitive_traffic_protected
	v := {
		"domain": "network_sovereignty",
		"control": "NS-006",
		"severity": "critical",
		"description": "Sensitive traffic transits foreign country without encryption",
		"remediation": "Encrypt all sensitive traffic end-to-end or reroute to avoid foreign jurisdiction transit",
	}
}

violations contains v if {
	not egress_controlled
	v := {
		"domain": "network_sovereignty",
		"control": "NS-007",
		"severity": "high",
		"description": "Internet egress not routed through single controlled, inspected point",
		"remediation": "Consolidate egress through a single inspected gateway with DPI and logging",
	}
}

violations contains v if {
	not egress_in_jurisdiction
	v := {
		"domain": "network_sovereignty",
		"control": "NS-008",
		"severity": "high",
		"description": concat("", ["Internet egress point located outside approved jurisdiction: ", input.internet_egress.egress_country]),
		"remediation": "Move internet egress to a point physically located in approved jurisdiction",
	}
}

violations contains v if {
	not netflow_monitoring
	v := {
		"domain": "network_sovereignty",
		"control": "NS-009",
		"severity": "medium",
		"description": "Network flow data not collected or retention less than 90 days",
		"remediation": "Enable NetFlow/IPFIX collection with at least 90-day retention for forensic capability",
	}
}

violations contains v if {
	not foreign_destination_alerting
	v := {
		"domain": "network_sovereignty",
		"control": "NS-010",
		"severity": "medium",
		"description": "No alerting configured for connections to foreign/unapproved network destinations",
		"remediation": "Configure alerts for new outbound connections to non-approved countries or destinations",
	}
}

violations contains v if {
	not segments_in_approved_jurisdictions
	seg := input.network_segments[_]
	seg.handles_regulated_data == true
	not seg.location_country in input.approved_jurisdictions
	v := {
		"domain": "network_sovereignty",
		"control": "NS-011",
		"severity": "critical",
		"segment_id": seg.segment_id,
		"description": concat("", ["Network segment handling regulated data located outside approved jurisdiction: ", seg.segment_id, " in ", seg.location_country]),
		"remediation": "Move network segment to approved jurisdiction or reclassify data",
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	dns_under_org_control
	dns_resolver_in_jurisdiction
	dnssec_enabled
	dns_logs_retained
	public_dns_blocked
	dns_zone_transfers_controlled
	rpki_deployed
	bgp_route_filtering
	sensitive_traffic_protected
	traffic_routed_over_approved_paths
	egress_controlled
	egress_in_jurisdiction
	egress_policy_documented
	netflow_monitoring
	network_anomaly_detection
	foreign_destination_alerting
	sensitive_traffic_private
	network_segments_documented
	regulated_segments_encrypted
	segments_in_approved_jurisdictions
}

report := {
	"domain": "Network Sovereignty",
	"compliant": compliant,
	"controls": {
		"NS-001_dns_org_controlled": dns_under_org_control,
		"NS-002_dns_in_jurisdiction": dns_resolver_in_jurisdiction,
		"NS-003_dnssec_enabled": dnssec_enabled,
		"NS-004_public_dns_blocked": public_dns_blocked,
		"NS-005_rpki_deployed": rpki_deployed,
		"NS-006_sensitive_traffic_protected": sensitive_traffic_protected,
		"NS-007_egress_controlled": egress_controlled,
		"NS-008_egress_in_jurisdiction": egress_in_jurisdiction,
		"NS-009_netflow_monitoring": netflow_monitoring,
		"NS-010_foreign_destination_alerting": foreign_destination_alerting,
		"NS-011_segments_in_jurisdiction": segments_in_approved_jurisdictions,
	},
	"violations": violations,
	"violation_count": count(violations),
}
