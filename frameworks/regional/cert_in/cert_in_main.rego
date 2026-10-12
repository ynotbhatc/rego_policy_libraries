# CERT-In Directions of 28 April 2022 under section 70B(6) of the Information
# Technology Act, 2000 (No. 20(3)/2022-CERT-In) — information security
# practices, procedure, prevention, response and reporting of cyber incidents.
# In force since 27 June 2022 (60 days from issue).
#
# Source: cert-in.org.in, CERT-In_Directions_70B_28.04.2022.pdf.
#
# Who: every service provider, intermediary, data centre, body corporate and
# Government organisation in India (directions i–iv); data centre, VPS, cloud
# and VPN service providers additionally (direction v); virtual asset service
# providers, exchanges and custodian wallet providers additionally (vi).
#
# Shape: attestation from the entity's evidence, input.cert_in.*. The two
# sector flags MUST be declared true or false — an undeclared flag is a
# violation, because a cloud provider that forgets to say so would otherwise
# pass without the subscriber-registration duty. Every other fact must be
# boolean true. Annexure I's twenty incident types are individual checks:
# the entity's reporting procedure must name each one as reportable.
#
# Query: POST /v1/data/cert_in/main/compliance_report
#
# Input contract — input.cert_in.*
#   provides_datacentre_vps_cloud_or_vpn   bool (required)   direction (v)
#   is_virtual_asset_service_provider      bool (required)   direction (vi)
#   time_sync.*  (i)   incident_reporting.*  (ii) + Annexure I
#   coordination.*  (iii) + Annexure II   logging.*  (iv)
#   subscriber_registration.*  (v)   virtual_assets.*  (vi) + Annexure III

# METADATA
# title: "CERT-In Directions under s.70B(6) IT Act (28 April 2022)"
# custom:
#   class: compliance
#   framework: cert_in
#   source: cert-in
#   domains: [india]
#   coverage:
#     checks: 54
#     cited: 45
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     as_of: v2.3.1
package cert_in.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

default _in := {}

_in := input.cert_in

effective_date := "2022-06-27"

# ── Sector flags: declared or violation ──────────────────────────────────

_flags := {
	"provides_datacentre_vps_cloud_or_vpn": "direction (v) — whether the entity is a data centre, VPS, cloud or VPN service provider must be declared true or false",
	"is_virtual_asset_service_provider": "direction (vi) — whether the entity is a virtual asset service provider, exchange or custodian wallet provider must be declared true or false",
}

violations contains msg if {
	some key, text in _flags
	not _in[key] == true
	not _in[key] == false
	msg := sprintf("CERT-In %v (cert_in.%v undeclared)", [text, key])
}

_is_provider if _in.provides_datacentre_vps_cloud_or_vpn == true

_is_vasp if _in.is_virtual_asset_service_provider == true

# ── (i) Time synchronisation ─────────────────────────────────────────────

_time_checks := {
	"all_ict_clocks_synchronised": "CERT-In direction (i): not all ICT system clocks are synchronised to a standard time source",
	"source_is_nic_npl_or_traceable": "CERT-In direction (i): time source is not the NIC or NPL NTP server, or a server traceable to them (a multi-geography entity may use another standard source only if it does not deviate from NPL/NIC)",
}

violations contains msg if {
	some key, msg in _time_checks
	not _in.time_sync[key] == true
}

# ── (ii) Incident reporting within 6 hours; Annexure I incident types ────

_reporting_checks := {
	"reported_within_6_hours_of_noticing": "CERT-In direction (ii): reportable cyber incidents are not reported to CERT-In within 6 hours of being noticed or brought to notice",
	"reporting_channels_configured": "CERT-In direction (ii): the CERT-In reporting channels (incident@cert-in.org.in, 1800-11-4949, published formats) are not built into the incident procedure",
	"procedure_uses_certin_published_format": "CERT-In direction (ii): reports do not follow the methods and formats published on cert-in.org.in",
}

violations contains msg if {
	some key, msg in _reporting_checks
	not _in.incident_reporting[key] == true
}

annexure_i := {
	"i_targeted_scanning_probing": "Targeted scanning/probing of critical networks/systems",
	"ii_compromise_of_critical_systems": "Compromise of critical systems/information",
	"iii_unauthorised_access": "Unauthorised access of IT systems/data",
	"iv_website_defacement_or_intrusion": "Defacement of or intrusion into a website, unauthorised changes such as malicious code or external links",
	"v_malicious_code": "Malicious code attacks — virus/worm/Trojan/bots/spyware/ransomware/cryptominers",
	"vi_attacks_on_servers_and_network_devices": "Attacks on servers (database, mail, DNS) and network devices such as routers",
	"vii_identity_theft_spoofing_phishing": "Identity theft, spoofing and phishing attacks",
	"viii_dos_ddos": "Denial of Service and Distributed Denial of Service attacks",
	"ix_critical_infrastructure_scada_ot_wireless": "Attacks on critical infrastructure, SCADA and OT systems and wireless networks",
	"x_attacks_on_applications": "Attacks on applications such as e-Governance and e-Commerce",
	"xi_data_breach": "Data breach",
	"xii_data_leak": "Data leak",
	"xiii_iot": "Attacks on IoT devices and associated systems, networks, software, servers",
	"xiv_digital_payment_systems": "Attacks or incidents affecting digital payment systems",
	"xv_malicious_mobile_apps": "Attacks through malicious mobile apps",
	"xvi_fake_mobile_apps": "Fake mobile apps",
	"xvii_social_media_accounts": "Unauthorised access to social media accounts",
	"xviii_cloud_systems": "Attacks or malicious/suspicious activities affecting cloud computing systems/servers/software/applications",
	"xix_big_data_blockchain_virtual_assets_robotics_drones": "Attacks or malicious/suspicious activities affecting Big Data, blockchain, virtual assets and exchanges, custodian wallets, robotics, 3D/4D printing, additive manufacturing, drones",
	"xx_ai_ml_systems": "Attacks or malicious/suspicious activities affecting AI and ML systems/servers/software/applications",
}

violations contains msg if {
	some id, text in annexure_i
	not _in.incident_reporting.reportable_types[id] == true
	msg := sprintf("CERT-In Annexure I (%v): \"%v\" is not a reportable incident type in the entity's procedure", [id, text])
}

# ── (iii) Orders, information, Point of Contact (Annexure II) ────────────

_coordination_checks := {
	"acts_on_certin_orders_within_specified_timeframe": "CERT-In direction (iii): no process to take action, provide information (up to near real-time) or assist CERT-In within the timeframe its order specifies",
	"poc_designated": "CERT-In direction (iii): no Point of Contact designated to interface with CERT-In",
	"poc_registered_in_annexure_ii_format": "CERT-In direction (iii) / Annexure II: Point of Contact details (name, designation, organisation, address, email, mobile, phone, fax) not sent to info@cert-in.org.in in the prescribed format",
	"poc_kept_updated": "CERT-In direction (iii): Point of Contact information is not updated when it changes",
}

violations contains msg if {
	some key, msg in _coordination_checks
	not _in.coordination[key] == true
}

# ── (iv) Logging: all ICT systems, 180 days rolling, within India ────────

_logging_checks := {
	"logs_enabled_on_all_ict_systems": "CERT-In direction (iv): logs are not enabled on all ICT systems",
	"logs_retained_180_days_rolling": "CERT-In direction (iv): logs are not maintained securely for a rolling period of 180 days",
	"logs_stored_within_indian_jurisdiction": "CERT-In direction (iv): logs are not maintained within the Indian jurisdiction",
	"logs_provided_with_incident_reports_or_on_order": "CERT-In direction (iv): logs are not provided to CERT-In with incident reports or when ordered",
}

violations contains msg if {
	some key, msg in _logging_checks
	not _in.logging[key] == true
}

# ── (v) Data centre / VPS / cloud / VPN: subscriber registration ────────

_registration_fields := {
	"a_validated_subscriber_names": "validated names of subscribers/customers hiring the services",
	"b_period_of_hire_with_dates": "period of hire including dates",
	"c_ips_allotted_or_used": "IPs allotted to / being used by the members",
	"d_registration_email_ip_timestamp": "email address, IP address and time stamp used at registration/on-boarding",
	"e_purpose_for_hiring": "purpose for hiring services",
	"f_validated_address_and_contact": "validated address and contact numbers",
	"g_ownership_pattern": "ownership pattern of the subscribers/customers",
}

violations contains msg if {
	_is_provider
	some id, text in _registration_fields
	not _in.subscriber_registration.fields[id] == true
	msg := sprintf("CERT-In direction (v) (%v): subscriber registration does not capture %v", [id, text])
}

violations contains msg if {
	_is_provider
	not _in.subscriber_registration.retained_5_years_after_cancellation == true
	msg := "CERT-In direction (v): subscriber registration information is not retained for 5 years (or longer where law mandates) after cancellation or withdrawal of the registration"
}

# ── (vi) Virtual asset service providers: KYC and transaction records ───

_vasp_checks := {
	"kyc_per_annexure_iii_maintained": "CERT-In direction (vi) / Annexure III: KYC information is not obtained with the RBI KYC Directions 2016 / SEBI April 2020 / DoT S-KYC officially valid documents (or RBI CDD for business entities) and maintained",
	"kyc_and_transaction_records_retained_5_years": "CERT-In direction (vi): KYC information and financial transaction records are not retained for five years",
	"transactions_reconstructable": "CERT-In direction (vi): transaction records do not allow each transaction to be reconstructed — party identification with IP addresses, timestamps and time zones, transaction ID, public keys/addresses/accounts, nature and date, amount",
}

violations contains msg if {
	_is_vasp
	some key, msg in _vasp_checks
	not _in.virtual_assets[key] == true
}

# ── Report ───────────────────────────────────────────────────────────────

compliance_report := {
	"framework": "CERT-In Directions under section 70B(6) of the IT Act, 2000 (28 April 2022)",
	"standard": "No. 20(3)/2022-CERT-In — cyber incident practices, reporting and logging; effective 2022-06-27",
	"source": "cert-in.org.in — CERT-In_Directions_70B_28.04.2022.pdf",
	"effective_date": effective_date,
	"direction_v_applies": object.get(_in, "provides_datacentre_vps_cloud_or_vpn", "undeclared"),
	"direction_vi_applies": object.get(_in, "is_virtual_asset_service_provider", "undeclared"),
	"annexure_i_types": count(annexure_i),
	"annexure_i_covered": count([id | some id, _ in annexure_i; _in.incident_reporting.reportable_types[id] == true]),
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
#   coverage:
#     checks: 54
#     cited: 45
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     as_of: v2.3.0
