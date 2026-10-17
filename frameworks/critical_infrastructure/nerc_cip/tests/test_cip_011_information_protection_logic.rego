package nerc_cip.cip_011_test

import rego.v1

import data.nerc_cip.cip_011 as c

# Validation 2026-10-17.

now_rfc := time.format([time.now_ns(), "UTC", "2006-01-02T15:04:05Z07:00"])

test_recent_iso_review_passes if {
	c.bcsi_access_reviewed with input as {"bcsi_access_list": [{"last_review_date": now_rfc}]}
}

test_old_iso_review_fails if {
	not c.bcsi_access_reviewed with input as {"bcsi_access_list": [{"last_review_date": "2019-01-01T00:00:00Z"}]}
}

test_missing_review_date_fails if {
	not c.bcsi_access_reviewed with input as {"bcsi_access_list": [{"person_id": "p1"}]}
}

test_no_access_list_fails if {
	not c.bcsi_access_reviewed with input as {}
	not c.bcsi_access_need_to_know with input as {}
	not c.bcsi_access_reviewed with input as {"bcsi_access_list": []}
}

test_unflagged_unencrypted_transmission_fails if {
	t := {"destination": "vendor", "recipient_authorized": true, "transmission_logged": true}
	not c.bcsi_transmission_protected with input as {"bcsi_transmissions": [t]}
}

test_internal_transmission_not_checked if {
	t := {"outside_esp": false}
	c.bcsi_transmission_protected with input as {"bcsi_transmissions": [t]}
}

test_documented_encrypted_flag_accepted if {
	t := {"outside_esp": true, "encrypted": true, "recipient_authorized": true, "transmission_logged": true}
	c.bcsi_transmission_protected with input as {"bcsi_transmissions": [t]}
	t2 := {"outside_esp": true, "encryption_used": true, "recipient_authorized": true, "transmission_logged": true}
	c.bcsi_transmission_protected with input as {"bcsi_transmissions": [t2]}
}
