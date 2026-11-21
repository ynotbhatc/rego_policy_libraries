package cis_docker_numeric_guards_test

import rego.v1

# #300 type traps: a non-number must not pass r_7_7.
test_r_7_7_number_type_traps if {
	data.cis_docker.r_7_7 with input as {"docker": {"info": {"Swarm": {"Cluster": {"Spec": {"CAConfig": {"NodeCertExpiry": 86400000000000}}}}}}}
	not data.cis_docker.r_7_7 with input as {"docker": {"info": {"Swarm": {"Cluster": {"Spec": {"CAConfig": {"NodeCertExpiry": "1"}}}}}}}
	not data.cis_docker.r_7_7 with input as {"docker": {"info": {"Swarm": {"Cluster": {"Spec": {"CAConfig": {"NodeCertExpiry": null}}}}}}}
	not data.cis_docker.r_7_7 with input as {"docker": {"info": {"Swarm": {"Cluster": {"Spec": {"CAConfig": {"NodeCertExpiry": "not-a-number"}}}}}}}
}
