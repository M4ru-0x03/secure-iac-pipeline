package gcp.public_ip

test_denies_empty_access_config if {
	msgs := deny with input as {"resource": {"google_compute_instance": {"web": [{"network_interface": [{
		"subnetwork": "s",
		"access_config": [{}],
	}]}]}}}
	count(msgs) == 1
}

test_denies_access_config_with_static_ip if {
	msgs := deny with input as {"resource": {"google_compute_instance": {"web": [{"network_interface": [{
		"subnetwork": "s",
		"access_config": [{"nat_ip": "203.0.113.10"}],
	}]}]}}}
	count(msgs) == 1
}

test_denies_when_only_second_interface_is_public if {
	msgs := deny with input as {"resource": {"google_compute_instance": {"web": [{"network_interface": [
		{"subnetwork": "private"},
		{"subnetwork": "public", "access_config": [{}]},
	]}]}}}
	count(msgs) == 1
}

test_allows_instance_without_access_config if {
	msgs := deny with input as {"resource": {"google_compute_instance": {"web": [{"network_interface": [{"subnetwork": "s"}]}]}}}
	count(msgs) == 0
}

test_allows_input_without_instances if {
	msgs := deny with input as {"resource": {"google_compute_network": {"main": [{"name": "n"}]}}}
	count(msgs) == 0
}
