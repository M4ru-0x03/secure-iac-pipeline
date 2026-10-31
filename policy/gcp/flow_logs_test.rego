package gcp.flow_logs

test_denies_subnet_without_log_config if {
	msgs := deny with input as {"resource": {"google_compute_subnetwork": {"main": [{
		"ip_cidr_range": "10.0.0.0/24",
		"region": "us-central1",
	}]}}}
	count(msgs) == 1
}

test_allows_subnet_with_log_config if {
	msgs := deny with input as {"resource": {"google_compute_subnetwork": {"main": [{
		"ip_cidr_range": "10.0.0.0/24",
		"region": "us-central1",
		"log_config": [{"aggregation_interval": "INTERVAL_5_SEC", "flow_sampling": 0.5}],
	}]}}}
	count(msgs) == 0
}

test_reports_each_subnet_without_log_config if {
	msgs := deny with input as {"resource": {"google_compute_subnetwork": {
		"a": [{"ip_cidr_range": "10.0.0.0/24"}],
		"b": [{"ip_cidr_range": "10.0.1.0/24"}],
	}}}
	count(msgs) == 2
}

test_allows_input_without_subnets if {
	msgs := deny with input as {"resource": {"google_compute_network": {"main": [{"name": "n"}]}}}
	count(msgs) == 0
}
