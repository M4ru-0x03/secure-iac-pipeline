package gcp.open_firewall

test_denies_ssh_from_internet if {
	msgs := deny with input as {"resource": {"google_compute_firewall": {"ssh": [{
		"direction": "INGRESS",
		"allow": [{"protocol": "tcp", "ports": ["22"]}],
		"source_ranges": ["0.0.0.0/0"],
	}]}}}
	count(msgs) == 1
}

test_denies_rdp_from_ipv6_internet if {
	msgs := deny with input as {"resource": {"google_compute_firewall": {"rdp": [{
		"direction": "INGRESS",
		"allow": [{"protocol": "tcp", "ports": ["3389"]}],
		"source_ranges": ["::/0"],
	}]}}}
	count(msgs) == 1
}

test_denies_all_ports_from_internet if {
	msgs := deny with input as {"resource": {"google_compute_firewall": {"any": [{
		"direction": "INGRESS",
		"allow": [{"protocol": "tcp"}],
		"source_ranges": ["0.0.0.0/0"],
	}]}}}
	count(msgs) == 1
}

test_denies_when_direction_is_omitted if {
	msgs := deny with input as {"resource": {"google_compute_firewall": {"ssh": [{
		"allow": [{"protocol": "tcp", "ports": ["22"]}],
		"source_ranges": ["0.0.0.0/0"],
	}]}}}
	count(msgs) == 1
}

test_allows_ssh_from_private_range if {
	msgs := deny with input as {"resource": {"google_compute_firewall": {"ssh": [{
		"direction": "INGRESS",
		"allow": [{"protocol": "tcp", "ports": ["22"]}],
		"source_ranges": ["10.0.0.0/8"],
	}]}}}
	count(msgs) == 0
}

test_allows_web_port_from_internet if {
	msgs := deny with input as {"resource": {"google_compute_firewall": {"web": [{
		"direction": "INGRESS",
		"allow": [{"protocol": "tcp", "ports": ["443"]}],
		"source_ranges": ["0.0.0.0/0"],
	}]}}}
	count(msgs) == 0
}

test_allows_egress_rule if {
	msgs := deny with input as {"resource": {"google_compute_firewall": {"out": [{
		"direction": "EGRESS",
		"allow": [{"protocol": "tcp", "ports": ["22"]}],
		"destination_ranges": ["0.0.0.0/0"],
	}]}}}
	count(msgs) == 0
}
