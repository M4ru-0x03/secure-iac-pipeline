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

test_denies_port_range_that_includes_ssh if {
	msgs := deny with input as {"resource": {"google_compute_firewall": {"range": [{
		"direction": "INGRESS",
		"allow": [{"protocol": "tcp", "ports": ["20-30"]}],
		"source_ranges": ["0.0.0.0/0"],
	}]}}}
	count(msgs) == 1
}

test_denies_port_range_that_includes_rdp if {
	msgs := deny with input as {"resource": {"google_compute_firewall": {"range": [{
		"direction": "INGRESS",
		"allow": [{"protocol": "tcp", "ports": ["3000-4000"]}],
		"source_ranges": ["0.0.0.0/0"],
	}]}}}
	count(msgs) == 1
}

test_denies_range_with_exact_admin_port_as_boundary if {
	msgs := deny with input as {"resource": {"google_compute_firewall": {"range": [{
		"direction": "INGRESS",
		"allow": [{"protocol": "tcp", "ports": ["22-22"]}],
		"source_ranges": ["0.0.0.0/0"],
	}]}}}
	count(msgs) == 1
}

test_allows_port_range_without_admin_ports if {
	msgs := deny with input as {"resource": {"google_compute_firewall": {"range": [{
		"direction": "INGRESS",
		"allow": [{"protocol": "tcp", "ports": ["8000-9000"]}],
		"source_ranges": ["0.0.0.0/0"],
	}]}}}
	count(msgs) == 0
}

test_denies_unquoted_numeric_port if {
	msgs := deny with input as {"resource": {"google_compute_firewall": {"ssh": [{
		"direction": "INGRESS",
		"allow": [{"protocol": "tcp", "ports": [22]}],
		"source_ranges": ["0.0.0.0/0"],
	}]}}}
	count(msgs) == 1
}

test_allows_disabled_rule if {
	msgs := deny with input as {"resource": {"google_compute_firewall": {"ssh": [{
		"direction": "INGRESS",
		"disabled": true,
		"allow": [{"protocol": "tcp", "ports": ["22"]}],
		"source_ranges": ["0.0.0.0/0"],
	}]}}}
	count(msgs) == 0
}

test_denies_rule_with_disabled_false if {
	msgs := deny with input as {"resource": {"google_compute_firewall": {"ssh": [{
		"direction": "INGRESS",
		"disabled": false,
		"allow": [{"protocol": "tcp", "ports": ["22"]}],
		"source_ranges": ["0.0.0.0/0"],
	}]}}}
	count(msgs) == 1
}
