package gcp.open_firewall

# Ingress firewall rules must not expose administrative ports (SSH, RDP) or
# all ports to the whole internet.
# Limitation: port ranges such as "20-30" are not expanded.

internet_ranges := {"0.0.0.0/0", "::/0"}

admin_ports := {"22", "3389"}

# GCP treats a rule without "direction" as INGRESS.
is_ingress(rule) if object.get(rule, "direction", "INGRESS") == "INGRESS"

exposes_admin_port(allow) if {
	some port in allow.ports
	port in admin_ports
}

# No "ports" attribute means every port for that protocol.
exposes_admin_port(allow) if not allow.ports

deny contains msg if {
	some name, rules in input.resource.google_compute_firewall
	some rule in rules
	is_ingress(rule)
	some range in rule.source_ranges
	range in internet_ranges
	some allow in rule.allow
	allow.protocol in {"tcp", "all"}
	exposes_admin_port(allow)
	msg := sprintf("google_compute_firewall.%s allows ingress from %s to an administrative or unrestricted port", [name, range])
}
