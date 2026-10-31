package gcp.open_firewall

# Ingress firewall rules must not expose administrative ports (SSH, RDP) or
# all ports to the whole internet. Port ranges such as "20-30" are expanded:
# a range is flagged when it contains an administrative port.
# Rules with disabled = true are ignored because they do not filter traffic.

internet_ranges := {"0.0.0.0/0", "::/0"}

admin_ports := {22, 3389}

# GCP treats a rule without "direction" as INGRESS.
is_ingress(rule) if object.get(rule, "direction", "INGRESS") == "INGRESS"

is_disabled(rule) if rule.disabled == true

# Ports are strings in HCL ("22", "20-30"), but an unquoted number is parsed as a number.
port_covers_admin(port) if {
	text := sprintf("%v", [port])
	not contains(text, "-")
	to_number(text) in admin_ports
}

port_covers_admin(port) if {
	text := sprintf("%v", [port])
	contains(text, "-")
	bounds := split(text, "-")
	some admin in admin_ports
	to_number(bounds[0]) <= admin
	admin <= to_number(bounds[1])
}

exposes_admin_port(allow) if {
	some port in allow.ports
	port_covers_admin(port)
}

# No "ports" attribute means every port for that protocol.
exposes_admin_port(allow) if not allow.ports

deny contains msg if {
	some name, rules in input.resource.google_compute_firewall
	some rule in rules
	is_ingress(rule)
	not is_disabled(rule)
	some range in rule.source_ranges
	range in internet_ranges
	some allow in rule.allow
	allow.protocol in {"tcp", "all"}
	exposes_admin_port(allow)
	msg := sprintf("google_compute_firewall.%s allows ingress from %s to an administrative or unrestricted port", [name, range])
}
