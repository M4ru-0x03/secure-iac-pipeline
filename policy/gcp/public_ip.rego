package gcp.public_ip

# Compute instances must not get an external IP address. A network_interface
# with an access_config block (even an empty one) is assigned one.

deny contains msg if {
	some name, instances in input.resource.google_compute_instance
	some instance in instances
	some interface in instance.network_interface
	count(interface.access_config) > 0
	msg := sprintf("google_compute_instance.%s has a network_interface with access_config, which assigns a public IP", [name])
}
