package gcp.flow_logs

# Every VPC subnetwork must enable flow logs through a log_config block.
# Limitation: the sampling and aggregation settings are not checked.

has_flow_logs(subnet) if count(subnet.log_config) > 0

deny contains msg if {
	some name, subnets in input.resource.google_compute_subnetwork
	some subnet in subnets
	not has_flow_logs(subnet)
	msg := sprintf("google_compute_subnetwork.%s has no log_config; VPC flow logs are disabled", [name])
}
