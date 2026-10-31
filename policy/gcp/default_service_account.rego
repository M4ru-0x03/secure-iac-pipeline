package gcp.default_service_account

# VMs must not run as the default Compute Engine service account with the
# cloud-platform scope (full API access). Using that scope with a dedicated,
# least-privilege service account is allowed.
# When "email" is omitted, the provider uses the default service account.

default_sa_suffix := "-compute@developer.gserviceaccount.com"

full_access_scopes := {"cloud-platform", "https://www.googleapis.com/auth/cloud-platform"}

uses_default_sa(sa) if not sa.email

uses_default_sa(sa) if endswith(sa.email, default_sa_suffix)

deny contains msg if {
	some name, instances in input.resource.google_compute_instance
	some instance in instances
	some sa in instance.service_account
	uses_default_sa(sa)
	some scope in sa.scopes
	scope in full_access_scopes
	msg := sprintf("google_compute_instance.%s uses the default service account with the cloud-platform scope; use a dedicated service account", [name])
}
