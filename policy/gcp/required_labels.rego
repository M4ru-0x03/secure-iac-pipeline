package gcp.required_labels

# Buckets and VMs must carry the organization's required labels with non-empty
# values. Limitation: labels set through a variable or expression (for example
# "labels = var.labels") cannot be read statically and are reported as missing.

required_labels := {"owner", "environment"}

labelled_types := {"google_storage_bucket", "google_compute_instance"}

has_label(resource, label) if resource.labels[label] != ""

missing_labels(resource) := {label |
	some label in required_labels
	not has_label(resource, label)
}

deny contains msg if {
	some type in labelled_types
	some name, instances in input.resource[type]
	some instance in instances
	missing := missing_labels(instance)
	count(missing) > 0
	msg := sprintf("%s.%s is missing required labels: %s", [type, name, concat(", ", sort(missing))])
}
