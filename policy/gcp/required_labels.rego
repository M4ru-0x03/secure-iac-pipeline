package gcp.required_labels

# Buckets and VMs must carry the organization's required labels with non-empty
# values. Labels written as an expression (labels = var.labels, merge(...)) are
# parsed as a string and cannot be read statically, so they produce a warning
# instead of a violation.

required_labels := {"owner", "environment"}

labelled_types := {"google_storage_bucket", "google_compute_instance"}

labels_unresolved(resource) if is_string(resource.labels)

has_label(resource, label) if resource.labels[label] != ""

missing_labels(resource) := {label |
	some label in required_labels
	not has_label(resource, label)
}

deny contains msg if {
	some type in labelled_types
	some name, instances in input.resource[type]
	some instance in instances
	not labels_unresolved(instance)
	missing := missing_labels(instance)
	count(missing) > 0
	msg := sprintf("%s.%s is missing required labels: %s", [type, name, concat(", ", sort(missing))])
}

warn contains msg if {
	some type in labelled_types
	some name, instances in input.resource[type]
	some instance in instances
	labels_unresolved(instance)
	msg := sprintf("%s.%s sets labels through an expression that cannot be checked statically; verify owner and environment manually", [type, name])
}
