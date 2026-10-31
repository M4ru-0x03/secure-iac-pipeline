package gcp.required_labels

test_denies_bucket_without_labels if {
	msgs := deny with input as {"resource": {"google_storage_bucket": {"data": [{"name": "b"}]}}}
	count(msgs) == 1
}

test_denies_instance_missing_one_label if {
	msgs := deny with input as {"resource": {"google_compute_instance": {"web": [{"labels": {"owner": "team-a"}}]}}}
	count(msgs) == 1
}

test_denies_empty_label_value if {
	msgs := deny with input as {"resource": {"google_storage_bucket": {"data": [{"labels": {"owner": "", "environment": "dev"}}]}}}
	count(msgs) == 1
}

test_reports_each_resource_missing_labels if {
	msgs := deny with input as {"resource": {
		"google_storage_bucket": {"data": [{"name": "b"}]},
		"google_compute_instance": {"web": [{"name": "v"}]},
	}}
	count(msgs) == 2
}

test_allows_resource_with_all_labels if {
	msgs := deny with input as {"resource": {"google_storage_bucket": {"data": [{"labels": {"owner": "team-a", "environment": "dev"}}]}}}
	count(msgs) == 0
}

test_allows_extra_labels if {
	msgs := deny with input as {"resource": {"google_compute_instance": {"web": [{"labels": {"owner": "team-a", "environment": "dev", "cost_center": "42"}}]}}}
	count(msgs) == 0
}

test_ignores_resource_types_not_in_scope if {
	msgs := deny with input as {"resource": {"google_compute_network": {"main": [{"name": "n"}]}}}
	count(msgs) == 0
}

# Labels set through an expression cannot be read statically: warn, do not block.
test_warns_when_labels_come_from_a_variable if {
	input_doc := {"resource": {"google_storage_bucket": {"data": [{"labels": "${var.labels}"}]}}}
	denied := deny with input as input_doc
	warned := warn with input as input_doc
	count(denied) == 0
	count(warned) == 1
}

test_warns_when_labels_come_from_a_function_call if {
	input_doc := {"resource": {"google_compute_instance": {"web": [{"labels": "${merge(var.base_labels, {owner = \"team-a\"})}"}]}}}
	denied := deny with input as input_doc
	warned := warn with input as input_doc
	count(denied) == 0
	count(warned) == 1
}

test_no_warning_for_literal_labels if {
	input_doc := {"resource": {"google_storage_bucket": {"data": [{"labels": {"owner": "team-a", "environment": "dev"}}]}}}
	warned := warn with input as input_doc
	count(warned) == 0
}

test_missing_labels_still_denied_and_not_warned if {
	input_doc := {"resource": {"google_storage_bucket": {"data": [{"name": "b"}]}}}
	denied := deny with input as input_doc
	warned := warn with input as input_doc
	count(denied) == 1
	count(warned) == 0
}
