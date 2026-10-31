package gcp.bucket_cmek

test_denies_bucket_without_encryption_block if {
	msgs := deny with input as {"resource": {"google_storage_bucket": {"data": [{
		"name": "b",
		"location": "US",
	}]}}}
	count(msgs) == 1
}

test_denies_encryption_block_without_key if {
	msgs := deny with input as {"resource": {"google_storage_bucket": {"data": [{
		"name": "b",
		"encryption": [{}],
	}]}}}
	count(msgs) == 1
}

test_denies_empty_key_name if {
	msgs := deny with input as {"resource": {"google_storage_bucket": {"data": [{
		"name": "b",
		"encryption": [{"default_kms_key_name": ""}],
	}]}}}
	count(msgs) == 1
}

test_allows_bucket_with_kms_key if {
	msgs := deny with input as {"resource": {"google_storage_bucket": {"data": [{
		"name": "b",
		"encryption": [{"default_kms_key_name": "projects/p/locations/us/keyRings/r/cryptoKeys/k"}],
	}]}}}
	count(msgs) == 0
}

test_allows_key_given_as_reference if {
	msgs := deny with input as {"resource": {"google_storage_bucket": {"data": [{
		"name": "b",
		"encryption": [{"default_kms_key_name": "${google_kms_crypto_key.k.id}"}],
	}]}}}
	count(msgs) == 0
}

test_allows_input_without_buckets if {
	msgs := deny with input as {"resource": {"google_compute_network": {"main": [{"name": "n"}]}}}
	count(msgs) == 0
}
