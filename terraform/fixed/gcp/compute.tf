# REMEDIATED version of terraform/vulnerable/gcp/compute.tf.

# FIX (default service account): a dedicated service account for the VM.
resource "google_service_account" "vm" {
  account_id   = "demo-vm"
  display_name = "Service account for demo-vm"
}

resource "google_compute_instance" "web" {
  #checkov:skip=CKV_GCP_38:CSEK needs raw key material, which is a secret and cannot be stored in the repo. The disk is encrypted with Google-managed keys; this demo VM is not a critical workload.
  name         = "demo-vm"
  machine_type = "e2-micro"
  zone         = "us-central1-a"

  # FIX (labels): required labels.
  labels = {
    owner       = "platform-team"
    environment = "dev"
  }

  # Project-wide SSH keys are blocked; access goes through IAP.
  metadata = {
    block-project-ssh-keys = "TRUE"
  }

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  # FIX (public IP): no access_config block, so no external address.
  network_interface {
    subnetwork = google_compute_subnetwork.main.id
  }

  service_account {
    email  = google_service_account.vm.email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
}
