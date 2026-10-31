# INTENTIONALLY VULNERABLE: every flaw below is a test case for a policy.

# FLAWS:
#  - public IP: the empty access_config block assigns an ephemeral external IP.
#  - over-broad identity: no service account email means the default compute
#    service account is used, with the cloud-platform scope (full API access).
#  - no labels.
resource "google_compute_instance" "web" {
  name         = "demo-vm"
  machine_type = "e2-micro"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.main.id

    access_config {}
  }

  service_account {
    scopes = ["cloud-platform"]
  }
}
