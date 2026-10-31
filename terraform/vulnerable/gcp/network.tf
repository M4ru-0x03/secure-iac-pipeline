# INTENTIONALLY VULNERABLE: every flaw below is a test case for a policy.

resource "google_compute_network" "main" {
  name                    = "demo-network"
  auto_create_subnetworks = false
}

# FLAW (no logging): subnetwork has no log_config block, so VPC flow logs are off.
resource "google_compute_subnetwork" "main" {
  name          = "demo-subnet"
  ip_cidr_range = "10.0.0.0/24"
  region        = "us-central1"
  network       = google_compute_network.main.id
}

# FLAW (open firewall): SSH reachable from the whole internet.
resource "google_compute_firewall" "allow_ssh_from_anywhere" {
  name      = "allow-ssh-from-anywhere"
  network   = google_compute_network.main.name
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
}
