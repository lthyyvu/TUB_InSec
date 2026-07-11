### T-POT HOST (bare VM)
# A single internet-facing VM sized to run the full T-Pot platform
# (https://github.com/telekom-security/tpotce). This only provisions the box,
# creates a non-root user, and clones the tpotce repo - the T-Pot installer is
# run by hand afterwards from that user's shell. Distinct resource names from the
# local/ and cloud/ configs so nothing collides if they share a project.

### NETWORK

resource "google_compute_network" "tpot_vpc" {
  name = "tpot-vpc"
}

### FIREWALL

# Admin surface, restricted to the operator:
#   22    - initial install SSH (before T-Pot moves it)
#   64295 - real host SSH after the T-Pot installer relocates it
#   64294 - T-Pot web UI (nginx)
#   64297 - T-Pot web UI (https / Kibana)
resource "google_compute_firewall" "tpot_admin" {
  name    = "tpot-allow-admin"
  network = google_compute_network.tpot_vpc.id

  allow {
    protocol = "tcp"
    ports    = [ "64294", "64295", "64297"]
  }

  source_ranges = [var.admin_cidr]
  target_tags   = ["tpot-node"]
}

# Honeypot ports open to the whole internet - that's the point, T-Pot's sensors
# bind a wide range of low ports and we want real attacker traffic hitting them.
# Kept below the admin ports (64294+) so the two rules never overlap.
resource "google_compute_firewall" "tpot_honeypot" {
  name    = "tpot-allow-honeypot-traffic"
  network = google_compute_network.tpot_vpc.id

  allow {
    protocol = "tcp"
    ports    = ["1-64000"]
  }

  allow {
    protocol = "udp"
    ports    = ["1-64000"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["tpot-node"]
}

### INSTANCE
#
# Sizing for the STANDARD flavour: T-Pot runs ~20 honeypot containers plus a full
# Elasticsearch/Logstash/Kibana stack. Its docs recommend 8-16 GB RAM and a 128 GB+
# SSD; e2-standard-4 (4 vCPU / 16 GB) gives comfortable headroom. Disk capped at
# 249 GB (the max pd-ssd size available in this project/region).

resource "google_compute_instance" "tpot_vm" {
  name         = "tpot-vm"
  machine_type = "e2-standard-4"
  tags         = ["tpot-node"]

  boot_disk {
    initialize_params {
      size  = 249
      type  = "pd-ssd"
      image = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
    }
  }

  network_interface {
    network = google_compute_network.tpot_vpc.id

    access_config {
      # Ephemeral public IP - so we can SSH in to install T-Pot.
    }
  }

  metadata = {
    # GCP creates "labuser" (a non-root sudo user) from this key.
    ssh-keys = "labuser:${file(pathexpand("~/.ssh/lab_shared_key.pub"))}"

    # Clone the tpotce repo into the non-root user's home. Nothing else -
    # T-Pot's installer is run manually from ~/tpotce afterwards.
    startup-script = <<-EOF
      #!/bin/bash
      set -euxo pipefail

      # startup-script runs on every boot - skip if the repo is already there.
      if [ -d /home/labuser/tpotce ]; then
        echo "tpotce already cloned, skipping."
        exit 0
      fi

      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y git

      git clone https://github.com/telekom-security/tpotce /home/labuser/tpotce
      chown -R labuser:labuser /home/labuser/tpotce
    EOF
  }
}

### OUTPUTS

output "tpot_public_ip" {
  value       = google_compute_instance.tpot_vm.network_interface[0].access_config[0].nat_ip
  description = "Public IP of the T-Pot host. SSH in with: ssh labuser@<ip>, then run ~/tpotce/install.sh"
}
