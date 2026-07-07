### PUBLIC CLOUD HONEYPOT
# Standalone internet-facing honeypot (distinct resource names from local.tf's
# private lab so both files can coexist in this directory without collisions).

### NETWORK

resource "google_compute_network" "public_honeypot_vpc" {
  name                    = "public-honeypot-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "public_honeypot_subnet" {
  name          = "public-honeypot-subnet"
  ip_cidr_range = "10.10.0.0/24"
  region        = var.region
  network       = google_compute_network.public_honeypot_vpc.id
}

### FIREWALL

# Honeypot ports open to the whole internet - that's the point, we want real attacker traffic.
resource "google_compute_firewall" "allow_public_honeypot_traffic" {
  name    = "allow-public-honeypot-traffic"
  network = google_compute_network.public_honeypot_vpc.id

  allow {
    protocol = "tcp"
    ports    = ["22", "23", "80"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["public-honeypot-node"]
}

# Real admin SSH (moved to 22222 by the startup script) stays restricted to the operator.
resource "google_compute_firewall" "allow_public_honeypot_admin" {
  name    = "allow-public-honeypot-admin-ssh"
  network = google_compute_network.public_honeypot_vpc.id

  allow {
    protocol = "tcp"
    ports    = ["22222"]
  }

  source_ranges = [var.admin_cidr]
  target_tags   = ["public-honeypot-node"]
}

### INSTANCE

resource "google_compute_instance" "public_honeypot_vm" {
  name         = "public-honeypot-vm"
  machine_type = "e2-small"
  tags         = ["public-honeypot-node"]

  boot_disk {
    initialize_params {
      size  = 100
      image = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
    }
  }

  network_interface {
    network    = google_compute_network.public_honeypot_vpc.id
    subnetwork = google_compute_subnetwork.public_honeypot_subnet.id

    access_config {
      # Ephemeral public IP - this is what makes the honeypot reachable from the internet.
    }
  }

  metadata = {
    ssh-keys = "labuser:${file(pathexpand("~/.ssh/lab_shared_key.pub"))}"

    startup-script = <<-EOF
      #!/bin/bash
      # 1. System updaten und Docker & Python installieren
      apt-get update
      apt-get install -y docker.io docker-compose-v2 python3

      # 2. Echten SSH-Dienst auf Port 22222 verschieben
      # Ubuntu 24.04 nutzt ssh.socket zur Socket-Aktivierung - das Unit haelt Port 22 auch dann
      # noch besetzt, wenn nur ssh.service neu gestartet wird, also muss es explizit deaktiviert werden.
      echo "Port 22222" > /etc/ssh/sshd_config.d/adminport.conf
      systemctl disable --now ssh.socket
      systemctl enable --now ssh.service

      # 3. Cowrie Honeypot über Docker einrichten
      # var/ is bind-mounted so session logs, JSON logs, and files attackers try to download survive a
      # container restart and can be pulled off the VM directly, instead of living only in the container layer.
      mkdir -p /opt/cowrie/var
      chown -R 1000:1000 /opt/cowrie/var
      cat << 'DOCKER' > /opt/cowrie/docker-compose.yml
      version: '3.7'
      services:
        cowrie:
          image: cowrie/cowrie:latest
          container_name: cowrie
          restart: always
          ports:
            - "22:2222"
            - "23:2223"
          environment:
            - COWRIE_TELNET_ENABLED=yes
          volumes:
            - ./var:/cowrie/cowrie-git/var
      DOCKER
      cd /opt/cowrie && docker compose up -d

      # 4. Custom Python HTTP Honeypot erstellen
      mkdir -p /opt/custom_web
      cat << 'PY' > /opt/custom_web/server.py
      import http.server
      import socketserver
      import datetime

      PORT = 80
      LOG_FILE = "/var/log/custom_honeypot.log"

      # Small set of real-looking paths - everything else 404s, so directory brute-forcers get a real signal
      # instead of every path looking "found" (which trips gobuster's wildcard-response detector).
      VALID_PATHS = {"/", "/admin", "/login", "/config"}

      class HoneypotHandler(http.server.SimpleHTTPRequestHandler):
          def log_message(self, format, *args):
              with open(LOG_FILE, "a") as f:
                  timestamp = datetime.datetime.now().isoformat()
                  f.write(f"[{timestamp}] IP: {self.client_address[0]} | REQUEST: {format%args}\n")

          def do_GET(self):
              self.log_message("GET %s", self.path)
              if self.path.split("?")[0] not in VALID_PATHS:
                  self.send_response(404)
                  self.send_header("Content-type", "text/html")
                  self.end_headers()
                  self.wfile.write(b"<html><body><h1>404 Not Found</h1></body></html>")
                  return
              self.send_response(200)
              self.send_header("Content-type", "text/html")
              self.end_headers()
              self.wfile.write(b"<html><body><h1>Admin Portal v1.0</h1><form method='POST'><input name='user'/><input name='pass' type='password'/><input type='submit'/></form></body></html>")

          def do_POST(self):
              content_length = int(self.headers['Content-Length'])
              post_data = self.rfile.read(content_length).decode('utf-8', 'ignore')
              self.log_message("POST %s | PAYLOAD: %s", self.path, post_data)
              # Weak bait credential - deliberately "succeeds" so brute-force/injection attempts have something to find.
              if "user=admin&pass=admin123" in post_data:
                  self.send_response(200)
                  self.send_header("Content-type", "text/html")
                  self.end_headers()
                  self.wfile.write(b"<html><body><h1>Welcome, admin!</h1></body></html>")
                  return
              self.send_response(401)
              self.send_header("Content-type", "text/html")
              self.end_headers()
              self.wfile.write(b"<html><body><h1>Error: Invalid Credentials</h1></body></html>")

      with socketserver.TCPServer(("", PORT), HoneypotHandler) as httpd:
          httpd.serve_forever()
      PY

      # Python-Skript als Systemdienst einrichten und starten
      cat << 'SYS' > /etc/systemd/system/custom-honeypot.service
      [Unit]
      Description=Custom Python Low-Interaction HTTP Honeypot
      After=network.target

      [Service]
      ExecStart=/usr/bin/python3 /opt/custom_web/server.py
      Restart=always
      User=root

      [Install]
      WantedBy=multi-user.target
      SYS

      systemctl daemon-reload
      systemctl enable --now custom-honeypot.service
    EOF
  }
}

### OUTPUTS

output "public_honeypot_ip" {
  value       = google_compute_instance.public_honeypot_vm.network_interface[0].access_config[0].nat_ip
  description = "Public IP of the internet-facing honeypot"
}
