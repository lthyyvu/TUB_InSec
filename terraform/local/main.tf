### NETWORK

resource "google_compute_network" "honeypot_vpc" {
  name                    = "honeypot-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "lab_subnet" {
  name          = "lab-subnet"
  ip_cidr_range = "10.0.0.0/24"
  region        = var.region
  network       = google_compute_network.honeypot_vpc.id
}

### NAT (lets the honeypot download Docker/Cowrie; no inbound public IP)

resource "google_compute_router" "honeypot_router" {
  name    = "honeypot-router"
  network = google_compute_network.honeypot_vpc.id
  region  = var.region
}

resource "google_compute_router_nat" "honeypot_nat" {
  name                               = "honeypot-nat"
  router                             = google_compute_router.honeypot_router.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

### FIREWALL

# Rule 1: Allow you to SSH into the Attacker VM (Mit deiner IP)
resource "google_compute_firewall" "lab_firewall" {
  name    = "allow-management-ssh"
  network = google_compute_network.honeypot_vpc.id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"] 
  target_tags   = ["attacker-vm"]
}

# Rule 2: Allow the Attacker VM to hit the Honeypot VM (Inklusive Port 22222 für Management)
resource "google_compute_firewall" "allow_lab_traffic" {
  name    = "allow-lab-traffic"
  network = google_compute_network.honeypot_vpc.id

  allow {
    protocol = "tcp"
    ports    = ["22", "23", "80", "22222"] 
  }

  source_ranges = ["10.0.0.2/32"] 
  target_tags   = ["honeypot-node"] 
}

### INSTANCES 

# The Victim (No Public IP + Automatisches Honeypot-Setup)
resource "google_compute_instance" "honeypot_vm" {
  name         = "honeypot-vm"
  machine_type = "e2-small"
  tags         = ["honeypot-node"] 

  boot_disk {
    initialize_params {
      size  = 100
      image = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
    }
  }

  network_interface {
    network    = google_compute_network.honeypot_vpc.id
    subnetwork = google_compute_subnetwork.lab_subnet.id
    network_ip = "10.0.0.3" 
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

# The Attacker (Has Public IP + Pentest-Tooling zum Angreifen des Honeypots)
resource "google_compute_instance" "attacker_vm" {
  name         = "attacker-vm"
  machine_type = "e2-small"
  tags         = ["attacker-vm"]

  boot_disk {
    initialize_params {
      size  = 100
      image = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
    }
  }

  network_interface {
    network    = google_compute_network.honeypot_vpc.id
    subnetwork = google_compute_subnetwork.lab_subnet.id
    network_ip = "10.0.0.2"

    access_config {
      # Ephemeral Public IP
    }
  }

  metadata = {
    ssh-keys = "labuser:${file(pathexpand("~/.ssh/lab_shared_key.pub"))}"

    startup-script = <<-EOF
      #!/bin/bash
      # Pentest-Tools installieren: Recon/Scanning, Brute-Force (gegen Cowrie SSH/Telnet), Web (gegen den Fake-Admin-Login)
      apt-get update
      apt-get install -y \
        nmap \
        netcat-openbsd \
        hydra \
        medusa \
        nikto \
        gobuster \
        sqlmap \
        curl
    EOF
  }
}

### ATTACK RUN (SSHes into the attacker VM, fires the pentest tools at the honeypot, pulls the results back to this machine)

resource "null_resource" "run_attack" {
  depends_on = [google_compute_instance.attacker_vm, google_compute_instance.honeypot_vm]

  # Re-run on every apply.
  triggers = {
    always_run = timestamp()
  }

  connection {
    type        = "ssh"
    host        = google_compute_instance.attacker_vm.network_interface[0].access_config[0].nat_ip
    user        = "labuser"
    private_key = file(pathexpand("~/.ssh/lab_shared_key"))
  }

  provisioner "remote-exec" {
    inline = [
      "rm -rf /tmp/attack-results && mkdir -p /tmp/attack-results",
      # attacker_vm's own startup-script apt-get installs the tools asynchronously too - SSH comes up long
      # before that finishes, so wait until every tool binary actually exists before using any of them.
      "for i in $(seq 1 60); do command -v nmap >/dev/null 2>&1 && command -v hydra >/dev/null 2>&1 && command -v medusa >/dev/null 2>&1 && command -v nikto >/dev/null 2>&1 && command -v gobuster >/dev/null 2>&1 && command -v sqlmap >/dev/null 2>&1 && break; sleep 5; done",
      # honeypot_vm's startup-script installs Docker/Cowrie asynchronously, so wait for its ports to actually answer.
      "for i in $(seq 1 60); do nc -z -w2 10.0.0.3 22 && nc -z -w2 10.0.0.3 80 && break; sleep 5; done",
      # Small self-contained wordlists (Cowrie's default userdb accepts almost any password, so this is enough).
      "printf 'root\\nadmin\\ntoor\\npassword\\n123456\\nadmin123\\n' > /tmp/attack-results/creds.txt",
      "printf 'admin\\nlogin\\nadmin.php\\nconfig\\nbackup\\n.git\\nuploads\\n' > /tmp/attack-results/paths.txt",
      "nmap -sV -p22,23,80,22222 10.0.0.3 -oN /tmp/attack-results/nmap.txt || true",
      "hydra -L /tmp/attack-results/creds.txt -P /tmp/attack-results/creds.txt -t 4 -o /tmp/attack-results/hydra_ssh.txt 10.0.0.3 ssh || true",
      "medusa -h 10.0.0.3 -U /tmp/attack-results/creds.txt -P /tmp/attack-results/creds.txt -M telnet -O /tmp/attack-results/medusa_telnet.txt || true",
      # Web-form brute-force - the honeypot's fake admin login accepts one weak bait credential, so this should hit.
      "hydra -L /tmp/attack-results/creds.txt -P /tmp/attack-results/creds.txt -t 4 -o /tmp/attack-results/hydra_web.txt 10.0.0.3 http-post-form '/:user=^USER^&pass=^PASS^:F=Invalid Credentials' || true",
      "nikto -h http://10.0.0.3 -o /tmp/attack-results/nikto.txt || true",
      "gobuster dir -u http://10.0.0.3 -w /tmp/attack-results/paths.txt -o /tmp/attack-results/gobuster.txt || true",
      # --ignore-code=401 - the honeypot always answers bad guesses with 401, so without this sqlmap quits after one request.
      "sqlmap -u http://10.0.0.3/ --data='user=admin&pass=admin' --batch --ignore-code=401 --output-dir=/tmp/attack-results/sqlmap || true",
      "tar czf /tmp/attack-results.tar.gz -C /tmp attack-results",
    ]
  }

  # Pulls the tarball down via scp (runs on whatever machine invokes `terraform apply` - WSL, Linux, or macOS).
  provisioner "local-exec" {
    interpreter = ["bash", "-c"]
    command     = <<-EOT
      dest="${path.module}/../../attack-results"
      mkdir -p "$dest"
      stamp=$(date +%Y%m%d-%H%M%S)
      # UserKnownHostsFile=/dev/null - attacker_vm gets a fresh host key on every recreate, often on a
      # reused ephemeral IP, which otherwise trips "REMOTE HOST IDENTIFICATION HAS CHANGED" and can block the transfer.
      scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$HOME/.ssh/lab_shared_key" labuser@${google_compute_instance.attacker_vm.network_interface[0].access_config[0].nat_ip}:/tmp/attack-results.tar.gz "$dest/attack-results-$stamp.tar.gz"
    EOT
  }
}

### OUTPUTS

output "attacker_public_ip" {
  value       = google_compute_instance.attacker_vm.network_interface[0].access_config[0].nat_ip
  description = "SSH into this IP"
}