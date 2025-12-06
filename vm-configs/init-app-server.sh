#!/bin/bash
# init-app-server.sh – Ubuntu Server 22.04 (App Server role)
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

# --- Configuration Variables ---
DB_IP="192.168.10.10"
APP_IP="192.168.20.20"
CLIENT_NET="192.168.20.0/24"
# Network interface logic (dynamic)
IF=$(ip -br link | awk '/^e[ns][^:]+[[:space:]]+UP/ {print $1; exit}')

echo "=== Phase 1: Install Software (Nginx, Tomcat, Java) ==="
apt-get update && apt-get upgrade -y
apt-get install -y nginx tomcat9 openjdk-11-jdk ufw

# Ensure Tomcat is running on localhost:8080
systemctl enable --now tomcat9

echo "=== Phase 2: Certificate Generation (PKI) ==="
mkdir -p /etc/ssl/sirs
cd /etc/ssl/sirs

# Generate App Server Private Key
openssl genrsa -out app-server.key 2048

# Generate CSR to be signed by DB server
openssl req -new -key app-server.key -out app-server.csr -subj "/CN=civicecho-app/O=T19-CivicEcho"

# Generate temporary self-signed cert
openssl x509 -req -days 365 -in app-server.csr -signkey app-server.key -out app-server.crt

# Set permissions
chmod 600 app-server.key
chmod 644 app-server.crt

echo "=== Phase 3: Configure Nginx (Reverse Proxy) ==="
mv /etc/nginx/sites-available/default /etc/nginx/sites-available/default.bak

cat > /etc/nginx/sites-available/default <<EOF
server {
    listen 80;
    server_name _;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name civicecho-app;

    ssl_certificate /etc/ssl/sirs/app-server.crt;
    ssl_certificate_key /etc/ssl/sirs/app-server.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

nginx -t
systemctl restart nginx

echo "=== Phase 4: Firewall Configuration (Restricted to Internal Network) ==="
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Allow SSH from management network only (SW2)
ufw allow from $CLIENT_NET to any port 22 proto tcp

# Allow HTTP/HTTPS from internal clients ONLY (SW2)
ufw allow from $CLIENT_NET to any port 80 proto tcp
ufw allow from $CLIENT_NET to any port 443 proto tcp

# Explicitly allow outbound connections to DB server (MongoDB)
ufw allow out to $DB_IP port 27017 proto tcp

ufw --force enable

echo "=== Phase 5: Schedule Network Switch (Host-Only SW2) ==="
cat > /usr/local/bin/finish-app.sh <<EOF
#!/bin/bash
set -euo pipefail

# Apply Static IP Configuration for SW2
cat > /etc/netplan/02-sw2.yaml <<EOF2
network:
  version: 2
  ethernets:
    $IF:
      dhcp4: no
      addresses: [$APP_IP/24]
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]
EOF2
chmod 600 /etc/netplan/02-sw2.yaml
netplan apply

# Restart services to bind to new IP
systemctl restart tomcat9
systemctl restart nginx

echo "App Server ready on isolated $APP_IP (SW2)"
EOF
chmod +x /usr/local/bin/finish-app.sh

# Systemd service to run the network switch on next boot
cat > /etc/systemd/system/finish-app-config.service <<'EOF'
[Unit]
Description=Finish App isolation config for SW2
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/finish-app.sh
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable finish-app-config.service

echo "=== Setup Complete ==="
echo "1. Power off this VM."
echo "2. Change NIC to Host-only #3 (SW2 - 192.168.20.0/24)."
echo "3. Boot VM to apply network isolation."
echo ""
echo "--- MANUAL STEP REQUIRED FOR CERTIFICATES ---"
echo "1. Copy /etc/ssl/sirs/app-server.csr from this VM to the DB VM (SW1)."
echo "2. On DB VM, sign it: openssl x509 -req -in app-server.csr -CA server.crt -CAkey server.key -CAcreateserial -out app-server.crt"
echo "3. Copy the signed 'app-server.crt' BACK to this VM at /etc/ssl/sirs/app-server.crt"
echo "4. Restart Nginx: systemctl restart nginx"
