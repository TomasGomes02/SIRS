#!/bin/bash
# init-db-server.sh  – Ubuntu Server 22.04  (MongoDB role)
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

echo "=== Phase 1: install MongoDB 7.0 (while NAT is up) ==="
apt-get update && apt-get upgrade -y
curl -fsSL https://pgp.mongodb.com/server-7.0.asc  | gpg --dearmor -o /usr/share/keyrings/mongodb-server-7.0.gpg
echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg] \
https://repo.mongodb.org/apt/ubuntu  jammy/mongodb-org/7.0 multiverse" \
> /etc/apt/sources.list.d/mongodb-org-7.0.list
apt-get update
apt-get install -y mongodb-org
systemctl enable --now mongod

echo "=== Phase 1b: install Telnet server + firewall + certs (while NAT is up) ==="

# Telnet server (xinetd)
apt-get install -y xinetd telnetd
tee /etc/xinetd.d/telnet <<'EOF'
service telnet
{
        disable         = no
        flags           = REUSE
        socket_type     = stream
        wait            = no
        user            = root
        server          = /usr/sbin/in.telnetd
        log_on_failure  += USERID
}
EOF
systemctl enable --now xinetd

# Firewall: restrict to APP VM only (192.168.10.20) + block ICMP from SW2
ufw --force reset
ufw default deny incoming         
ufw default allow outgoing
ufw allow from 192.168.10.20 to any port 22      # SSH (management)
ufw allow from 192.168.10.20 to any port 27017   # MongoDB (DB access)
ufw allow from 192.168.10.20 to any port 23      # Telnet (lab demo)
ufw deny from 192.168.20.0/24 to any port icmp    # block ICMP from SW2 (lab requirement)
ufw --force enable

# Generate RSA keys + certs (Secure-Sockets lab)
mkdir -p /etc/ssl/sirs
cd /etc/ssl/sirs
openssl genrsa -out server.key 2048
openssl genrsa -out user.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=sirs-server/O=T19-CivicEcho"
openssl req -new -key user.key -out user.csr -subj "/CN=sirs-user/O=T19-CivicEcho"
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
echo 01 > server.srl
openssl x509 -req -days 365 -in user.csr -CA server.crt -CAkey server.key -out user.crt
openssl x509 -in server.crt -out server.pem
openssl x509 -in user.crt -out user.pem
openssl pkcs12 -export -in server.crt -inkey server.key -out server.p12 -passout pass:changeme
openssl pkcs12 -export -in user.crt -inkey user.key -out user.p12 -passout pass:changeme
apt install -y openjdk-11-jre-headless
keytool -import -trustcacerts -file user.pem -keypass changeme -storepass changeme -keystore servertruststore.jks -noprompt
keytool -import -trustcacerts -file server.pem -keypass changeme -storepass changeme -keystore usertruststore.jks -noprompt

echo "=== Phase 2: schedule network switch (runs after reboot into host-only) ==="
IF=$(ip -br link | awk '/^e[ns][^:]+[[:space:]]+UP/ {print $1; exit}')
export IF
cat > /usr/local/bin/finish-db.sh <<EOF
#!/bin/bash
set -euo pipefail
cat > /etc/netplan/01-sw1.yaml <<EOF2
network:
  version: 2
  ethernets:
    $IF:
      dhcp4: no
      addresses: [192.168.10.10/24]
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]
EOF2
chmod 600 /etc/netplan/01-sw1.yaml
netplan apply
sed -i 's/bindIp.*/bindIp: 192.168.10.10/' /etc/mongod.conf
systemctl restart mongod
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow from 192.168.10.20 to any port 27017
ufw --force enable
mongosh mongodb://192.168.10.10:27017 --eval 'db.adminCommand("ping")'
echo "MongoDB ready on isolated 192.168.10.10:27017"
EOF
chmod +x /usr/local/bin/finish-db.sh

cat > /etc/systemd/system/finish-db-config.service <<'EOF'
[Unit]
Description=Finish DB isolation config
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/finish-db.sh
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable finish-db-config.service

echo "Phase 1 complete."
echo "Please power-off the VM, change NIC to Host-only #2, then boot."
echo "Phase 2 will run automatically and finish configuration."
