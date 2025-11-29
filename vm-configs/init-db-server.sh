#!/bin/bash
# init-db-server.sh  – Ubuntu Server 22.04  (MongoDB role)

# Phase 1: install while NAT is present

set -euo pipefail
echo "=== Phase 1: installing MongoDB 7.0 ==="
apt-get update && apt-get upgrade -y
curl -fsSL https://pgp.mongodb.com/server-7.0.asc | gpg --dearmor -o /usr/share/keyrings/mongodb-server-7.0.gpg
echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" \
 > /etc/apt/sources.list.d/mongodb-org-7.0.list
apt-get update
apt-get install -y mongodb-org
systemctl enable mongod


# Phase 2: switch to isolated SW1 (host-only) and reboot

echo "=== Phase 2: move to isolated SW1 (host-only) ==="
IF=$(ip -br link | awk '/enp0s[0-9]+/ {print $1; exit}')
cat > /etc/netplan/01-sw1.yaml <<EOF
network:
  version: 2
  ethernets:
    $IF:
      dhcp4: no
      addresses: [192.168.10.10/24]
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]
EOF
netplan apply
sed -i "s/bindIp.*/bindIp: 192.168.10.10/" /etc/mongod.conf
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow from 192.168.10.0/24 to any port 27017
ufw --force enable
systemctl restart mongod
mongosh mongodb://192.168.10.10:27017 --eval 'db.adminCommand("ping")' && echo "MongoDB ready on 192.168.10.10:27017"