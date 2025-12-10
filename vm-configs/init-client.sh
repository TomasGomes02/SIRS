#!/bin/bash
# init-client-vm.sh – Ubuntu Server 22.04 (CivicEcho Client role, minimal)
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# --- Configurations ---
SHARED_NAME="jar"   # VBox shared-folder label
MOUNT_POINT="/media/sf_civicechor"
APP_DIR="/opt/civicecho/client"
CLIENT_JAR="client-app-1.0-SNAPSHOT.jar"
CLIENT_NET="192.168.20.0/24"
IF=$(ip -br link | awk '/^e[ns][^:]+[[:space:]]+UP/ {print $1; exit}')


echo '=== 1. install JDK 25 ==='
apt-get update && apt-get upgrade -y

apt-get install -y openjdk-25-jdk virtualbox-guest-utils


echo "=== 2. user & shared folder ==="
useradd -m -s /bin/bash $USER 2>/dev/null || true
mkdir -p "$APP_DIR" "$MOUNT_POINT"
usermod -aG vboxsf $USER
mount -t vboxsf "$SHARED_NAME" "$MOUNT_POINT" || {
  echo "ERROR: mount failed – install Guest Additions"; exit 1
}

cp "$MOUNT_POINT/$CLIENT_JAR" "$APP_DIR/"
chown -R $USER:$USER "$APP_DIR"


echo "=== 3. firewall ==="
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw --force enable


echo "=== 4. enable DHCP on SW2 ==="
cat >/usr/local/bin/finish-client.sh <<EOF
#!/bin/bash
cat >/etc/netplan/02-sw2.yaml <<EOF2
network:
  version: 2
  ethernets:
    $IF:
      dhcp4: yes
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]
EOF2
chmod 600 /etc/netplan/02-sw2.yaml
netplan apply
echo "Client ready – run: sudo -u civicecho -i && cd $APP_DIR && /opt/jdk/bin/java -jar $CLIENT_JAR"
EOF
chmod +x /usr/local/bin/finish-client.sh
cat >/etc/systemd/system/finish-client-config.service <<'EOF'
[Unit]
Description=Finish Client isolation config
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/finish-client.sh
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable finish-client-config.service

echo 'Done. After isolating the VM:'
echo '  sudo -u civicecho -i'
echo '  cd $APP_DIR && /opt/jdk/bin/java -jar $CLIENT_JAR'
