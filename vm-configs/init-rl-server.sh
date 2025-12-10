#!/bin/bash
# init-rate-limiter-vm.sh – Ubuntu Server 22.04 (Rate-Limiter role, minimal)
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# Configurations
SHARED_NAME='T19-CivicEcho/auth/jar'   # VBox label
MOUNT_POINT='/media/sf_civicecho'
APP_DIR='/opt/civicecho/app'
AUTH_JAR='auth-1.0-SNAPSHOT.jar'
AUTH_IP='192.168.20.10'          
DB_IP='192.168.10.10'           
IF=$(ip -br link | awk '/^e[ns][^:]+[[:space:]]+UP/ {print $1; exit}')


echo '=== 1. install JDK 25 ==='
apt-get update && apt-get upgrade -y
wget https://download.java.net/java/early_access/jdk25/19/GPL/openjdk-25-ea+19_linux-x64_bin.tar.gz
mkdir -p /opt/jdk
tar -xf openjdk-25-ea+19_linux-x64_bin.tar.gz -C /opt/jdk --strip-components=1
update-alternatives --install /usr/bin/java java /opt/jdk/bin/java 2500
rm openjdk-25-ea+19_linux-x64_bin.tar.gz
apt-get install -y virtualbox-guest-utils

echo '=== 2. user & shared folder ==='
useradd -m -s /bin/bash civicecho 2>/dev/null || true
mkdir -p "$APP_DIR" "$MOUNT_POINT"
usermod -aG vboxsf civicecho
mount -t vboxsf "$SHARED_NAME" "$MOUNT_POINT" || {
  echo 'ERROR: mount failed – install Guest Additions'; exit 1
}

cp "$MOUNT_POINT/$AUTH_JAR" "$APP_DIR/"

chown -R civicecho:civicecho "$APP_DIR"

echo '=== 3. static IP on SW2 ==='
cat >/usr/local/bin/finish-rate-limiter.sh <<EOF
#!/bin/bash
cat >/etc/netplan/02-sw2.yaml <<EOF2
network:
  version: 2
  ethernets:
    $IF:
      dhcp4: no
      addresses: [$AUTH_IP/24]
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]
EOF2
chmod 600 /etc/netplan/02-sw2.yaml
netplan apply
echo "Rate-Limiter ready – run: sudo -u civicecho -i && cd $APP_DIR && /opt/jdk/bin/java -jar $AUTH_JAR"
EOF
chmod +x /usr/local/bin/finish-rate-limiter.sh
cat >/etc/systemd/system/finish-rate-limiter-config.service <<'EOF'
[Unit]
Description=Finish Rate-Limiter isolation config
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/finish-rate-limiter.sh
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable finish-rate-limiter-config.service


echo '=== 4. firewall ==='
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow from "$AUTH_IP" to "$DB_IP" port 27017 proto tcp
ufw --force enable

echo 'Done. After isolating the VM:'
echo '  sudo -u civicecho -i'
echo '  cd $APP_DIR && /opt/jdk/bin/java -jar $AUTH_JAR'