#!/bin/bash
# init-client-vm.sh – Ubuntu Server 22.04 (CivicEcho Client)
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

# Configuration
SHARED_NAME="client-app-1.0-SNAPSHOT.jar"                    
MOUNT_POINT="/media/sf_civicecho_jar"        
JAR_NAME="client-app-1.0-SNAPSHOT.jar"
APP_DIR="/opt/civicecho/app"


echo "=== Phase 1: Installing JDK 25 and VirtualBox Guest Additions ==="
apt-get update && apt-get upgrade -y

wget https://download.java.net/java/early_access/jdk25/19/GPL/openjdk-25-ea+19_linux-x64_bin.tar.gz
mkdir -p /opt/jdk
tar -xf openjdk-25-ea+19_linux-x64_bin.tar.gz -C /opt/jdk --strip-components=1
update-alternatives --install /usr/bin/java java /opt/jdk/bin/java 2500

apt-get install -y virtualbox-guest-utils

echo "=== Phase 2: Setting up user and copying JAR from shared folder ==="
useradd -m -s /bin/bash civicecho
mkdir -p $APP_DIR

usermod -aG vboxsf civicecho

sleep 2

# Check if JAR exists in shared folder
if [ -f "$SHARED_DIR/$JAR_NAME" ]; then
    cp "$SHARED_DIR/$JAR_NAME" "$APP_DIR/"
    chown civicecho:civicecho "$APP_DIR/$JAR_NAME"
    echo "JAR copied from shared folder"
else
    echo "ERROR: JAR not found at $SHARED_DIR/$JAR_NAME"
    echo "Please ensure:"
    echo "  1. VirtualBox shared folder 'civicecho-shared' is configured"
    echo "  2. The JAR is placed in that folder on the host"
    exit 1
fi

chown -R civicecho:civicecho $APP_DIR

echo "=== Phase 3: Configuring firewall (production-safe) ==="
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw --force enable

echo "=== Setup complete ==="
echo "After rebooting into Host-only #3:"
echo "1. Log in as user 'civicecho'"
echo "2. Run: cd $APP_DIR && /opt/jdk/bin/java -jar $JAR_NAME"
