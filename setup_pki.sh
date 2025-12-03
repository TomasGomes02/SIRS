#!/bin/bash
# setup_pki.sh
# Simulates the Provisioning Phase: Generates keys for DB, Server, and Client.

echo "--- 1. Cleaning Environment ---"
mkdir -p keys/ca
mkdir -p keys/mongo
mkdir -p app/src/main/resources
mkdir -p client/src/main/resources
rm -f keys/ca/* keys/mongo/* app/src/main/resources/*.p12 client/src/main/resources/*.jks

echo "--- 2. Generate CA (Root of Trust) ---"
# This represents the Organization's root CA (held on the DB VM or Admin Station)
openssl genrsa -out keys/ca/ca.key 2048
openssl req -x509 -new -nodes -key keys/ca/ca.key -sha256 -days 365 \
    -out keys/ca/ca.crt -subj "/CN=CivicEcho-Root-CA"

echo "--- 3. Provisioning Database (MongoDB) ---"
# Generate DB Key & CSR
openssl genrsa -out keys/mongo/mongodb.key 2048
openssl req -new -key keys/mongo/mongodb.key -out keys/mongo/mongodb.csr -subj "/CN=localhost"

# Sign DB Cert with CA
openssl x509 -req -in keys/mongo/mongodb.csr -CA keys/ca/ca.crt -CAkey keys/ca/ca.key \
    -CAcreateserial -out keys/mongo/mongodb.crt -days 365 -sha256

# Mongo requires the Key and Cert in a SINGLE PEM file
cat keys/mongo/mongodb.key keys/mongo/mongodb.crt > keys/mongo/mongodb.pem

echo "--- 4. Provisioning App Server ---"
# Generate Server Key
openssl genrsa -out app/server.key 2048
openssl req -new -key app/server.key -out app/server.csr -subj "/CN=localhost"

# Sign Server Cert with CA
openssl x509 -req -in app/server.csr -CA keys/ca/ca.crt -CAkey keys/ca/ca.key \
    -CAcreateserial -out app/server.crt -days 365 -sha256

# Package for Java (PKCS12 Keystore)
# This file is "SCP'd" to the Server VM
openssl pkcs12 -export -in app/server.crt -inkey app/server.key \
    -out app/src/main/resources/server.p12 -name server \
    -CAfile keys/ca/ca.crt -caname root -passout pass:serverpass

# Create a Truststore for the Server (so it trusts the Database)
keytool -import -trustcacerts -noprompt -alias root -file keys/ca/ca.crt \
    -keystore app/src/main/resources/server_truststore.jks -storepass serverpass

rm app/server.key app/server.csr app/server.crt

echo "--- 5. Provisioning Client ---"
# Create Client Truststore (so it trusts the App Server)
keytool -import -trustcacerts -noprompt -alias root -file keys/ca/ca.crt \
    -keystore client/src/main/resources/client_truststore.jks -storepass clientpass

echo "--- Setup Complete ---"
