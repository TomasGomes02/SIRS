# CXX DeathNode / ChainOfProduct / CivicEcho Project Report

## 1. Introduction

(_Provide a brief overview of your project, including the business scenario and the main components: secure documents, infrastructure, and security challenge._)

(_Include a structural diagram, in UML or other standard notation._)

## 2. Project Development

### 2.1. Secure Document Format

#### 2.1.1. Design

(_Outline the design of your custom cryptographic library and the rationale behind your design choices, focusing on how it addresses the specific needs of your chosen business scenario._)

(_Include a complete example of your data format, with the designed protections._)

#### 2.1.2. Implementation

(_Detail the implementation process, including the programming language and cryptographic libraries used._)

(_Include challenges faced and how they were overcome._)

### 2.2. Infrastructure

#### 2.2.1. Network and Machine Setup

(_Provide a brief description of the built infrastructure._)

(_Justify the choice of technologies for each server._)

#### 2.2.2. Server Communication Security

(_Discuss how server communications were secured, including the secure channel solutions implemented and any challenges encountered._)

(_Explain what keys exist at the start and how are they distributed?_)

### 2.3. Security Challenge

#### 2.3.1. Challenge Overview

(_Describe the new requirements introduced in the security challenge and how they impacted your original design._)

#### 2.3.2. Attacker Model

(_Define who is fully trusted, partially trusted, or untrusted._)

(_Define how powerful the attacker is, with capabilities and limitations, i.e., what can he do and what he cannot do_)

#### 2.3.3. Solution Design and Implementation

(_Explain how your team redesigned and extended the solution to meet the security challenge, including key distribution and other security measures._)

(_Identify communication entities and the messages they exchange with a UML sequence or collaboration diagram._)

## 3. Conclusion

(_State the main achievements of your work._)

(_Describe which requirements were satisfied, partially satisfied, or not satisfied; with a brief justification for each one._)

(_Identify possible enhancements in the future._)

(_Offer a concluding statement, emphasizing the value of the project experience._)

## 4. Bibliography

(_Present bibliographic references, with clickable links. Always include at least the authors, title, "where published", and year._)

---

END OF REPORT

### Generating the certificates

# 1. Create Config for the SERVERS (Mongo, App, Auth)

# These are the machines that need the IP addresses/SANs.

cat > server_san.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
[req_distinguished_name]
C = PT
O = CivicEcho
CN = Generic-Server
[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names
[alt_names]
IP.1 = 192.168.10.10
IP.2 = 192.168.10.20
IP.3 = 192.168.10.11
IP.4 = 192.168.20.20
IP.5 = 192.168.20.10
DNS.1 = localhost
EOF

# 2. Create the Root CA (Self-Signed)

# CA does NOT need the IPs. It just needs to be a valid Authority.

openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
 -keyout db-ca.key -out db-ca.crt \
 -subj "/C=PT/O=CivicEcho/CN=CivicEcho-Root-CA"

# 3. Create PEM bundle for Mongo (Key + Cert)

cat db-ca.crt db-ca.key > db-ca.pem

# 4. Generate & Sign App-Server Cert

openssl req -new -nodes -newkey rsa:2048 \
 -keyout app-server.key -out app-server.csr \
 -subj "/C=PT/O=CivicEcho/CN=App-Server" \
 -config server_san.cnf

openssl x509 -req -in app-server.csr \
 -CA db-ca.crt -CAkey db-ca.key -CAcreateserial \
 -out app-server.crt -days 365 \
 -extensions v3_req -extfile server_san.cnf

openssl pkcs12 -export -in app-server.crt -inkey app-server.key \
 -out app-server.p12 -name app-server \
 -CAfile db-ca.crt -caname root-ca \
 -passout pass:appserverpass

# 5. Generate & Sign Auth-Server Cert

openssl req -new -nodes -newkey rsa:2048 \
 -keyout auth-server.key -out auth-server.csr \
 -subj "/C=PT/O=CivicEcho/CN=Auth-Server" \
 -config server_san.cnf

openssl x509 -req -in auth-server.csr \
 -CA db-ca.crt -CAkey db-ca.key -CAcreateserial \
 -out auth-server.crt -days 365 \
 -extensions v3_req -extfile server_san.cnf

openssl pkcs12 -export -in auth-server.crt -inkey auth-server.key \
 -out auth-server.p12 -name auth-server \
 -CAfile db-ca.crt -caname root-ca \
 -passout pass:authserverpass

# 6. Generate Key & CSR for MongoDB

openssl req -new -nodes -newkey rsa:2048 \
 -keyout mongodb-server.key -out mongodb-server.csr \
 -subj "/C=PT/O=CivicEcho/CN=sirs-database1" \
 -config server_san.cnf

# 7. Sign it with your CA

openssl x509 -req -in mongodb-server.csr \
 -CA db-ca.crt -CAkey db-ca.key -CAcreateserial \
 -out mongodb-server.crt -days 365 \
 -extensions v3_req -extfile server_san.cnf

# 8. Create the PEM bundle (Key + Cert) for MongoDB

cat mongodb-server.key mongodb-server.crt > mongodb-server.pem

# 9. Create Java Truststore

# (Delete old one first to avoid duplicates)

rm -f server_truststore.jks
keytool -import -alias db-ca -file db-ca.crt \
 -keystore server_truststore.jks \
 -storepass changeit -noprompt
