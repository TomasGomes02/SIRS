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

#### Database Certificate:

# 1. Generate DB Private Key

openssl genrsa -out db-ca.key 4096

# 2. Generate DB Self-Signed Certificate

# CN=CivicDB-CA is the issuer name everyone will see

openssl req -x509 -new -nodes -key db-ca.key -sha256 -days 365 \
 -out db-ca.crt \
 -subj "/C=PT/ST=Lisbon/L=Oeiras/O=CivicEcho/OU=DB/CN=CivicDB-CA"

#### App Server Certificate:

# 1. Generate App Server Private Key

openssl genrsa -out app-server.key 2048

# 2. Create Certificate Signing Request (CSR)

# CN must match the hostname (e.g., localhost)

openssl req -new -key app-server.key -out app-server.csr \
 -subj "/C=PT/ST=Lisbon/L=Oeiras/O=CivicEcho/OU=App/CN=localhost"

# 3. Create a configuration file for SAN (Required for localhost)

cat > app-ext.cnf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

# 4. Sign the App Server CSR using the DB CA

openssl x509 -req -in app-server.csr -CA db-ca.crt -CAkey db-ca.key \
 -CAcreateserial -out app-server.crt -days 365 -sha256 -extfile app-ext.cnf

#### Auth Server Certificate:

# 1. Generate Auth Server Private Key

openssl genrsa -out auth-server.key 2048

# 2. Create Certificate Signing Request (CSR)

openssl req -new -key auth-server.key -out auth-server.csr \
 -subj "/C=PT/ST=Lisbon/L=Oeiras/O=CivicEcho/OU=Auth/CN=localhost"

# 3. Create configuration for SAN (Reuse same SAN config if running on localhost)

# (We can reuse app-ext.cnf or create auth-ext.cnf if IPs differ)

cp app-ext.cnf auth-ext.cnf

# 4. Sign the Auth Server CSR using the DB CA

openssl x509 -req -in auth-server.csr -CA db-ca.crt -CAkey db-ca.key \
 -CAcreateserial -out auth-server.crt -days 365 -sha256 -extfile auth-ext.cnf

#### Package Keys for Java:

##### Create Server Identity Keystore

# For App Server (Password: appserverpass)

openssl pkcs12 -export -in app-server.crt -inkey app-server.key \
 -out app-server.p12 -name app-server \
 -CAfile db-ca.crt -caname root -passout pass:serverpass

# For Auth Server (Password: authserverpass)

openssl pkcs12 -export -in auth-server.crt -inkey auth-server.key \
 -out auth-server.p12 -name auth-server \
 -CAfile db-ca.crt -caname root -passout pass:serverpass

##### Create the Common Truststore

# Import DB CA certificate into a new Java KeyStore (Password: clientpass)

keytool -import -trustcacerts -noprompt -alias db-ca \
 -file db-ca.crt -keystore truststore.jks -storepass clientpass
