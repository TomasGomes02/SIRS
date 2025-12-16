# T19 CivicEcho Project Read Me

## Team

| Number | Name            | User                                                                   | E-mail                                                                            |
| ------ | --------------- | ---------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| 106869 | Martin Silveira | [https://github.com/MartinSilveira](https://github.com/MartinSilveira) | [martin.silveira@tecnico.ulisboa.pt](mailto:martin.silveira@tecnico.ulisboa.pt)   |
| 112307 | Tomás Gomes     | [https://github.com/TomasGomes02](https://github.com/TomasGomes02)     | [tomasldgomes2002@tecnico.ulisboa.pt](mailto:tomasldgomes2002@tecnico.ulisboa.pt) |
| 117340 | Tomás Matos     | [https://github.com/tomasmatos6](https://github.com/tomasmatos6)       | [tomasmbmatos@tecnico.ulisboa.pt](mailto:tomasmbmatos@tecnico.ulisboa.pt)         |

![Alice](img/alice.png) ![Bob](img/bob.png) ![Charlie](img/charlie.png)

_(add face photos with 150px height; faces should have similar size and framing)_

## Contents

This repository contains documentation and source code for the _Network and Computer Security (SIRS)_ project.

The [REPORT](REPORT.md) document provides a detailed overview of the key technical decisions and various components of the implemented project. It offers insights into the rationale behind these choices, the project's architecture, and the impact of these decisions on the overall functionality and performance of the system.

This document presents installation and demonstration instructions.

## Installation

To see the project in action, it is necessary to setup a virtual environment with **2 isolated networks** and **4 virtual machines**.

The following diagram shows the networks and machines:

### 0\. Prerequisites & Build

**Host Machine Requirements:**

- VirtualBox
- Java 21+ & Maven (to build the JARs)
- Base VM ISO: Ubuntu 22.04.4 live server ([Download](https://old-releases.ubuntu.com/releases/22.04/ubuntu-22.04.4-live-server-amd64.iso))

**Build the Project:**
Before creating the VMs, you must build the project to generate the JAR files that will be shared with the VMs. Run this command in the root of the repository:

```sh
mvn clean package
```

_Ensure that the `target/` folders and `.jar` files are created inside `app/`, `auth-server/`, `client/`, and `db/`._

### 1\. Network Configuration

Create the following host-only networks in **VirtualBox -\> File -\> Tools -\> Network Manager**:

| Network Name          | IPv4 Address/Mask | DHCP Server  |
| :-------------------- | :---------------- | :----------- |
| **SW1** (Network \#2) | `192.168.10.0/24` | **Disabled** |
| **SW2** (Network \#3) | `192.168.20.0/24` | **Enabled**  |
_(Note: In the DHCP Server in SW2, select the lower address bound as 192.168.20.100 and the upper address bound as 192.168.20.200)._

### 2\. Virtual Machines Setup

We require 4 Virtual Machines. The setup process is identical for all of them, differing only in **Network Connections**, **Shared Folders**, and the **Initialization Script**.

#### A. Create & Configure VMs

For each machine (Database, App Server, Auth Server, Client), follow these steps:

1.  **Create VM:** Use the Ubuntu 22.04 ISO.
2.  **Initial Network:** Set Adapter 1 to **NAT** (to allow internet access during setup).
3.  **Port Forwarding:** To SSH into them during setup, add a rule (Host Port: `2222`-`2225` -\> Guest Port: `22`).
4.  **Shared Folders:** Go to **Settings -\> Shared Folders** and add the folder corresponding to the VM type.
    - _Note: Check "Make Machine-permanent" (If the VM is already running)._
    - _Note: Check "Auto-mount"_
    - _Note: The "Folder Path" is the location on your host machine._

| VM Role         | Username    |Shared Folder Path (Host)                  | Network Adapter 1 (Target) | Network Adapter 2 (Target) |
| :-------------- | ----------- | :---------------------------------------- | :------------------------- | :------------------------- |
| **Database**    | database    | `.../T19-CivicEcho/db/src/main/resources` | Host-only **SW1** (\#2)    | _None_                     |
| **App Server**  | app         | `.../T19-CivicEcho/app/target`            | Host-only **SW1** (\#2)    | Host-only **SW2** (\#3)    |
| **Auth Server** | auth        | `.../T19-CivicEcho/auth/target`           | Host-only **SW1** (\#2)    | Host-only **SW2** (\#3)    |
| **Client**      | client      | `.../T19-CivicEcho/client/target`         | Host-only **SW2** (\#3)    | _None_                     |

_(Note: During the "Installation Phase", keep Adapter 1 as NAT. You will switch to the Host-only networks listed above ONLY after running the script)._

#### B. Installation & Scripts

Boot each VM, log in, and run the following commands to set up the environment.

**Database VM**

```bash
curl -fsSL https://gist.githubusercontent.com/TomasGomes02/c5538fb7a45f8b1fa79c1bd156e9a4b1/raw/8fab50e25ae60e7c9ed875bfcb8be590e96316e7/init-database-vm.sh | sudo bash
```

**App Server VM**

```bash
curl -fsSL https://gist.githubusercontent.com/tomasmatos6/70ef5f6cb7376e6e0aea0be1d36a17b9/raw/418d40a380d3105b560656f52729832fb7ccf045/init-app-vm.sh | sudo bash
```

**Auth Server VM**

```bash
curl -fsSL https://gist.githubusercontent.com/tomasmatos6/beeaaaffec51e330f78cc526f80a21d2/raw/06540d01d3483e1607deba0aba0c5293ceb98aaa/init-auth-vm.sh | sudo bash
```

**Client VM**

```bash
curl -fsSL https://gist.githubusercontent.com/tomasmatos6/55a5a0d0a02b240edbde6916c0aedc5e/raw/d9f9c23bd662e6ee6dbdc8f6734724d741afc1bc/init-client-vm.sh | sudo bash
```

3.  **Finalize Network Isolation:**
    - **Power OFF** the VM.
    - Change the **Network Adapters** in VirtualBox settings to match the table in **Step A**.
      - _For Client:_ Change Adapter 1 to Host-Only SW2.
      - _For Database:_ Change Adapter 1 to Host-Only SW1.
      - _For App and Auth:_ Change Adapter 1 to Host-Only SW1 and enable Adapter 2 with Host-Only SW2.
    - **Power ON** the VM.

### 3\. Verification

After rebooting into the isolated networks, verify connectivity and services.

_Note:_ If connection through ssh is desired, run:
```sh
sudo ufw allow ssh
```

**1. Network Isolation (All VMs)**

```sh
ip route show

ping -c 3 google.com   # Should FAIL (No internet)
```

**2. Database Server (`192.168.10.10`)**

```sh
# Check if MongoDB is running and reachable
sudo systemctl status mongod

# Verify connection to App Server
ping -c 3 192.168.10.20

# Verify connection to Auth Server
ping -c 3 192.168.10.11
```

**3. App/Auth Servers (`192.168.10.20`, `192.168.10.11`)**

```sh
# Verify connection to DB
ping -c 3 192.168.10.10
```

**4. Client Machine (`192.168.20.100`)**

```sh
# Verify connection to App Server
ping -c 3 192.168.20.20

# Verify connection to Auth Server
ping -c 3 192.168.20.10
```

### Troubleshooting

#### In case your host machine is blocking the switches do this:

#### **Windows**

- Enable Ipv4 pings in windows

#### **Linux**

```sh

```

## Demonstration

Now that the system is running, you can demonstrate the full flow.

### 1\. User Registration & Login (Client VM)

On the Client VM, run the application:

```sh
java -jar /opt/civicecho/app/client-app-1.0-SNAPSHOT.jar
```

- **Register:** Creates a new user key pair and registers with the Auth Server.
- **Login:** Authenticates using the Challenge-Response protocol.

### 2\. Submitting a Report

```sh
# Inside the client CLI
report
```

- _Observation:_ The client requests a nonce, signs the report, encrypts it (Hybrid Encryption), and submits it.

### 3\. Security Checks (Attacks)

To demonstrate resilience, simulate the following attacks:

**Replay Attack:**
Capture a valid `SUBMIT` payload and try sending it again using `curl`:

```sh
curl -X POST -d @captured_payload.json 192.168.20.20:8443
```

_Expected Result:_ The server rejects the request with `401 Unauthorized` or `Invalid Nonce`.

**Man-in-the-Middle (MITM):**
Try to inspect traffic between Client and App Server using Wireshark/tcpdump on the SW2 interface.
_Expected Result:_ All traffic is encrypted via TLS, making the payload unreadable.

**Pinging database directly:**
Try to ping the database directly as an attacker (client machine) from inside and outside the network.

```sh
ping -c 3 192.168.10.10
```

## Additional Information

### Links to Used Tools and Libraries

- [Java 25](https://openjdk.java.net/)
- [Maven 3.9.11](https://maven.apache.org/)
- [MongoDB 7.0](https://www.mongodb.com/)
- [Google Gson](https://github.com/google/gson) (JSON handling)

### Versioning

We use [Github](https://github.com/) for versioning.

### License

This project is licensed under the MIT License - see the [LICENSE.txt](https://www.google.com/search?q=LICENSE.txt) for details.

---
