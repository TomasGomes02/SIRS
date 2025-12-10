# T19 CivicEcho Project Read Me

<!-- this is an instruction line; after you follow the instruction, delete the corresponding line. Do the same for all instruction lines! -->

## Team

| Number | Name            | User                                | E-mail                                |
| ------ | --------------- | ----------------------------------- | ------------------------------------- |
| 106869 | Martin Silveira | <https://github.com/MartinSilveira> | <martin.silveira@tecnico.ulisboa.pt>  |
| 112307 | Tomás Gomes     | <https://github.com/TomasGomes02>   | <tomasldgomes2002@tecnico.ulisboa.pt> |
| 117340 | Tomás Matos     | <https://github.com/tomasmatos6>    | <tomasmbmatos@tecnico.ulisboa.pt>     |

![Alice](img/alice.png) ![Bob](img/bob.png) ![Charlie](img/charlie.png)

_(add face photos with 150px height; faces should have similar size and framing)_

## Contents

This repository contains documentation and source code for the _Network and Computer Security (SIRS)_ project.

The [REPORT](REPORT.md) document provides a detailed overview of the key technical decisions and various components of the implemented project.
It offers insights into the rationale behind these choices, the project's architecture, and the impact of these decisions on the overall functionality and performance of the system.

This document presents installation and demonstration instructions.

_(adapt all of the following to your project, changing to the specific Linux distributions, programming languages, libraries, etc)_

## Installation

To see the project in action, it is necessary to setup a virtual environment, with 3 networks and 4 machines.

The following diagram shows the networks and machines:

![Figure 1 - Network diagram](img/diagrama_sirs_v3.png)

### Prerequisites

Database virtual machine and application virtual machine are based on: Ubuntu 22.04.4 live server
[Download](https://old-releases.ubuntu.com/releases/22.04/ubuntu-22.04.4-live-server-amd64.iso) a virtual machine.

### Machine configurations

#### Network topology

Create the following host-only networks in **VirtualBox -> File -> Tools -> Networks -> Host Network Manager**:

| Network | Adapter # | IPv4 Address/Mask | DHCP |
| ------- | --------- | ----------------- | ---- |
| SW1     | #2        | 192.168.10.0/24   | OFF  |
| SW2     | #3        | 192.168.20.0/24   | OFF  |

Wire each VM as shown in the deployment diagram.

#### Machine 1 - Database server

This machine runs Ubuntu 22.04.4-live-server-amd and Mongodb v7.0.26

setup:

1. Create VM with **NAT** network, boot, log in.
2. Inside VM console:
   ```sh
   sudo apt update
   sudo apt install -y curl
   ```
3. [Add port forward] Power-off the VM -> Settings -> Network -> Adapter 1 -> Advanced -> Port Forward -> Add:

| Name | Protocol | Host IP | Host Port | Guest IP | Guest Port |
| ---- | -------- | ------- | --------- | -------- | ---------- |
| ssh  | TCP      |         | 2222      |          | 22         |

4. Power-on the VM and from **Host**:

```sh
ssh <vm-user>@127.0.0.1 -p 2222
```

5. Inside SSH session paste:

```sh
curl -fsSL https://gist.githubusercontent.com/TomasGomes02/c5538fb7a45f8b1fa79c1bd156e9a4b1/raw/abc124e38bb38263a6ebf26c11b1cdd15a64fc6d/init-database-vm.sh | sudo bash
```

6. When script finishes, exit ssh and power-off VM

7. [Isolate network] VM Settings -> Network -> Adapter 1 -> Attached to: Host-only Adapter #2 (192.168.10.0/24)

To verify network isolation:

1. Show ip route table:

```sh
ip route show
```

2. Verify network isolation (no internet):

```sh
ping -c 3 google.com
```

3. Verify reachability inside SW1:

```sh
ping -c 3 192.168.10.0
```

To verify database installation:

```sh
mongosh mongodb://192.168.10.10:27017 --eval 'db.adminCommand("ping")'
```

#### Machine 2 - App Server

This machine runs Ubuntu 22.04.4 (Nginx + Tomcat9 + OpenJDK 25)

setup:

1. Create VM with **NAT** network, boot, log in
2. Inside VM console:
   ```sh
   sudo apt update
   sudo apt install -y curl
   ```
3. [Add port forward] Power-off the VM -> Settings -> Network -> Adapter 1 -> Advanced -> Port Forward -> Add:

| Name | Protocol | Host IP | Host Port | Guest IP | Guest Port |
| ---- | -------- | ------- | --------- | -------- | ---------- |
| ssh  | TCP      |         | 2223      |          | 22         |

4. Power-on the VM and from **Host**:

```sh
ssh <vm-user>@127.0.0.1 -p 2223
```

5. Inside SSH session paste:

```sh
curl -fsSL https://gist.githubusercontent.com/tomasmatos6/70ef5f6cb7376e6e0aea0be1d36a17b9/raw/e019dc54b9a8e624080cc217c2966c719f38692b/init-app-vm.sh | sudo bash
```

6. When script finishes, exit ssh and power-off the VM

7. [Isolate network] VM Settings -> Network -> Adapter 1 -> Attached to: Host-only Adapter #2 (192.168.10.0/24)

8. [Isolate network] VM Settings -> Network -> Adapter 2 -> Attached to: Host-only Adapter #3 (192.168.20.0/24)

To verify network isolation:

1. Show ip route table:

```sh
ip route show
```

2. Verify network isolation (no internet):

```sh
ping -c 3 google.com
```

3. Verify reachability inside SW1:

```sh
ping -c 3 192.168.10.0
```

4. Verify reachability inside SW2:

```sh
ping -c 3 192.168.20.0
```

To verify application services:

```sh
# Test Nginx/SSL/Tomcat stack (ignore the cert warning for now)
curl -k https://192.168.10.20

# After certificate signing, test proper SSL:
curl https://192.168.10.20
```

_(replace with actual commands)_

To test:

```sh
$ test command
```

_(replace with actual commands)_

The expected results are ...

_(explain what is supposed to happen if all goes well)_

If you receive the following message ... then ...

_(explain how to fix some known problem)_

#### Machine ...

_(similar content structure as Machine 1)_

## Demonstration

Now that all the networks and machines are up and running, ...

_(give a tour of the best features of the application; add screenshots when relevant)_

```sh
$ demo command
```

_(replace with actual commands)_

_(IMPORTANT: show evidence of the security mechanisms in action; show message payloads, print relevant messages, perform simulated attacks to show the defenses in action, etc.)_

This concludes the demonstration.

## Additional Information

### Links to Used Tools and Libraries

- [Java 25.0.1](https://openjdk.java.net/)
- [Maven 3.9.11](https://maven.apache.org/)
- ...

### Versioning

We use [SemVer](http://semver.org/) for versioning.

### License

This project is licensed under the MIT License - see the [LICENSE.txt](LICENSE.txt) for details.

_(switch to another license, or no license, as you see fit)_

---

END OF README
