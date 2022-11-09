# Module 06 - Network PenTest - Internal
An internal penetration testing highlights the following items:
- protocol and network infrastructure vulnerabilities
- server operating system and application vulnerabilities
- internal controls and procedures
- unsuitable user privileges
- internal "intrawalls" separating subnetworks

## Footprinting
Gather internal information like domains, hosts, subnets, IP ranges, etc.

### Identify internal domains
Preferred tools: net

| Command | Description |
| --- | --- |
| `net view` | display a list of computers in current domain |
| `net view /domain` | list domains in the network |
| `net view \\ComputerName` | list of file/printer shares |
| `net view \\ComputerName /all` | displays the shares including hidden ones |
| `net view /network:nw` | lists the list of shares on a remote Netware computer |

### Identify Hosts
| Command | Description |
| --- | --- |
| `systeminfo | findstr /B /C:"Domain"\` | find the domain name |
| `echo %userdomain%` | logged in user's domain |
| `wmic <computer_system> get domain` | find domain name |
| `net view /domain: [domain name]` | available servers on \<domain name\> |

### Identify Internal IP Range of Subnet
| Command | Description |
| --- | --- |
| `ipconfig` | host's IP address and subnet mask |
| `arp -a` | IP and physical addresses on same segment |
| `nmap -sL <IP_RANGE>` | list IP addressess in a target subnet |

**Tools**
- [SoftPerfect Network Scanner](https://www.softperfect.com/products/networkscanner/), IP, NETBIOS and SNMP scanner. Can mount shared folders. `Options > IP Address > Detect Local IP Range` calculates the network IP range.
- [MyLanViewer](https://www.mylanviewer.com/network-ip-scanner.html), includes NETBIOS, IP scanning, Wake-On-Lan manager and remote shutdown.
- [SolarWind's IP Network Browser](https://www.solarwinds.com/network-performance-monitor/use-cases/ip-network-browser)

## Network Scanning

## OS and Service Fingerprinting

## Enumeration

## Vulnerability Assessment

## Windows Exploitation

## Unix/Linux Exploitation

## Other Internal Network Exploitation Techniques

## Automating Internal Network PenTest Effort

## Post Exploitation

## Advanced Tips and Techniques

## Document the Result
