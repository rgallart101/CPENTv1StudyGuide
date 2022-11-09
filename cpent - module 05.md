# Module 05 - Network PenTest - External
External network pentest has the focus on assessing the assets and identifying the vulnerabilities that could help attackers to exploit the network from outside.
## Steps
1 Information gathering (OSINT)
2 Port Scanning
3 OS and Service fingerprinting
4 Vulnerability research
5 Exploit verification
6 Reporting
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

### ￼Use Connect Scan
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


