# Module 06 - Network PenTest - Internal
An internal penetration testing highlights the following items:
- protocol and network infrastructure vulnerabilities
- server operating system and application vulnerabilities
- internal controls and procedures
- unsuitable user privileges
- internal "intrawalls" separating subnetworks

## Footprinting
Purpose: to gather internal information like domains, hosts, subnets, IP ranges, etc.

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
| `systeminfo \| findstr /B /C:"Domain"\` | find the domain name |
| `echo %userdomain%` | logged in user's domain |
| `wmic <computer_system> get domain` | find domain name |
| `net view /domain: [domain name]` | available servers on \<domain name\> |

### Identify Internal IP Range of Subnet
| Command | Description |
| --- | --- |
| `ipconfig` | host's IP address and subnet mask |
| `arp -a` | IP and physical addresses on same segment |
| `nmap -sL <IP_RANGE>` | list IP addressess in a target subnet |

**Other tools**
- [SoftPerfect Network Scanner](https://www.softperfect.com/products/networkscanner/), IP, NETBIOS and SNMP scanner. Can mount shared folders. `Options > IP Address > Detect Local IP Range` calculates the network IP range.
- [MyLanViewer](https://www.mylanviewer.com/network-ip-scanner.html), includes NETBIOS, IP scanning, Wake-On-Lan manager and remote shutdown.
- [SolarWind's IP Network Browser](https://www.solarwinds.com/network-performance-monitor/use-cases/ip-network-browser)

## Network Scanning
Preferred tools: nmap
Purpose: to discover exploitable communication channels, probe as many listeners as possible and keep track of the ones that are responsive or useful to our needs.

### Scanning Methodology
1. Live systems, `-sP`, `-sn` in nmap
2. Ports, all of them, 0-65535. `-sS`, `-sT`, `-sU` in nmap
3. Services, what's behind the ports. `-sV` in nmap
4. Enumeration, `-sC`, `-A` in nmap
5. Identify vulnerabilities, manual search and tools ([Search and Map the Target](./cpent%20-%20module%2005.md#search-and-map-the-target), [Vulnerability Assessment](cpent%20-%20module%2006.md#vulnerability-assessment))
6. Exploit, validate the vulnerability and exploit it ([Exploit Verification](./cpent%20-%20module%2005.md#exploit-verification))

### Scan a Network: IP Addresses, Multiple Addresses, Subnet Scan
| Scan Type | Command |
| --- | --- |
| Scan single host | `nmap <IP_ADDRESS>` |
| Scan multiple hosts | `nmap <IP1> <IP2> <IP3>...` or `nmap 10.10.10.10,11,12,13...` |
| Scan a subnet | `nmap <CIDR>`, e.g. `nmap 192.168.0.0/24` |
| Scan IP address range | `nmap 10.10.10.10-255` |
| Scan host(s) from file | `nmap -iL <input_file>` |
| Save results to file | `nmap <IP_ADDRESS> > <output_file>` |
| Quick scan | `nmap -F <IP_ADDRESS>` |
| Scan alive hosts | `nmap -sn <IP_RANGE>` [^1]|

Other tools:
- [Angry IP Scanner](https://angryip.org/)
- [SoftPerfect Network Scanner](https://www.softperfect.com/products/networkscanner/)

### Scan a Network: Live Host Scan
Preferred tools: nmap, netdiscover

- `nmap`
- [Netdiscover](https://kalilinuxtutorials.com/netdiscover-scan-live-hosts-network/). Works in **active** (default) or **passive** (`-p`) mode. A range can be specified (`-r <CIDR>`). In passive mode nmap can be used to ping hosts and get traffic (e.g. `nmap -sn <CIDR>`).
- [Ettercap](https://linux.die.net/man/8/ettercap), excellent for MitM. Sniff only our connections `ettercap -T -i eth0 -q -p`.
- Bash script, that checks if a host is alive (`hostcheck.sh`)
```bash
#!/bin/bash
host=$1
function pingcheck {
ping=`ping -c 1 $host | grep bytes | wc -l`
if [ "$ping" -gt 1 ];
then
echo "$host is up";
else
echo "$host is down. Quitting";
exit
fi
}
pingcheck
```
- Ruby ping sweep (`pingsweep.rb`)
```ruby
#!/usr/bin/ruby
require 'socket'
s = UDPSocket.new
254.times do |i|
  next if i == 0
  s.send("test", 0, "192.168.0."+i.to_s, 53)
end
f = File.open("/proc/net/arp", "r")
data = f.read.split("\n")
up_hosts = []
data.each do |line|
  entry = line.split(/\s+/)
  next if entry[3] == "00:00:00:00:00:00"
  next if entry[0] == "IP"
  up_hosts << {:ip => entry[0], :mac => entry[3]}
end
print "Active network hosts\n"
print "%-12s\t%s\n" % ["IP Addr", "MAC Address"]
up_hosts.each do |host|
  print "%-12s\t%s\n" % [host[:ip], host[:mac]]
end
```
- Nmap host discovery, great for scanning, not for global nets.
  - Use ARP on local subnets (`nmap -PR 192.168.0.0/24`)
  - ICMP usually blocked
  - Use TCP host discovery (`nmap 192.168.0.0/24 -sn -PA80`)
- [Unicornscan](https://linuxhint.com/unicornscan_beginner_tutorial/), fast scanner that can set the rate and packets per second.
- Use scripts
```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("www.google.com",80))
s.send("GET / HTTP/1.1\nHost: www.google.com\n\n".encode("ascii"))
page = ""
while 1:
    data = s.recv(1024).decode("ascii")
    if data == "":
        break
    page = page + data
```
- Source port scanning, to attempt pass through filtering devices. Some stateless devices filter most origin ports but leave some others open (e.g. SSH, FTP, DNS, HTTP/S). It's worth to try this technique when attempting to trespass it.
  - `nmap -g`
  - `netcat -p`
  - `msfconsole`, `set CPORT`
- [Zmap](https://github.com/zmap/zmap/wiki) to scan a big amount of IPv4 space.
- [MASSCAN](https://github.com/robertdavidgraham/masscan), let's scan the Internet!

### Scan a Network: Port Scan
Preferred tools: nmap

| Scan Type | Command |
| --- | --- |
| Scan a port | `nmap -p [PORT] <IP_ADDRESS>` |
| Scan multiple ports | `nmap -p [PORT1],[PORT2] <IP_ADDRESS>` |
| Scan ALL ports | `nmap -p- <IP_ADDRESS>` [^2] |
| Scan port range | `nmap -p [PORT1-PORT2] <IP_ADDRESS>` |
| Scan most common ports | `nmap --top-ports [NUMBER] <IP_ADDRESS>` |
| Scan specific TCP ports | `nmap -p T:[PORT] <IP_ADDRESS>` |
| Scan all TCP ports | `nmap -sT <IP_ADDRESS>` |
| Scan specific UDP ports | `nmap -p U:[PORT] <IP_ADDRESS>` |
| Scan all UDP ports | `nmap -sU <IP_ADDRESS>` |
| Display only open ports | `nmap --open <IP_ADDRESS>` |

Ports can be in any of the following states:
- **open**, actively responds to an incoming connection
- **closed**, the port responds but doesn't seem to have any service running. Found where there are no firewalls or filtering devices
- **filtered**, ports protected by a firewall or filtering device and nmap can't know if it's open or closed
- **unfiltered**, nmap can access but doesn't know if it's open or closed
- **open|filtered**, nmap thinks it's open or filtered but can't assure the actual state
- **closed|filtered**, nmap thinks it's closed or filtered but can't assure the actual state

### Common port list
| Port Number | Service |
|--- | --- |
| 7 | Echo |
| 20-21 | FTP |
| 22 | SSH/SCP |
| 23 | Telnet |
| 25 | SMTP |
| 43 | WHOIS |
| 53 | DNS |
| 69 | TFTP |
| 79 | Finger |
| 80 | HTTP |
| 88 | Kerberos |
| 109 | POP2 |
| 110 | POP3 |
| 115 | Simple File Transfer Protocol (SFTP) |
| 118 | SQL Services |
| 123 | NTP |
| 135 | MS RPC |
| 137-139 | NetBIOS |
| 143 | IMAP4 |
| 156 | SSQL server |
| 161-162 | SNMP |
| 194 | IRC |
| 443 | HTTP over SSL |
| 464 | Kerberos |
| 465 | SMTP over SSL |
| 512 | rexec |
| 513 | rlogin |
| 514 | syslog |
| 587 | SMTP |
| 631 | Internet Printing |
| 660 | Mac OSX Server |
| 691 | MS Exchange |
| 749-752 | Kerberos |
| 843 | Adobe Flash |
| 873 | rsync |
| 902 | VMware Server |
| 989-990 | FTP OVER SSL |
| 993 | IMAP4 OVER SSL |
| 995 | POP3 OVER SSL |

### Using Metasploit as a scanner

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

# Footnotes

[^1]: in `nmap` both `-sn` and `-sP` mean the same (don't ping). `-sn` is the most recent flag deprecating `-sP`.
[^2]: or `nmap -p "*" <IP_ADDRESS>`
