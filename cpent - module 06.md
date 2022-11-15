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
Metasploit can scan networks or can import results from nmap. This is useful to improve our hosts DB.

We can obtain help on Metasploit commands either by executing `help [command]` or `[command] -h`.

#### Prepare Database
| Command | Description |
| --- | --- |
| `systemctl start postgresql` | Start the database |
| `msfdb init` | Initializes the DB |
| `msfdb status` | Checks if connected |

#### Metasploit Database Commands
All commands to be executed within `msfconsole`.

| Command | Description |
| --- | --- |
| `db_connect` | To interact with other DBs than the default one |
| `db_export` | Exports the DB to create reports or as input to another tool |
| `db_nmap` | Executes `nmap` and stores the result in Metasploit's DB |
| `db_status` | Checks DB connection |
| `db_import` | Imports scan results from `nmap`, `nessus`, etc. Requires an XML formatted scan output |

#### Managing Workspaces
Workspaces gives us the ability to save scan results per subnet/location/networks. All commands executed within `msfconsole`.

| Command | Description |
| --- | --- |
| `help workspace` | Prints `workspace`'s command help |
| `workspace -a [NANE]` | Creates \[NAME\] workspace and activates it |
| `workspace [NAME]` | Activates \[NAME\] workspace |
| `workspace -d [NAME]` | Deletes \[NAME\] workspace |

#### Gathering Data
| Command | Description |
| --- | --- |
| `db_nmap` | Executes `nmap` and stores the result in Metasploit's DB |
| `db_import` | Imports scan results from `nmap`, `nessus`, etc. Requires an XML formatted scan output |

#### Store and Review the Results
| Command | Description |
| --- | --- |
| `hosts -h` | Displays help for the `hosts` command |
| `hosts` | Displays target information |
| `db_export` | Exports the DB (as XML or pwdump) to create reports or as input to another tool |

#### Setting Up Modules
We can leverage the data in the DB to set up module's configurations.

For example, to leverage the hosts found to make a TCP scan:
```
msf 6 > use auxiliary/scanner/portscan/tcp # using the TCP scanner
msf 6 > hosts -c address -R  # -R imports the target data into the module
msf 6 > run  # executes the scan and stores results in the database
```

## OS and Service Fingerprinting
Preferred tools: nmap, ping, wireshark, p0f
Identifying the operating system running the target host.

### Using TTL
This is a quick (but not reliable) way to identify an OS running on a target host. Different OSs use different TTLs. We can use `ping`, `wireshark`, etc and look for the TTL value to determine the OS.

**Sample of TTL values**
![Sample TTL Values](images/ttl_values.png)

### Identify the OS
We can use `p0f` as one of its outputs is the OS being used:

```
$ sudo p0f -i any -p -o /tmp/sniff.log
...
.-[ 1.2.3.4/1524 -> 4.3.2.1/80 (syn) ]-
|
| client   = 1.2.3.4
| os       = Windows XP
| dist     = 8
| params   = none
| raw_sig  = 4:120+8:0:1452:65535,0:mss,nop,nop,sok:df,id+:0
|
`----
...
```

We can also use `nmap`.

| Scan Type | Command |
| --- | --- |
| Identify OS on targer machine | `nmap -O <IP_ADDRESS>` |
| Enables OS version detection | `nmap -sV -O -v <IP_ADDRESS>` |
| OS detection + script run | `nmap -A -T4 -v <IP_ADDRESS>` |
| Limits OS detection to promising targets | `nmap -O -Pn --osscan-limit <IP_RANGE>` |
| Aggressively guess OS detection | `--osscan-guess` or equivalent `--fuzzy` |
| Set maximum number of retries (default 5) to guess the OS | `--max-os-tries [NUMBER]` |
| SMB OS discovery | `nmap --script smb-os-discovery.nse --script-args=unsafe=1 -p 445 <IP_ADDRESS>` |

#### Manual Banner Grabbing
Connecting manually to the port and observe the response.

**Netcat or Telnet**
```bash
$ nc -vn <IP_ADDRESS> <PORT>
<SERVICE BANNER>
```

**Using dmitry**
```bash
$ dmitry -pb <IP_ADDRESS>
...
<SERVICE BANNER>
```

**Using Python**
```python
#!/usr/bin/env python
import socket
import sys
host=sys.argv[1]
ua="Mozilla/5.0"
bangrab = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
bangrab.connect((host, 80))
data = "HEAD / HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\n\r\n".format(host,ua).encode('ascii')
bangrab.send(data)
r = bangrab.recv(500)
print(r.decode('ascii'))
bangrab.close()
```

**Using Ruby**
```ruby
#!/usr/bin/env ruby
require 'socket'
host=ARGV[0]
ua="Mozilla/5.0"
data="HEAD / HTTP/1.1\r\nHost:#{host}\r\nUser-Agent:#{ua}\r\n\r\n"
a=TCPSocket.open(host, 80)
a.puts(data)
puts a.recv(500)
a.close
```
### Identify the Services
Preferred tools: nmap, svmap, Metasploit

| Scan Type | Command |
|--- | --- |
| Identify services | `nmap -sV <IP_ADDRESS>` |
| Services running on open ports | `nmap -T4 -A -v <IP_ADDRESS>` |
| Identify IPSec devices | `nmap -sU -p 500 <IP_ADDRESS>` |
| Identify VoIP devices | `svmap <IP_RANGE>` |
| SSH fingerprinting | Metasploit. Run `search ssh_version` and then use a found module. |

| Metasploit Instruction | Command |
| --- | --- |
| Display service details from the DB | `services` |
| Display services data | `services -c port,proto,created_at <IP_ADDRESS>` |
| Services Port State | `services -c port,proto,state -p 1-300` |

### Map the Internal Network
Mapping the internal network is very useful. Tools you can use:
- [Network Topology Mapper](https://www.solarwinds.com/network-topology-mapper)
- [NetSurveyor](https://nutsaboutnets.com/archives/netsurveyor-wifi-scanner/)

## Enumeration
The process of extracting as much useful data as possible (usernames, IP tables, macine names, DNS details, services running, etc.) from a system or network. This will allow us to identify system attack points and perform password attacks to gain unauthorized access to systems.

### Perform Service Enumeration
- [SuperScan](https://www.softpedia.com/get/Network-Tools/Network-IP-Scanner/SuperScan.shtml), multi-functional application designed as a TCP port scanner, pinger and address resolver. Performs ping sweeps, Windows Enumeration, Host and Service discovery, etc.
- [Winfingerprint](https://www.softpedia.com/get/Security/Security-Related/winfingerprint.shtml), enables security administrators to scan a range of IP addresses and retrieve useful information on the remote hosts, such as patch level. WinFingerprint is able to send the Ping and Traceroute signals to the hosts, show an event log and errors, and more. Results include the computer name, Ping reply time, SID, MAC address, patch level, NetBIOS shares, and services.

### Enumeration Techniques and Tools
| Technique | Information Obtained | Tools |
| --- | --- | --- |
| NetBIOS enumeration | <ul><li>list of computers</li><li>list of shares</li><li>policies and passwords</li></ul> | <ul><li>nbtstat</li><li>SuperScan</li><li>Hyena</li><li>Winfingerprint</li></ul> |

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
