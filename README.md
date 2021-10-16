
# Attack Defense Analysis of a Vulnerable Network
This document contains the following details: 

- Network Topology 
-  Critical Vulnerabilities 
- Traffic Profile
- Normal Activity 
- Malicious Activity 


## Description of the Topology
This repository includes code defining the infrastructure below. 

![](https://github.com/ActualSalt/Attack-Defense-Analysis-of-a-Vulnerable-Network/blob/main/images/network_topology.png?raw=true)
| Name     |   Function  | IP Address | Operating System |
|----------|-------------|------------|------------------|
| HYPER-V |   VM Host   | 192.168.1.1   | Windows            |
| Attacker    | Attacker VM  | 192.168.1.90  | Kali             |
| Target 1   | Web Server  | 192.168.1.110  | Linux            |
| Target 2   | Web Server  | 192.168.1.115  | Linux            |
| ELK      | Monitoring  | 192.168.1.100   | Linux            |

## Critical Vulnerabilities
| Vulnerability   |   Description  |  Impact |
|----------|-------------|------------------|
| 22/TCP SSH |  CVE-2018-6082 CVSS= 4.3    |    System is vulnerable to brute force and dictionary attacks. |
| 80/TCP HTTP |   CVE-2019-6579 CVSS= 9.8   |  An attacker can execute system commands with administrative privileges.   |
| 111/TCP rpcbind |   CVE-2017-8779 CVSS= 7.8   | Vulnerability disrupts memory allocation which can allow a remote attacker to cause a denial of service, aka. rpcbomb.    |
| 139/TCP netbios-sn |   CVE-2017-0143 NIST= 8.1   |   Windows remote code execution vulnerability. Allows a remote attacker to execute code.  |
| 445/TCP microsoft-ds |   CVE-2020-0796 NIST= 10.0   |  An attacker who successfully exploits the SMBv3 protocol can gain access to a system to execute code.   |
| Simple passwords |   Lack of complexity in passwords. No 2-Factor Authentication at login   |  Simple passwords like first and last names can be easily guessed or cracked using a tool like john by a hacker. In addition, 2-Factor Authentication was missing at login for the user’s Michael and Steven.   |
| Root accessibility |   Sudoer privileges for non-administrative users   |   Steven had sudoer privileges that allows an attacker to gain root access by exploiting the binary program python.  |

## Traffic Profile 
| Feature   |   Value  |  Description |
|----------|-------------|------------------|
|Top Talkers (IP Addresses) | 172.16.4.205 <br> 10.0.0.201 <br>166.62.111.64 <br>185.243.115.84 | Machines that sent the most traffic  | 
|Most Common Protocols | TLS<br>DNS<br>HTTP |Three most common protocols on the network| 
|# of of Unique IP Addresses | 810 | Count of observed IP addreses |
|Subnets| 10.0.0.0/24, 10.6.12.0/24, 10.11.11.0/24, 172.16.4.0/24 172.217.0.0/16, 192.168.1.0/24 | Observed subnet ranges |
|# of Malware Species | 1, june11.dll was discovered as trojan | Number of malware binaries identified in traffic|

### Normal Activity 
- Web browsing 
	- HTTP protocols 
	- No downloads 

### Malicious Activity 
