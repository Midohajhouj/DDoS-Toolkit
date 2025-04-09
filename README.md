<p align="center"> 
  <img src="/test/banner.jpg"> 
</p>
<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-a80505?style=plastic">
  <img src="https://img.shields.io/badge/License-MIT-a80505?style=plastic">
  <img src="https://img.shields.io/github/v/release/Midohajhouj/DDoS-Toolkit?label=Version&color=a80505&style=plastic">
  <img src="https://img.shields.io/badge/Open%20Source-Yes-darkviolet?style=plastic&color=a80505">

**DDoS Toolkit is a powerful and customizable tool designed for ethical cybersecurity testing and research. It enables users to simulate a wide range of Distributed Denial of Service (DDoS) attacks and includes additional modules for network scanning, anonymization, and Wi-Fi deauthentication.**                                                                                               

> 🚨 **Note: The author is not responsible for any misuse of this tool. Use it responsibly for educational and testing purposes.**
 
> 🚨 **Note: I use a single versioning technique. I upgrade the source code while maintaining the same version number.**

> 🚨 **Note: The tool's configuration relies on the directory path `/opt/DDoS-Toolkit/`, Ensure proper installation below.**

# **Table of Contents**

- [Features](#Features)
- [Dependencies](#Dependencies)                                                         
- [Installation](#Installation)    
- [Usage](#Usage)
- [Extensions](#Extensions)
- [Contributing](#Contributing)
 
---

## **📋 Features**

- **Multiple Attack Modes**: HTTP/HTTP2 Flood, Slowloris, UDP Flood, SYN Flood, SSH Flood, SSL Flood, FTP Flood, and more.
- **Rate-Limited Attacks**: Customize request rates for precision testing.
- **Proxy Support**: Efficient and masked attacks via proxy lists.
- **Custom Payloads**: JSON, XML, and Form data payload options.
- **Real-time Monitoring**: Track attack progress and resource usage.
- **Interactive Mode**: Simplified usage with an interactive CLI.
- **Integrated Modules**: Network scanning, anonymization, and Wi-Fi deauthentication tools.

---

## **🔌 Dependencies**
**Python Libraries**:  
`aiohttp`, `asyncio`, `scapy`, `colorama`, `tqdm`, `psutil`, `dnspython`, `hashlib`, `zlib`, `concurrent-log-handler`, `requests`
`tabulate`.

**System Requirements**:  
- Python 3.x  
- Internet access.
- A distro with full Python 3 library support (Debian-based Distro recommended)
- Few basic pentesting tools like `Nmap`, `Aircrak-ng`, `Tor`. (optional for extensions modules, the tool main foncunality will work with out them.)
- A minimum of an i3 processor and 4 GB of RAM.

--- 

## **🛠️ Installation** 
### **Clone the Repository**
```bash
sudo git clone https://github.com/Midohajhouj/DDoS-Toolkit.git 
```
```bash
cd DDoS-Toolkit
```
```bash
sudo chmod +x *
```
```bash
sudo ./setup.sh
```

### **I have added a built-in script error handler for errors related to missing modules For example:**
**If the error is:**
```
ModuleNotFoundError: No module named 'aiohttp' Install it using: pip install aiohttp --break-system-packages
```

**You can resolve it by running:**

```bash
pip install aiohttp --break-system-packages
```

---

## **⚙️ Usage**

### **Basic Attack**
```bash
sudo ddos -u 192.168.48.165 
```

### **Command-Line Arguments**
- **`-u, --url`**: Target URL/IP (required).
- **`-t, --threads`**: Number of threads (default: 10).
- **`-p, --pause`**: Pause time between requests (default: 0.1 seconds).
- **`-d, --duration`**: Duration of attack in seconds (default: 1500).
- **`--proxies`**: Proxy list file (optional).
- **`--rate-limit`**: Requests per second (default: 100).
- **`--attack-mode`**: Attack type (`http-flood`, `syn-flood`, etc., default is `http-flood`).
- **`--results`**: Save attack results to JSON (optional).

### **Examples**

Costumizable HTTP flood attack:
```bash
ddos -u 192.168.48.165 -t 20 -p 0.1 -d 300
```

SYN flood attack:
```bash
ddos -u 192.168.48.165 -a syn-flood
```

SSH flood attack:
```bash
ddos -u 192.168.48.165 -a ssh-flood
```

FTP flood attack:
```bash
ddos -u 192.168.48.165 -a ftp-flood
```

---

## **🌟 Extensions**

### 1. **Network Scanner (`netscan`)**
This extension provides advanced network analysis and vulnerability assessment capabilities. (Nmap optional)
#### Features:
- **Port Scanning**: Identify open TCP and UDP ports on target systems.
- **DDoS Vulnerability Detection**: Check for amplification vulnerabilities on common ports (e.g., DNS, NTP, SNMP).
- **Firewall Detection**: Detect the presence of firewalls using ICMP pings.
- **CVE Assessment**: Match open services to known CVEs for detailed risk analysis.
- **Report Generation**: Create JSON and HTML reports of scan results.
- **External Tool Integration**: Run Nmap, or Shodan scans directly from the tool.

#### Usage:
```bash
ddos -u 192.168.48.165 -s
```

---

### 2. **Wi-Fi Deauthentication Tool (`wifideauth`)**
This tool provides comprehensive Wi-Fi network management and attack functionalities for cybersecurity testing. (Aircrak-ng optional)

#### Features:
- **Wi-Fi Network Scanning**: Detect nearby networks with details like SSID, BSSID, channel, and signal strength.
- **Deauthentication Attacks**: Disconnect devices from networks using aireplay-ng or scapy.
- **MAC Address Spoofing**: Change the attacker's MAC address to avoid detection.

#### Usage:
```bash
ddos --wifi-deauth
```

---

### 3. **Anonymizer (`anonymizer`)**
A script to ensure complete anonymity during attacks by routing traffic through the Tor network. (Required Tor)

#### Features:
- **Tor Integration**: Redirect all network traffic through Tor for anonymity.
- **DNS Leak Protection**: Prevent DNS queries from bypassing Tor.
- **VPN Compatibility**: Combine with VPNs for added security.

#### Usage:
```bash
ddos --anonymizer start
```

---

## **🤝 Contributing**
Contributions are welcome! Submit an issue or pull request to improve the toolkit.  

**<p align="center"> Developed by <a href="https://github.com/Midohajhouj">LIONMAD</a> </p>**
