<p align="center"> 
  <img src="/test/imgs.jpg"> 
</p>
<p align="center">
  <img src="https://img.shields.io/badge/Platform-Kali Linux-a80505?style=flat-square">
  <img src="https://img.shields.io/badge/License-MIT-a80505?style=flat-square">
  <img src="https://img.shields.io/github/v/release/Midohajhouj/DDoS-Toolkit?label=Version&color=a80505">
  <img src="https://img.shields.io/badge/Open%20Source-Yes-darkviolet?style=flat-square&color=a80505">
  <img src="https://img.shields.io/github/languages/top/Midohajhouj/DDoS-Toolkit?color=a80505">
</p>

**DDoS Toolkit is a powerful and customizable tool designed for ethical cybersecurity testing and research. It enables users to simulate a wide range of Distributed Denial of Service (DDoS) attacks and includes additional modules for network scanning, anonymization, and Wi-Fi deauthentication.**                                                                                               
**This tool is designed to work on Kali Linux or any other distribution with a full Python 3 library support.**

> 🚨 **Note: The author is not responsible for any misuse of this tool. Use it responsibly for educational and testing purposes.**

> 🚨 **Note: The tool's configuration relies on the directory path `/opt/DDoS-Toolkit/`. Ensure proper installation 👇👇 .**

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
`aiohttp`, `asyncio`, `scapy`, `colorama`, `tqdm`, `psutil`, `dnspython`, `hashlib`, `zlib`.  

**System Requirements**:  
- Python 3.x  
- Internet access for proxy validation and AI suggestions  

--- 

## **🛠️ Installation** 
### **Clone the Repository**
```bash
sudo git clone https://github.com/Midohajhouj/DDoS-Toolkit.git /opt/DDoS-Toolkit
```
```bash
cd /opt/DDoS-Toolkit
```
```bash
sudo chmod +x *
```
```bash
sudo ./setup install
```

### **Build Debian Package (Optional for Debian-based Distros)**
```bash
cd builder
```
```bash
chmod +x builder.sh
```
```bash
sudo ./builder.sh
```
```bash
sudo dpkg -i ddos-toolkit.deb
```

### **If you encounter an error related to missing modules or dependencies, you can install each one individually. For example:**
```bash
pip install <module_name>
```

**For example, if the error is:**

```
ModuleNotFoundError: No module named 'aiohttp'
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
HTTP flood attack:
```bash
ddos -u 192.168.48.165 -t 20 -p 0.1 -d 300
```

SYN flood attack:
```bash
ddos -u 192.168.48.165 --attack-mode syn-flood -d 60
```

---

## **🌟 Extensions**

### 1. **Network Scanner (`netscan`)**
This extension provides advanced network analysis and vulnerability assessment capabilities.

#### Features:
- **Port Scanning**: Identify open TCP and UDP ports on target systems.
- **DDoS Vulnerability Detection**: Check for amplification vulnerabilities on common ports (e.g., DNS, NTP, SNMP).
- **Firewall Detection**: Detect the presence of firewalls using ICMP pings.
- **CVE Assessment**: Match open services to known CVEs for detailed risk analysis.
- **Report Generation**: Create JSON and HTML reports of scan results.
- **External Tool Integration**: Run Nmap, Metasploit, or Shodan scans directly from the tool.

#### Usage:
```bash
ddos -u 192.168.48.165 -s
```

---

### 2. **Wi-Fi Deauthentication Tool (`wifideauth`)**
This tool provides comprehensive Wi-Fi network management and attack functionalities for cybersecurity testing.

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
A script to ensure complete anonymity during attacks by routing traffic through the Tor network.

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

<p align="center"> Developed by <a href="https://github.com/Midohajhouj">MIDO</a> </p>
