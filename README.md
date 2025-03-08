# 💥 DDoS Toolkit

## Description
DDoS Toolkit is a powerful and customizable tool designed to simulate various types of Distributed Denial of Service (DDoS) attacks, including HTTP Flood, Slowloris, UDP Flood, and SYN Flood. It offers features like rate-limited attacks, proxy support, custom payload generation, and system resource monitoring, making it suitable for testing and research purposes in ethical cybersecurity simulations.

> 🚨 **Note:** The author is not responsible for any misuse of this tool. Use at your own risk.

---

## Table of Contents

- [Features](##features)
- [Installation](##installation)
- [Usage](##usage)
- [Contact](##contact)

---

## 📋 Features
- **Multiple Attack Modes:** Supports HTTP Flood, Slowloris, UDP Flood, and SYN Flood.
- **Rate-Limited Attacks:** Customize the rate of requests sent to the target.
- **Proxy Support:** Use proxies to mask your requests and make attacks more efficient.
- **Custom Payloads:** Generate various types of payloads such as JSON, XML, and Form data.
- **AI-Powered Suggestions:** Use OpenAI GPT to optimize attack parameters.
- **Real-time Monitoring:** Track system resource usage and attack progress.

## Requirements

### Python Libraries
- aiohttp
- asyncio
- argparse
- threading
- scapy
- psutil
- colorama
- tqdm
- openai
- dns.resolver
- hashlib
- zlib

### System Requirements
- Python 3.x
- Internet access for proxy validation and AI suggestions

## 🛠️ Installation

### 1. Clone the repository:
```bash
git clone https://github.com/Midohajhouj/DDoS-Toolkit.git
cd DDoS-Toolkit
chmod +x *
```

### 2. Install dependencies:
```bash
pip install -r requirements.txt
```
or
```bash
./install.sh
```

### 3. Set up OpenAI API key:
Create a file `.env` and add your OpenAI API key:
```
OPENAI_API_KEY=your_openai_api_key_here
```

## ⚙️ Usage

### Basic Attack
To perform a basic attack with default settings:
```bash
ddos -u https://google.com/
```

### Command-Line Arguments:
- `-u, --url`: Target URL or IP address (required)
- `-t, --threads`: Number of threads (default: 10)
- `-p, --pause`: Pause time between requests (default: 0.1 seconds)
- `-d, --duration`: Duration of the attack in seconds (default: 1500)
- `--proxies`: Proxy list file (optional)
- `--headers`: Custom headers as JSON string (optional)
- `--payload`: Payload type (`json`, `xml`, `form`), default is `json`
- `--rate-limit`: Rate limit for requests per second (default: 100)
- `--attack-mode`: Type of attack (`http-flood`, `slowloris`, `udp-flood`, `syn-flood`), default is `http-flood`
- `--proxy-auth`: Proxy authentication (username:password), optional
- `--retry`: Number of retries for failed requests (default: 3)
- `--user-agents`: Custom user-agent list file (optional)

### Example Usage:
1. Perform an HTTP flood attack with 20 threads, 0.1s pause time, and for 300 seconds:
```bash
ddos -u http://192.168.48.165/ -t 20 -p 0.1 -d 300
```

2. Perform a SYN flood attack on IP `192.168.48.165` for 60 seconds:
```bash
ddos -u 192.168.48.165 --attack-mode syn-flood -d 60
```

3. Use proxies for the attack:
```bash
ddos -u http://192.168.48.165 --proxies proxies.txt
```

4. Save attack results to a JSON file:
```bash
ddos -u http://192.168.48.165 --results attack_results.json
```

## Example Output
```bash
Starting attack on http://192.168.48.165...
Requests Sent: 100 | Successful: 98 | Failed: 2 | RPS: 50.00 | CPU: 45% | Memory: 32%
```

## Contributing

Contributions are welcome! If you have suggestions or improvements, feel free to open an issue or submit a pull request.

## License
This project is licensed under the MIT License.

## Disclaimer
This tool is intended for educational purposes only. The author is not responsible for any misuse or illegal activity. Use this tool responsibly and with permission.
