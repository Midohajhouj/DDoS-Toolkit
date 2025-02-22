# 💥 DDoS Toolkit

HTTP Flood DDoS attack tool written in Python3. This tool is designed to simulate a Distributed Denial of Service (DDoS) attack by sending multiple HTTP requests to a target URL, potentially overloading the server. This tool is for educational and ethical purposes only. Use it responsibly and only with explicit permission from the target server owner.

---

## 🚨 **Ethical Use Only**

This tool is intended strictly for:

- Ethical testing of server resilience.
- Security research and vulnerability assessments.
- Educational purposes to understand load testing mechanics.

Unauthorized use on websites or servers without explicit permission is illegal and may result in severe legal consequences. Always obtain proper authorization before running this tool.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Contact](#contact)

---
 
## 📋 Features

- **HTTP Load Simulation:** Sends multiple HTTP requests to a target URL in quick succession.
- **Multi-threaded Requests:** Distributes requests across multiple threads to simulate larger-scale attacks.
- **Customizable Parameters:** Adjust thread count, pause time between requests, and duration of the test.
- **Proxy Support:** Load testing using proxies to distribute the traffic and prevent IP blocking.
- **Real-Time Status:** Displays the number of requests sent in real-time, including successful and failed requests.
- **Graceful Shutdown:** Allows stopping the test gracefully with a KeyboardInterrupt (Ctrl+C).
- **CSV Results:** Option to save results to a CSV file for later analysis.

---

## 🛠️ Installation

### Clone the Repository

Clone the repository to your local machine:

git clone https://github.com/Midohajhouj/DDoS-Toolkit.git

cd DDoS-Toolkit


chmod +x install.sh


./install.sh 


### Debian based distro 


### download the release 


### dpkg -i ddos-toolkit.deb


---


## ⚙️ Usage

After completing the setup, run the tool using:

ddos -u (http://example.com )

Command-Line Arguments

    -u or --url (required): Target URL (e.g., http://example.com).
    -t or --threads (optional): Number of threads to use. Default is 10.
    -p or --pause (optional): Pause time (in seconds) between requests. Default is 0.1 seconds.
    -d or --duration (optional): Duration of the test in seconds. Default is 999999 seconds.
    --proxies (optional): File containing a list of proxy servers.
    --headers (optional): Custom headers in JSON format.
    --payload (optional): Type of payload (json, xml, or form). Default is "json".
    --results (optional): File to save results (CSV).
    -l or --logfile (optional): Log file to store log output.
    -v or --verbose (optional): Enable verbose logging.

Example

Send requests to http://example.com using 20 threads, with a 0.5-second pause between requests, for a duration of 120 seconds:

ddos -u http://example.com -t 20 -p 0.5 -d 120

---

## 📞 Contact

For questions, suggestions, or contributions, feel free to reach out:

Email: midohajhouj11@gmail.com

Thank you for using the DDoS Toolkit! Stay ethical and responsible..

---

#### *<p align="center"> Coded by <a href="https://github.com/Midohajhouj">MIDO777</a> </p>*


