DDoS Toolkit

A simple and lightweight HTTP Flood DDoS attack tool written in Python3. This tool is designed to simulate a Distributed Denial of Service (DDoS) attack by sending multiple HTTP requests to a target URL, potentially overloading the server. This tool is for educational and ethical purposes only. Use it responsibly and only with explicit permission from the target server owner.

🚨 Ethical Use Only

This tool is intended strictly for:

Ethical testing of server resilience.

Security research and vulnerability assessments.

Educational purposes to understand DDoS attack mechanics.

Unauthorized use on websites or servers without explicit permission is illegal and may result in severe legal consequences. Always obtain proper authorization before running this tool.

Table of Contents

Features

Installation

Usage

Examples

Contact

📋 Features

HTTP Flood Simulation: Sends multiple HTTP requests to a target URL in quick succession.

Multi-threaded Requests: Distributes requests across multiple threads to simulate larger-scale attacks.

Customizable Parameters: Adjust thread count and pause time between requests.

Real-Time Status: Displays the number of requests sent in real-time.

Graceful Shutdown: Allows stopping the attack with a KeyboardInterrupt (Ctrl+C).

🛠️ Installation

1. Clone the Repository

Clone the repository to your local machine:

git clone https://github.com/Midohajhouj/DDOS

If not already done, copy the directory to /opt/:

sudo cp -r DDOS /opt/

2. Install Dependencies

Install the required Python dependencies listed in the requirements.txt file:

pip install -r requirements.txt

If you encounter the error:

error: externally-managed-environment

It means your Python environment is managed externally. To resolve this:

Use a Virtual Environment:

python3 -m venv myenv
source myenv/bin/activate
pip install -r requirements.txt
deactivate

This ensures package installation does not interfere with your system.

Alternatively, override the restriction (not recommended):

pip install -r requirements.txt --break-system-packages

3. Set Permissions and Install

Make the installation script executable and run it:

chmod +x install.sh
bash install.sh

4. Verify Python Installation

Ensure Python 3.x is installed:

python3 --version

⚙️ Usage

After completing the setup, run the tool using:

ddos -u <TARGET_URL>

Command-Line Arguments

-u or --url (required): Target URL (e.g., http://example.com).

-t or --threads (optional): Number of threads to use. Default is 10.

-p or --pause (optional): Pause time (in seconds) between requests. Default is 0.1 seconds.

Example

Send requests to http://example.com using 20 threads with a 0.5-second pause:

ddos -u http://example.com -t 20 -p 0.5

📞 Contact

For questions, suggestions, or contributions, feel free to reach out:

Email: midohajhouj11@gmail.com

GitHub: Midohajhouj

Thank you for using the DDoS Toolkit! Stay ethical and responsible. 💻🎉


