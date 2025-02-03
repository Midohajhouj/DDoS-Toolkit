## DDoS Toolkit 

A simple and lightweight HTTP Flood DDoS attack tool written in Python3. This tool is designed to simulate a Distributed Denial of Service (DDoS) attack on a target URL by sending multiple HTTP requests, which may overload the server. It is intended **only for educational purposes**. Use this tool responsibly and always have permission from the target server owner.

## 🚨 **Warning: Ethical Use Only**
This tool is designed for **ethical** testing, security research, and educational purposes. Unauthorized use on websites or servers without explicit permission is **illegal** and can result in criminal charges. Always ensure that you have proper authorization before running the tool on any server or website.

---

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)

---

## 📋 Features

- **HTTP Flood Simulation**: Sends multiple HTTP requests to a target URL in quick succession.
- **Multi-threaded Requests**: Distribute the requests across multiple threads to simulate a larger-scale attack.
- **Customizable Parameters**: Adjust the number of threads and pause time between requests.
- **Real-Time Attack Status**: Displays the number of requests sent in real-time.
- **Graceful Shutdown**: Allows users to stop the attack with a `KeyboardInterrupt`.

---

## 🛠️ Installation

To get started with this tool, follow these steps:

### 1. Clone the Repository

First, clone the repository to your local machine:


## git clone https://github.com/Midohajhouj/DDOS
## copy the directory and paste in on /opt/ directory

2. Install the Required Dependencies

Install the necessary Python dependencies listed in the requirements.txt file:

## pip install -r requirements.txt

This will install:

    requests for sending HTTP requests
    colorama for colored output

you may find this error
 error: externally-managed-environment

This environment is externally managed

To install Python packages system-wide, try apt install

python3-xyz, where xyz is the package you are trying to

.......

.......
....

note: If you believe this is a mistake, please contact your Python installation or OS distribution provider. You can override this, at the risk of breaking your Python installation or OS, by passing --break-system-packages.
hint: See PEP 668 for the detailed specification.
 
don't panic

Here’s how you can resolve or work around it:

 Use a Virtual Environment: Create a virtual environment to install packages locally without affecting the system installation. Here's how to do it:

## python3 -m venv myenv

## source myenv/bin/activate

## pip install -r requirements.txt

## deactivate

Once inside the virtual environment, you can install packages as usual with pip.

## chmod +x install.sh

## bash install.sh

## cp the directory to /opt/ if you didnt do it first

3. Python 3.x Requirement

Ensure that you have Python 3.x installed on your machine. You can check the version with:

python --version

⚙️ Usage

Once the setup is complete, you can launch the attack using the following command:

## ddos -u http://example.com 

Command-Line Arguments:

    -u or --url: Required. The target URL (e.g., http://example.com).
    -t or --threads: Optional. The number of threads to use for the attack. Default is 10.
    -p or --pause: Optional. The time in seconds to pause between requests. Default is 0.1 seconds.

Example:

ddos -u http://example.com -t 20 -p 0.5

This command will send requests to http://example.com with 20 threads and a 0.5-second pause between each request.


📞 Contact

If you have any questions or suggestions, feel free to reach out to me:

    Email: midohajhouj11@gmail..com
    GitHub: https://github.com/Midohajhouj

Thank you for using the DDoS Toolkit! Stay ethical, and happy hacking! 💻🎉

---

This README will provide a comprehensive guide for anyone looking to use or contribute to the project.

