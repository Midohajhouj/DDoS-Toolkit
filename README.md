DDoS Toolkit

A simple and lightweight HTTP Flood DDoS attack tool written in Python. This tool is designed to simulate a Distributed Denial of Service (DDoS) attack on a target URL by sending multiple HTTP requests, which may overload the server. It is intended **only for educational purposes**. Use this tool responsibly and always have permission from the target server owner.

## 🚨 **Warning: Ethical Use Only**
This tool is designed for **ethical** testing, security research, and educational purposes. Unauthorized use on websites or servers without explicit permission is **illegal** and can result in criminal charges. Always ensure that you have proper authorization before running the tool on any server or website.

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

```bash
git clone https://github.com/yourusername/ddos-toolkit.git
cd ddos-toolkit

2. Install the Required Dependencies

Install the necessary Python dependencies listed in the requirements.txt file:

pip install -r requirements.txt

This will install:

    requests for sending HTTP requests
    colorama for colored output

3. Python 3.x Requirement

Ensure that you have Python 3.x installed on your machine. You can check the version with:

python --version

⚙️ Usage

Once the setup is complete, you can launch the attack using the following command:

python3 ddos.py -u http://example.com 

Command-Line Arguments:

    -u or --url: Required. The target URL (e.g., http://example.com).
    -t or --threads: Optional. The number of threads to use for the attack. Default is 10.
    -p or --pause: Optional. The time in seconds to pause between requests. Default is 0.1 seconds.

Example:

python3 attack_script.py -u http://example.com -t 20 -p 0.5

This command will send requests to http://example.com with 20 threads and a 0.5-second pause between each request.
💻 Example Usage Script

If you want to automate the attack or integrate it into a larger project, you can use the following example shell script to run the attack:

# example_attack.txt

#!/bin/bash

URL="http://example.com"
THREADS=20
PAUSE_TIME=0.1

python3 ddos.py -u $URL -t $THREADS -p $PAUSE_TIME

📊 Real-Time Status Reporting

While the attack is running, the script will show the number of requests sent in real-time. The status will be updated every second and displayed on the console.

Example output:

Requests Sent: 1000
Requests Sent: 2000
Requests Sent: 3000

🧪 Testing the Tool

If you'd like to contribute or test the functionality of this tool, unit tests are available for certain functions like the attack process and utility methods. You can find these tests in the tests/ directory.

To run the tests:

python3 -m unittest discover tests/

📄 License

This project is licensed under the MIT License. See the LICENSE file for details.
🤝 Contributing

We welcome contributions! If you'd like to contribute to this project, feel free to open an issue or a pull request. Make sure to follow the guidelines below:

    Fork the repository.
    Create a new branch.
    Commit your changes.
    Open a pull request with a description of what you've changed.

📞 Contact

If you have any questions or suggestions, feel free to reach out to me:

    Email: midohajhouj11@gmail..com
    GitHub: MIDO

Thank you for using the DDoS Toolkit! Stay ethical, and happy hacking! 💻🎉


---

### Key Points of the README:

1. **Clear Explanation**: It explains the purpose of the tool and the ethical usage warnings.
2. **Installation Instructions**: It includes step-by-step instructions to set up the project locally.
3. **Command-Line Usage**: It explains the command-line arguments for launching the attack.
4. **Real-Time Status**: Describes how the real-time status is displayed during the attack.
5. **Test Instructions**: Mentions how to run tests for validating the tool’s functions.
6. **Contributing Guidelines**: Invites contributions and provides simple guidelines.
7. **License**: Specifies that the tool is under the MIT License.

This README will provide a comprehensive guide for anyone looking to use or contribute to the project.

