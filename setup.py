#!/usr/bin/env python3
# -*- coding: utf-8 -*-
### BEGIN INIT INFO
# Provides:          ddos_toolkit_installer
# Required-Start:    $network $remote_fs
# Required-Stop:     $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: DDoS Attack Toolkit
# Description:       A toolkit designed for simulating various types of Distributed Denial of Service (DDoS) attacks for ethical cybersecurity testing.
# Author:
# + LIONMAD <https://github.com/Midohajhouj>
# License:           MIT License - https://opensource.org/licenses/MIT
## END INIT INFO #

import os
import sys
import subprocess
import logging
from setuptools import setup, find_packages
from setuptools.command.install import install

# Colors for stylish output
YELLOW = "\033[1;33m"
GREEN = "\033[1;32m"
BLUE = "\033[1;34m"
RED = "\033[1;31m"
RESET = "\033[0m"  # Reset color

# Logging configuration
PIP_LOG = "pip_install.log"
logging.basicConfig(filename=PIP_LOG, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def display_banner():
    """Display a stylish banner."""
    print(f"{BLUE}")
    print("██████████████████████████████████████████████████")
    print("██                                              ██")
    print("██         DDoS Toolkit Coded by MIDO           ██")
    print("██                Setup Script                  ██")
    print("██       This script sets up the environment    ██")
    print("██           for running the DDoS Toolkit       ██")
    print("██                                              ██")
    print("██████████████████████████████████████████████████")
    print(f"{RESET}")

def install_system_dependencies():
    """Install system dependencies using apt-get."""
    print(f"{GREEN}[INFO]{RESET} Updating package list...")
    try:
        subprocess.run(["apt-get", "update", "-y"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"{RED}[ERROR]{RESET} Failed to update package list: {e}")
        sys.exit(1)

    print(f"{GREEN}[INFO]{RESET} Installing required system packages...")
    try:
        subprocess.run(
            ["apt-get", "install", "-y", "python3", "python3-pip", "python3-venv", "libssl-dev", "libffi-dev", "build-essential"],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"{RED}[ERROR]{RESET} Failed to install system packages: {e}")
        sys.exit(1)

def install_python_packages():
    """Install required Python packages and log the output."""
    print(f"{GREEN}[INFO]{RESET} Installing required Python packages (output logged to {PIP_LOG})...")
    packages = [
        "aiohttp==3.8.1",
        "asyncio==3.4.3",
        "dnspython==2.1.0",
        "openai==0.27.0",
        "psutil==5.8.0",
        "requests==2.28.2",
        "scapy==2.4.5",
        "tabulate==0.9.0",
        "tqdm==4.64.1",
        "colorama",
    ]

    for package in packages:
        try:
            subprocess.run(
                ["pip", "install", "--break-system-packages", package],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            logging.info(f"Successfully installed {package}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to install {package}: {e.stderr.decode()}")
            print(f"{RED}[ERROR]{RESET} Failed to install {package}. Check {PIP_LOG} for details.")
            sys.exit(1)

def create_symlink():
    """Create a symlink for easy access to the DDoS Toolkit."""
    print(f"{YELLOW}[*]{RESET} Creating symlink for easy access...")

    # Check if the source file exists
    if not os.path.isfile("ddos.py"):
        print(f"{RED}[ERROR]{RESET} ddos.py not found in the current directory.")
        sys.exit(1)

    # Remove existing symlink if present
    if os.path.exists("/usr/local/bin/ddos"):
        print(f"{YELLOW}[INFO]{RESET} Removing existing symlink...")
        try:
            subprocess.run(["sudo", "rm", "/usr/local/bin/ddos"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"{RED}[ERROR]{RESET} Failed to remove existing symlink: {e}")
            sys.exit(1)

    # Create a new symlink
    try:
        subprocess.run(["sudo", "cp", "ddos.py", "/usr/local/bin/ddos"], check=True)
        subprocess.run(["sudo", "chmod", "+x", "/usr/local/bin/ddos"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"{RED}[ERROR]{RESET} Failed to create symlink: {e}")
        sys.exit(1)

    # Verify symlink creation
    if os.path.exists("/usr/local/bin/ddos"):
        print(f"{GREEN}[SUCCESS]{RESET} Symlink created! You can now run 'ddos' from anywhere.")
    else:
        print(f"{RED}[ERROR]{RESET} Symlink creation failed.")
        sys.exit(1)

class CustomInstall(install):
    """Custom installation class to handle system dependencies and symlink creation."""

    def run(self):
        """Run the custom installation process."""
        display_banner()

        # Ensure the script is being run as root or with sudo
        if os.geteuid() != 0:
            print(f"{RED}[ERROR]{RESET} This script must be run as root or with sudo.")
            sys.exit(1)

        # Install system dependencies
        install_system_dependencies()

        # Install Python packages
        install_python_packages()

        # Create a symlink for easy access
        create_symlink()

        # Completion message
        print(f"{GREEN}[INFO]{RESET} Setup complete! The necessary packages have been installed system-wide.")
        print(f"{BLUE}You can now run the DDoS Toolkit script directly using:{RESET}")
        print(f"{GREEN}ddos{RESET}")

        print(f"{BLUE}")
        print("████████████████████████████████████████████████████")
        print("██                                                ██")
        print("██               Setup is complete                ██")
        print("██                 MIDØ SALUTES YOU               ██")
        print("██                                                ██")
        print("████████████████████████████████████████████████████")
        print(f"{RESET}")

# Define the setup configuration
setup(
    name="ddos_toolkit",
    version="1.0",
    author="MIDØ",
    author_email="midohajhouj11@gmail.com",
    description="A toolkit designed for simulating various types of Distributed Denial of Service (DDoS) attacks for ethical cybersecurity testing.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Midohajhouj/DDoS-Toolkit",
    packages=find_packages(),
    install_requires=[
        "aiohttp==3.8.1",
        "asyncio==3.4.3",
        "dnspython==2.1.0",
        "openai==0.27.0",
        "psutil==5.8.0",
        "requests==2.28.2",
        "scapy==2.4.5",
        "tabulate==0.9.0",
        "tqdm==4.64.1",
        "colorama",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'ddos=ddos:main',
        ],
    },
    cmdclass={
        'install': CustomInstall,
    },
)
