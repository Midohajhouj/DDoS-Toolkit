#!/bin/bash

# ------------------------------------------------------
#    DDoS Toolkit - Setup Script
#    Coded by MIDO777
#    This script sets up the environment for running the DDoS Toolkit
# ------------------------------------------------------

# Function to display a banner
function display_banner() {
    echo -e "\n"
    echo -e "\033[1;34m######################################################"
    echo -e "#                                                    #"
    echo -e "#                DDoS Toolkit Setup                 #"
    echo -e "#               Coded by MIDO777                    #"
    echo -e "#                                                    #"
    echo -e "######################################################\n"
}

# Display the banner
display_banner

# Ensure the script is being run as root or with sudo for system-wide installations
if [[ $EUID -ne 0 ]]; then
    echo -e "\033[1;31mError: This script must be run as root or with sudo.\033[0m"
    exit 1
fi

# Start installation
echo -e "\033[1;32m[INFO]\033[0m Updating package list..."
apt-get update -y

# Install system dependencies (if not already installed)
echo -e "\033[1;32m[INFO]\033[0m Installing required system packages..."
apt-get install -y python3 python3-pip python3-venv libssl-dev libffi-dev build-essential

# Upgrade pip to the latest version
echo -e "\033[1;32m[INFO]\033[0m Upgrading pip..."
pip3 install --upgrade pip

# Install required Python packages with --break-system-packages to bypass system package conflicts
echo -e "\033[1;32m[INFO]\033[0m Installing required Python packages..."
pip3 install requests colorama dnspython cloudscraper --break-system-packages

# Optional: Create a requirements.txt file (for easy re-installation)
echo -e "\033[1;32m[INFO]\033[0m Creating requirements.txt..."
pip3 freeze > requirements.txt

# Completion message with a stylish output
echo -e "\033[1;32m[INFO]\033[0m Setup complete! The necessary packages have been installed system-wide."
echo -e "\033[1;34mYou can now run the DDoS Toolkit script directly using:\033[0m"
echo -e "\033[1;32mpython3 your_script.py\033[0m"

echo -e "\n\033[1;34m######################################################"
echo -e "#                                                    #"
echo -e "#     DDoS Toolkit Setup is complete!               #"
echo -e "#                                                    #"
echo -e "######################################################\n"