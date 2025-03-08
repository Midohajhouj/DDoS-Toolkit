#!/bin/bash

# ------------------------------------------------------
#    DDoS Toolkit - Setup Script
#    Coded by LIONMAD
#    This script sets up the environment for running the DDoS Toolkit
# ------------------------------------------------------

# Colors for stylish output
YELLOW="\033[1;33m"
GREEN="\033[1;32m"
BLUE="\033[1;34m"
RED="\033[1;31m"
NC="\033[0m" # No Color

# Function to display a banner
function display_banner() {
    echo -e "\n"
    echo -e "${BLUE}######################################################${NC}"
    echo -e "#                                                    #"
    echo -e "#                DDoS Toolkit Setup                 #"
    echo -e "#               Coded by LIONMAD                    #"
    echo -e "#                                                    #"
    echo -e "${BLUE}######################################################${NC}\n"
}

# Display the banner
display_banner

# Ensure the script is being run as root or with sudo for system-wide installations
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR] This script must be run as root or with sudo.${NC}"
    exit 1
fi

# Start installation
echo -e "${GREEN}[INFO]${NC} Updating package list..."
apt-get update -y

# Install system dependencies (if not already installed)
echo -e "${GREEN}[INFO]${NC} Installing required system packages..."
apt-get install -y python3 python3-pip python3-venv libssl-dev libffi-dev build-essential

# Install required Python packages
echo -e "${GREEN}[INFO]${NC} Installing required Python packages..."
pip3 install colorama dns.resolver argparse threading asyncio dnspython cloudscraper hashlib zlib aiohttp scapy tqdm psutil --break-system-packages

# Function to create a symlink for easy access
create_symlink() {
    echo -e "${YELLOW}[*] Creating symlink for easy access...${NC}"

    # Check if the source file exists
    if [ ! -f "$(pwd)/ddos.py" ]; then
        echo -e "${RED}[ERROR] ddos.py not found in the current directory.${NC}"
        return 1
    fi

    # Remove existing symlink if present
    if [ -L "/usr/local/bin/ddos" ]; then
        echo -e "${YELLOW}[INFO] Removing existing symlink...${NC}"
        sudo rm "/usr/local/bin/ddos"
    fi

    # Create a new symlink
    sudo ln -s "$(pwd)/ddos.py" /usr/local/bin/ddos

    # Verify symlink creation
    if [ -L "/usr/local/bin/ddos" ]; then
        echo -e "${GREEN}[SUCCESS] Symlink created! You can now run 'ddos' from anywhere.${NC}"
    else
        echo -e "${RED}[ERROR] Failed to create the symlink.${NC}"
        return 1
    fi
}

# Call the symlink creation function
create_symlink

# Completion message with a stylish output
echo -e "${GREEN}[INFO]${NC} Setup complete! The necessary packages have been installed system-wide."
echo -e "${BLUE}You can now run the DDoS Toolkit script directly using:${NC}"
echo -e "${GREEN}ddos${NC}"

echo -e "\n${BLUE}######################################################${NC}"
echo -e "#                                                    #"
echo -e "#     DDoS Toolkit Setup is complete!               #"
echo -e "#            LIONMAD SALUTES YOU                    #"
echo -e "#                                                    #"
echo -e "${BLUE}######################################################${NC}\n"
