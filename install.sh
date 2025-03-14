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
RESET="\033[0m" # Reset color

# Function to display a banner
function display_banner() {
    echo -e "${BLUE}"
    echo "██████████████████████████████████████████████████████████"
    echo "██                                                      ██"
    echo "██              DDoS Toolkit Coded by LIONMAD           ██"
    echo "██                     Setup Script                     ██"
    echo "██          This script sets up the environment         ██"
    echo "██              for running the DDoS Toolkit            ██"
    echo "██   LIONMAD SALUTES YOU           LIONMAD SALUTES YOU  ██"
    echo "██                   LIONMAD SALUTES YOU                ██"
    echo "██                                                      ██"
    echo "██████████████████████████████████████████████████████████"
    echo -e "${RESET}"
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
pip install --break-system-packages aiohttp==3.8.1
pip install --break-system-packages asyncio==3.4.3
pip install --break-system-packages dnspython==2.1.0
pip install --break-system-packages openai==0.27.0
pip install --break-system-packages psutil==5.8.0
pip install --break-system-packages requests==2.28.2
pip install --break-system-packages scapy==2.4.5
pip install --break-system-packages tabulate==0.9.0
pip install --break-system-packages tqdm==4.64.1

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
    sudo cp "$(pwd)/ddos.py" /usr/local/bin/ddos

    # Verify symlink creation
    if [ -L "/usr/local/bin/ddos" ]; then
        echo -e "${GREEN}[SUCCESS] Symlink created! You can now run 'ddos' from anywhere.${NC}"
    else
        echo -e "${GREEN}[SUCCESS] Symlink created! You can now run 'ddos' from anywhere.${NC}"
        return 1
    fi
}

# Call the symlink creation function
create_symlink

# Completion message with a stylish output
echo -e "${GREEN}[INFO]${NC} Setup complete! The necessary packages have been installed system-wide."
echo -e "${BLUE}You can now run the DDoS Toolkit script directly using:${NC}"
echo -e "${GREEN}ddos${NC}"

    echo -e "${BLUE}"
    echo "████████████████████████████████████████████████████████████"
    echo "██                                                        ██"
    echo "██                    Setup is complete                   ██"
    echo "██   LIONMAD SALUTES YOU             LIONMAD SALUTES YOU  ██"
    echo "██   LIONMAD SALUTES YOU             LIONMAD SALUTES YOU  ██"
    echo "██   LIONMAD SALUTES YOU             LIONMAD SALUTES YOU  ██"
    echo "██   LIONMAD SALUTES YOU             LIONMAD SALUTES YOU  ██"
    echo "██                                                        ██"
    echo "████████████████████████████████████████████████████████████"
    echo -e "${RESET}"
