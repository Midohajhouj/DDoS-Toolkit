#!/bin/bash

# ------------------------------------------------------
#    DDoS Toolkit - Setup Script
#    Coded by LIONMAD
#    This script sets up the environment for running the DDoS Toolkit
# ------------------------------------------------------

# Function to display a banner
function display_banner() {
    echo -e "\n"
    echo -e "\033[1;34m######################################################"
    echo -e "#                                                    #"
    echo -e "#                DDoS Toolkit Setup                 #"
    echo -e "#               Coded by LIONMAD                    #"
    echo -e "#                                                    #"
    echo -e "######################################################\n"
}

# Function to download ddos.py if it doesn't exist
function download_ddos_script() {
    if [[ ! -f "ddos.py" ]]; then
        echo -e "\033[1;32m[INFO]\033[0m Downloading ddos.py..."
        wget -O ddos.py "https://example.com/path/to/ddos.py"  # Replace with the actual URL
        if [[ $? -ne 0 ]]; then
            echo -e "\033[1;31mError: Failed to download ddos.py.\033[0m"
            exit 1
        fi
        echo -e "\033[1;32m[INFO]\033[0m ddos.py downloaded successfully."
    else
        echo -e "\033[1;32m[INFO]\033[0m ddos.py already exists."
    fi
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
pip3 install --upgrade pip --break-system-packages

# Install required Python packages with --break-system-packages to bypass system package conflicts
echo -e "\033[1;32m[INFO]\033[0m Installing required Python packages..."
pip3 install aiohttp scapy psutil dnsresolver tqdm colorama openai --break-system-packages

# Optional: Create a requirements.txt file (for easy re-installation)
echo -e "\033[1;32m[INFO]\033[0m Creating requirements.txt..."
pip3 freeze > requirements.txt

# Download ddos.py if it doesn't exist
download_ddos_script

# Function to create a symlink for easy access
create_symlink() {
    echo -e "${YELLOW}[*] Creating symlink for easy access...${NC}"
    sudo ln -s "$(pwd)/ddos.py" /usr/local/bin/ddos
    echo -e "${GREEN}[+] Symlink created! You can now run 'ddos'${NC}"
}

# Completion message with a stylish output
echo -e "\033[1;32m[INFO]\033[0m Setup complete! The necessary packages have been installed system-wide."
echo -e "\033[1;34mYou can now run the External DDoS Toolkit script directly using:\033[0m"
echo -e "\033[1;32mddos\033[0m"

echo -e "\n\033[1;34m######################################################"
echo -e "#                                                    #"
echo -e "#     External DDoS Toolkit Setup is complete!       #"
echo -e "#                                                    #"
echo -e "######################################################\n"
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
pip3 install --upgrade pip --break-system-packages

# Install required Python packages with --break-system-packages to bypass system package conflicts
echo -e "\033[1;32m[INFO]\033[0m Installing required Python packages..."
pip3 install aiohttp scapy psutil dnsresolver tqdm colorama openai --break-system-packages

# Optional: Create a requirements.txt file (for easy re-installation)
echo -e "\033[1;32m[INFO]\033[0m Creating requirements.txt..."
pip3 freeze > requirements.txt

# Function to create a symlink for easy access
create_symlink() {
    echo -e "${YELLOW}[*] Creating symlink for easy access...${NC}"
    sudo cp "$(pwd)/ddos.py" /usr/local/bin/ddos
    echo -e "${GREEN}[+] Symlink created! You can now run 'ddos'${NC}"
}

# Completion message with a stylish output
echo -e "\033[1;32m[INFO]\033[0m Setup complete! The necessary packages have been installed system-wide."
echo -e "\033[1;34mYou can now run the DDoS Toolkit script directly using:\033[0m"
echo -e "\033[1;32mddos\033[0m"

echo -e "\n\033[1;34m######################################################"
echo -e "#                                                    #"
echo -e "#     DDoS Toolkit Setup is complete!               #"
echo -e "#            LIONMAD SALUT YOU                       #"
echo -e "######################################################\n"
