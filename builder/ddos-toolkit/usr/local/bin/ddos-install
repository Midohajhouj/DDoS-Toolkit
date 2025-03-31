#!/bin/bash

# Colors for stylish output
YELLOW="\033[1;33m"
GREEN="\033[1;32m"
BLUE="\033[1;34m"
RED="\033[1;31m"
RESET="\033[0m"  # Reset color

# Logging configuration
PIP_LOG="pip_install.log"

display_banner() {
    echo -e "${BLUE}"
    echo "██████████████████████████████████████████████████"
    echo "██                                              ██"
    echo "██          DDoS Toolkit Setup                  ██"
    echo "██       Advanced Network Testing               ██"
    echo "██                                              ██"
    echo "██  Supports: HTTP/HTTPS, TCP, UDP, ICMP,      ██"
    echo "██  DNS, NTP, Memcached, and 20+ other         ██"
    echo "██  attack vectors                             ██"
    echo "██                                              ██"
    echo "██████████████████████████████████████████████████"
    echo -e "${RESET}"
}

install_system_dependencies() {
    echo -e "${GREEN}[INFO]${RESET} Updating package list..."
    if ! apt update -y; then
        echo -e "${YELLOW}[WARNING]${RESET} Failed to update package list"
        echo -e "${YELLOW}[WARNING]${RESET} Continuing with installation..."
        return 1
    fi
    return 0
}

install_apt_packages() {
    local apt_packages=(
        "python3" "python3-pip" "python3-venv"
        "libssl-dev" "libffi-dev" "wget"
        "nmap" "tor" "proxychains" "aircrack-ng"
        "tcpdump" "dnsutils" "net-tools"
    )
    
    local failed_packages=()
    echo -e "${GREEN}[INFO]${RESET} Installing required system packages..."
    
    for pkg in "${apt_packages[@]}"; do
        if ! apt install -y "$pkg"; then
            echo -e "${YELLOW}[WARNING]${RESET} Failed to install $pkg"
            failed_packages+=("$pkg")
        fi
    done
    
    if [ ${#failed_packages[@]} -gt 0 ]; then
        echo -e "${YELLOW}[WARNING]${RESET} The following packages failed to install: ${failed_packages[*]}"
        echo -e "${YELLOW}[WARNING]${RESET} Some features may not work properly without these packages"
        return 1
    fi
    return 0
}

install_python_packages() {
    echo -e "${GREEN}[INFO]${RESET} Installing required Python packages (output logged to ${PIP_LOG})..."
    local packages=(
        "aiohttp"
        "scapy"
        "dnspython"
        "colorama"
        "tqdm"
        "requests"
        "tabulate"
        "psutil"
        "argparse"
        "uuid"
        "hmac"
        "ipaddress"
        "urllib3"
        "pyOpenSSL"
        "python-nmap"
    )

    local failed_packages=()
    for package in "${packages[@]}"; do
        if ! pip install --break-system-packages "$package" >> "$PIP_LOG" 2>&1; then
            echo -e "${YELLOW}[WARNING]${RESET} Failed to install $package. Check $PIP_LOG for details."
            failed_packages+=("$package")
        fi
    done
    
    if [ ${#failed_packages[@]} -gt 0 ]; then
        echo -e "${YELLOW}[WARNING]${RESET} The following Python packages failed to install: ${failed_packages[*]}"
        echo -e "${YELLOW}[WARNING]${RESET} Some features may not work properly without these packages"
        return 1
    fi
    return 0
}

create_directories_and_files() {
    echo -e "${GREEN}[INFO]${RESET} Creating required directories and files..."
    
    # List of directories to create
    local directories=(
        '/opt/DDoS-Toolkit'
        '/opt/DDoS-Toolkit/assets'
        '/opt/DDoS-Toolkit/logs'
        '/opt/DDoS-Toolkit/wordlists'
    )
    
    local failed_ops=()
    
    # Create directories
    for directory in "${directories[@]}"; do
        if ! mkdir -p "$directory"; then
            echo -e "${YELLOW}[WARNING]${RESET} Failed to create directory $directory"
            failed_ops+=("$directory")
        else
            echo -e "${GREEN}[+] Created directory: $directory${RESET}"
        fi
    done
    
    # Copy asset files if they exist
    if [ -d "assets" ]; then
        for asset in "netscan" "wifideauth" "anonymizer"; do
            if [ -f "assets/$asset" ]; then
                if ! cp "assets/$asset" "/opt/DDoS-Toolkit/assets/"; then
                    echo -e "${YELLOW}[WARNING]${RESET} Failed to copy asset $asset"
                    failed_ops+=("asset:$asset")
                fi
            else
                echo -e "${YELLOW}[WARNING]${RESET} Asset file assets/$asset not found"
                failed_ops+=("asset:$asset")
            fi
        done
    else
        echo -e "${YELLOW}[WARNING]${RESET} Assets directory not found"
        failed_ops+=("assets")
    fi
    
    if [ ${#failed_ops[@]} -gt 0 ]; then
        echo -e "${YELLOW}[WARNING]${RESET} Some directory/file operations failed: ${failed_ops[*]}"
        return 1
    fi
    return 0
}

download_default_wordlists() {
    echo -e "${GREEN}[INFO]${RESET} Checking for default wordlists..."
    declare -A wordlists=(
        ['common_ports.txt']='https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Infrastructure/common-http-ports.txt'
        ['http_headers.txt']='https://raw.githubusercontent.com/devanshbatham/headerpwn/refs/heads/main/headers.txt'
        ['user_agents.txt']='https://gist.githubusercontent.com/pzb/b4b6f57144aea7827ae4/raw/cf847b76a142955b1410c8bcef3aabe221a63db1/user-agents.txt'
        ['proxy.txt']='https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/http.txt'
    )

    local failed_downloads=()
    for filename in "${!wordlists[@]}"; do
        local filepath="/opt/DDoS-Toolkit/wordlists/$filename"
        if [ ! -e "$filepath" ]; then
            echo -e "${YELLOW}[*]${RESET} Downloading $filename..."
            if ! wget -q -O "$filepath" "${wordlists[$filename]}"; then
                echo -e "${YELLOW}[WARNING]${RESET} Failed to download $filename"
                failed_downloads+=("$filename")
                # Remove partially downloaded file
                rm -f "$filepath"
            else
                echo -e "${GREEN}[+] Successfully downloaded $filename${RESET}"
            fi
        fi
    done
    
    if [ ${#failed_downloads[@]} -gt 0 ]; then
        echo -e "${YELLOW}[WARNING]${RESET} Failed to download these wordlists: ${failed_downloads[*]}"
        return 1
    fi
    return 0
}

create_symlink() {
    echo -e "${YELLOW}[*]${RESET} Creating symlink for easy access..."

    # Check if the source file exists
    if [ ! -f "ddos.py" ]; then
        echo -e "${RED}[ERROR]${RESET} ddos.py not found in the current directory."
        return 1
    fi

    # Remove existing symlink if present
    if [ -e "/usr/local/bin/ddos" ]; then
        echo -e "${YELLOW}[INFO]${RESET} Removing existing symlink..."
        rm -f "/usr/local/bin/ddos"
    fi

    # Create a new symlink
    if ! cp "$(pwd)/ddos.py" "/usr/local/bin/ddos"; then
        echo -e "${YELLOW}[WARNING]${RESET} Symlink creation failed."
        return 1
    fi

    chmod +x "/usr/local/bin/ddos"

    # Verify symlink creation
    if [ -e "/usr/local/bin/ddos" ]; then
        echo -e "${GREEN}[SUCCESS]${RESET} Symlink created! You can now run 'ddos' from anywhere."
        return 0
    else
        echo -e "${YELLOW}[WARNING]${RESET} Symlink creation failed."
        return 1
    fi
}

main() {
    display_banner

    # Ensure the script is being run as root or with sudo
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[ERROR]${RESET} This script must be run as root or with sudo."
        exit 1
    fi

    # Track installation success
    local overall_success=0
    
    # Install system dependencies
    if ! install_system_dependencies; then
        overall_success=1
    fi
    
    # Install apt packages
    if ! install_apt_packages; then
        overall_success=1
    fi

    # Install Python packages
    if ! install_python_packages; then
        overall_success=1
    fi

    # Create required directories and files
    if ! create_directories_and_files; then
        overall_success=1
    fi

    # Download default wordlists
    if ! download_default_wordlists; then
        overall_success=1
    fi

    # Create a symlink for easy access
    if ! create_symlink; then
        overall_success=1
    fi

    # Completion message
    if [ $overall_success -eq 0 ]; then
        echo -e "${GREEN}[SUCCESS]${RESET} Setup completed successfully!"
    else
        echo -e "${YELLOW}[WARNING]${RESET} Setup completed with some warnings. Some features may not work properly."
    fi
    
    echo -e "${BLUE}You can now run the tool using:${RESET}"
    echo -e "${GREEN}ddos${RESET}"

    echo -e "${BLUE}"
    echo "████████████████████████████████████████████████████"
    echo "██                                                ██"
    echo "██           Installation Complete               ██"
    echo "██      DDoS Toolkit Ready                       ██"
    echo "██                                                ██"
    echo "████████████████████████████████████████████████████"
    echo -e "${RESET}"
}

# Run the main function
main
