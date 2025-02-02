#!/bin/bash

# This script installs the ddos tool on your system.

# Step 1: Copy the Python script to /usr/local/bin/ (or any directory in PATH)
echo "Copying ddos.py to /usr/local/bin/..."
cp ddos.py /usr/local/bin/ddos

# Step 2: Make the script executable
echo "Making the ddos script executable..."
chmod +x /usr/local/bin/ddos

# Step 3: Verify installation
echo "Installation complete. Verifying ddos command..."

if command -v ddos &>/dev/null; then
    echo "ddos command is now available!"
    echo "You can now run ddos --help for usage instructions."
else
    echo "Something went wrong. ddos command is not available."
    exit 1
fi
