#!/bin/bash

# Build the .deb package
echo "Building .deb package..."
dpkg-deb --build ddos-toolkit

echo "Package built successfully: ddos-toolkit.deb"
