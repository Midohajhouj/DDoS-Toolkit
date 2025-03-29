#!/bin/bash
# Easter egg LIONMAD salut u 
# Build the .deb package
echo "Building .deb package..."
cd ddos-toolkit/DEBIAN
chmod +x * && cd .. && cd ..
dpkg-deb --build ddos-toolkit

echo "Package built successfully: ddos-toolkit.deb"
