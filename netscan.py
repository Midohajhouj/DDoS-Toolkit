#!/usr/bin/env python3
# -*- coding: utf-8 -*-
### BEGIN INIT INFO
# Provides:          ddos_toolkit extension
# Required-Start:    $network $scanner
# Required-Stop:     $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: DDoS Attack Simulation Toolkit
# Description:       A toolkit designed for simulating various types of Distributed Denial of Service (DDoS) attacks for ethical cybersecurity testing.
# Author:
# + LIONMAD <https://github.com/Midohajhouj>
# Version:           v1.6
# License:           MIT License - https://opensource.org/licenses/MIT
### END INIT INFO

import socket
import threading
import subprocess
import sys
import argparse
from colorama import init, Fore, Style
import requests
from tabulate import tabulate
import json
import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import asyncio

# Initialize colorama
init(autoreset=True)

# Colors
GREEN = Fore.GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
RESET = Style.RESET_ALL

# Common DDoS amplification ports and their descriptions
DDoS_PORTS = {
    53: {"service": "DNS", "risk": "High", "description": "DNS amplification attacks"},
    123: {"service": "NTP", "risk": "High", "description": "NTP amplification attacks"},
    161: {"service": "SNMP", "risk": "High", "description": "SNMP amplification attacks"},
    19: {"service": "CHARGEN", "risk": "High", "description": "CHARGEN amplification attacks"},
    17: {"service": "QOTD", "risk": "Medium", "description": "QOTD amplification attacks"},
    137: {"service": "NetBIOS", "risk": "Medium", "description": "NetBIOS amplification attacks"},
    389: {"service": "LDAP", "risk": "High", "description": "LDAP amplification attacks"},
    1900: {"service": "UPnP", "risk": "Medium", "description": "UPnP amplification attacks"},
    11211: {"service": "Memcached", "risk": "High", "description": "Memcached amplification attacks"},
    80: {"service": "HTTP", "risk": "Medium", "description": "Potential HTTP-based attacks (DDoS)"},
    443: {"service": "HTTPS", "risk": "Medium", "description": "Potential HTTPS-based attacks (DDoS)"}
}

# Common CVEs for DDoS-related services
CVE_DATABASE = {
    "DNS": ["CVE-2020-1350", "CVE-2019-6477"],
    "NTP": ["CVE-2016-7431", "CVE-2015-8138"],
    "SNMP": ["CVE-2017-6742", "CVE-2012-2148"],
    "LDAP": ["CVE-2021-44228", "CVE-2020-15778"],
    "HTTP": ["CVE-2017-5638", "CVE-2018-7600"],
    "HTTPS": ["CVE-2018-11776", "CVE-2020-2551"]
}

# Logging configuration
LOG_DIR = "/opt/DDoS-Toolkit/logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "netscan.log")),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def resolve_domain_to_ip(domain):
    """Resolve a domain name to an IP address."""
    try:
        ip = socket.gethostbyname(domain)
        logger.info(f"Resolved {domain} to IP: {ip}")
        return ip
    except socket.gaierror:
        logger.error(f"Could not resolve domain: {domain}")
        return None

def scan_port(ip, port):
    """Scan a single port on the target IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            return True
        else:
            return False
    except Exception as e:
        logger.warning(f"Error scanning port {port}: {e}")
        return False
    finally:
        sock.close()

async def scan_port_async(ip, port):
    """Asynchronously scan a single port on the target IP."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=1)
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

def detect_firewall(ip):
    """Detect if a firewall is present using ICMP ping."""
    try:
        response = subprocess.run(["ping", "-c", "1", ip], capture_output=True, text=True)
        if "1 received" in response.stdout:
            logger.info("Firewall not detected (ICMP allowed)")
            return False
        else:
            logger.warning("Firewall detected (ICMP blocked)")
            return True
    except Exception as e:
        logger.error(f"Error detecting firewall: {e}")
        return None

def check_cves(service):
    """Check for common CVEs related to a service."""
    return CVE_DATABASE.get(service, [])

def scan_for_ddos_vulnerabilities(ip):
    """Scan for common DDoS amplification ports and classify them."""
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scan_port_thread, ip, port, info): port for port, info in DDoS_PORTS.items()}
        for future in as_completed(futures):
            results.append(future.result())
    return results

async def scan_for_ddos_vulnerabilities_async(ip):
    """Asynchronously scan for common DDoS amplification ports."""
    tasks = [scan_port_async(ip, port) for port in DDoS_PORTS.keys()]
    results = await asyncio.gather(*tasks)
    return results

def scan_http_https(ip):
    """Check if HTTP or HTTPS ports (80, 443) are open and vulnerable."""
    results = []
    for port in [80, 443]:
        open_port = scan_port(ip, port)
        if open_port:
            service = DDoS_PORTS[port]["service"]
            cves = check_cves(service)
            results.append({
                "port": port,
                "service": service,
                "status": "Open",
                "risk": DDoS_PORTS[port]["risk"],
                "description": DDoS_PORTS[port]["description"],
                "cves": cves
            })
    return results

def scan_port_thread(ip, port, info):
    """Thread function to scan a port and check for vulnerabilities."""
    is_open = scan_port(ip, port)
    if is_open:
        cves = check_cves(info["service"])
        return {
            "port": port,
            "service": info["service"],
            "status": "Open",
            "risk": info["risk"],
            "description": info["description"],
            "cves": cves
        }
    else:
        return {
            "port": port,
            "service": info["service"],
            "status": "Closed",
            "risk": "None",
            "description": "No DDoS risk",
            "cves": []
        }

def print_scan_report(scan_results):
    """Print the scan results in a tabular format."""
    headers = ["Port", "Service", "Status", "Risk", "Description", "CVEs"]
    table_data = []
    
    for result in scan_results:
        cve_list = ", ".join(result["cves"]) if result["cves"] else "None"
        table_data.append([
            result["port"],
            result["service"],
            result["status"],
            result["risk"],
            result["description"],
            cve_list
        ])
    
    print(tabulate(table_data, headers, tablefmt="pretty"))

def generate_html_report(scan_results):
    """Generate an HTML report."""
    html_report = """
    <html>
    <head>
        <title>DDoS Vulnerability Scan Report</title>
        <style>
            table { width: 100%; border-collapse: collapse; }
            th, td { border: 1px solid black; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <h1>DDoS Vulnerability Scan Report</h1>
        <h2>Scan Results</h2>
        <table>
            <tr><th>Port</th><th>Service</th><th>Status</th><th>Risk</th><th>Description</th><th>CVEs</th></tr>
    """
    
    for result in scan_results:
        cve_list = ", ".join(result["cves"]) if result["cves"] else "None"
        html_report += f"""
            <tr>
                <td>{result['port']}</td>
                <td>{result['service']}</td>
                <td>{result['status']}</td>
                <td>{result['risk']}</td>
                <td>{result['description']}</td>
                <td>{cve_list}</td>
            </tr>
        """
    
    html_report += """
        </table>
    </body>
    </html>
    """
    return html_report

def save_scan_results_to_json(scan_results, filename="scan_results.json"):
    """Save scan results to a JSON file."""
    filepath = os.path.join(LOG_DIR, filename)
    with open(filepath, "w") as file:
        json.dump(scan_results, file, indent=4)
    logger.info(f"Scan results saved to {filepath}")

def run_nmap_scan(ip):
    """Run a local Nmap scan if available."""
    logger.info(f"Running Nmap scan on {ip}...")
    try:
        nmap_result = subprocess.run(["nmap", "-sV", "-p", "80,443,53,123,161,11211", ip], capture_output=True, text=True)
        if nmap_result.returncode == 0:
            logger.info("Nmap scan successful")
            print(nmap_result.stdout)
        else:
            logger.error("Nmap scan failed")
            print(nmap_result.stderr)
    except FileNotFoundError:
        logger.error("Nmap not found. Please install Nmap to run this scan.")

async def main_async():
    """Main function to run the advanced DDoS vulnerability scanner asynchronously."""
    parser = argparse.ArgumentParser(description="Advanced DDoS Vulnerability Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP address or domain name")
    args = parser.parse_args()

    target = args.target

    if not target.replace(".", "").isdigit():
        ip = resolve_domain_to_ip(target)
        if not ip:
            return
    else:
        ip = target

    logger.info(f"Scanning target IP: {ip} for DDoS vulnerabilities")

    run_nmap_scan(ip)

    firewall_detected = detect_firewall(ip)

    scan_results = scan_for_ddos_vulnerabilities(ip)
    http_https_scan = scan_http_https(ip)

    logger.info("Scan Report:")
    print_scan_report(scan_results)

    html_report = generate_html_report(scan_results)
    html_report_path = os.path.join(LOG_DIR, "scan_report.html")
    with open(html_report_path, "w") as file:
        file.write(html_report)
    logger.info(f"HTML report saved to {html_report_path}")

    save_scan_results_to_json(scan_results)

if __name__ == "__main__":
    asyncio.run(main_async())
