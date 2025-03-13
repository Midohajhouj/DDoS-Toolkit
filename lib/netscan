#!/usr/bin/env python3
# -*- coding: utf-8 -*-
### BEGIN INIT INFO
# Provides:          ddos_toolkit_network_scanner
# Required-Start:    $network $remote_fs
# Required-Stop:     $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Network Scanner and Security Analyzer (Extension of DDoS Toolkit)
# Description:       An extension of the DDoS Toolkit, designed for network scanning, vulnerability assessment.
# + LIONMAD <https://github.com/Midohajhouj>
# License:           MIT License - https://opensource.org/licenses/MIT
### END INIT INFO

# ================== Standard Libraries ====================
import socket  # Handling low-level network connections.
import threading  # Multithreading for simultaneous scans.
import subprocess  # Running external network tools.
import sys  # System-level operations (e.g., argument handling).
import argparse  # Parsing command-line arguments.
import json  # Managing JSON data for inputs and outputs.
import os  # Interacting with the operating system.
import logging  # Recording scan logs and error details.
from concurrent.futures import ThreadPoolExecutor, as_completed  # Managing parallel scans.
import asyncio  # Supporting asynchronous scanning tasks.
import time  # Measuring scan durations and timeouts.
import configparser  # Handling configuration files.
from typing import Dict, List, Optional, Tuple  # Defining type hints for better code clarity.

# ================== Third-Party Libraries ==================
from colorama import init, Fore, Style  # Adding colors to terminal outputs.
import requests  # Making HTTP/HTTPS requests for web server analysis.
from tabulate import tabulate  # Displaying scan results in table format.

# Initialize colorama
init(autoreset=True)

# Colors
GREEN = Fore.GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
RESET = Style.RESET_ALL

# Constants
DEFAULT_PORTS = [80, 443, 53, 123, 161, 11211]
LOG_DIR = "/var/log/network_scanner"
CONFIG_FILE = "config.ini"

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

# Expanded CVE database for DDoS-related services
CVE_DATABASE = {
    "DNS": ["CVE-2020-1350", "CVE-2019-6477", "CVE-2017-14491"],
    "NTP": ["CVE-2016-7431", "CVE-2015-8138", "CVE-2014-9295"],
    "SNMP": ["CVE-2017-6742", "CVE-2012-2148", "CVE-2010-3847"],
    "LDAP": ["CVE-2021-44228", "CVE-2020-15778", "CVE-2019-1309"],
    "HTTP": ["CVE-2017-5638", "CVE-2018-7600", "CVE-2021-41773"],
    "HTTPS": ["CVE-2018-11776", "CVE-2020-2551", "CVE-2021-3449"],
    "Memcached": ["CVE-2018-1000115", "CVE-2016-8704"],
    "UPnP": ["CVE-2020-12695", "CVE-2013-0229"],
    "CHARGEN": ["CVE-1999-0635"],
    "QOTD": ["CVE-1999-0635"],
    "NetBIOS": ["CVE-1999-0519"]
}

# Logging configuration
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "network_scanner.log")),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def resolve_domain_to_ip(domain: str) -> Optional[str]:
    """Resolve a domain name to an IP address."""
    try:
        ip = socket.gethostbyname(domain)
        logger.info(f"Resolved {domain} to IP: {ip}")
        return ip
    except socket.gaierror as e:
        logger.error(f"Could not resolve domain: {domain}. Error: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error resolving domain: {domain}. Error: {e}")
        return None

def scan_port(ip: str, port: int) -> bool:
    """Scan a single TCP port on the target IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        return result == 0
    except Exception as e:
        logger.warning(f"Error scanning port {port}: {e}")
        return False
    finally:
        sock.close()

def scan_udp_port(ip: str, port: int) -> bool:
    """Scan a single UDP port on the target IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(b'', (ip, port))
        data, _ = sock.recvfrom(1024)
        return True
    except socket.timeout:
        return False
    except Exception as e:
        logger.warning(f"Error scanning UDP port {port}: {e}")
        return False
    finally:
        sock.close()

async def scan_port_async(ip: str, port: int) -> bool:
    """Asynchronously scan a single TCP port on the target IP."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=1)
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

async def scan_udp_port_async(ip: str, port: int) -> bool:
    """Asynchronously scan a single UDP port on the target IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(b'', (ip, port))
        await asyncio.wait_for(sock.recvfrom(1024), timeout=1)
        return True
    except socket.timeout:
        return False
    except Exception as e:
        logger.warning(f"Error scanning UDP port {port}: {e}")
        return False
    finally:
        sock.close()

async def scan_ports_batch(ip: str, ports: List[int], udp: bool = False) -> List[bool]:
    """Scan a batch of ports asynchronously."""
    tasks = [scan_udp_port_async(ip, port) if udp else scan_port_async(ip, port) for port in ports]
    results = await asyncio.gather(*tasks)
    return results

def rate_limited_scan(ip: str, port: int, delay: int = 1) -> bool:
    """Scan a port with a delay to avoid rate limiting."""
    time.sleep(delay)
    return scan_port(ip, port)

def detect_firewall(ip: str) -> Optional[bool]:
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

def check_cves(service: str) -> List[str]:
    """Check for common CVEs related to a service."""
    return CVE_DATABASE.get(service, [])

def scan_for_ddos_vulnerabilities(ip: str) -> List[Dict]:
    """Scan for common DDoS amplification ports and classify them."""
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scan_port_thread, ip, port, info): port for port, info in DDoS_PORTS.items()}
        for future in as_completed(futures):
            results.append(future.result())
    return results

async def scan_for_ddos_vulnerabilities_async(ip: str) -> List[bool]:
    """Asynchronously scan for common DDoS amplification ports."""
    tasks = [scan_port_async(ip, port) for port in DDoS_PORTS.keys()]
    results = await asyncio.gather(*tasks)
    return results

def scan_http_https(ip: str) -> List[Dict]:
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

def scan_port_thread(ip: str, port: int, info: Dict) -> Dict:
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

def print_scan_report(scan_results: List[Dict]) -> None:
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

def generate_html_report(scan_results: List[Dict], filename: str = "scan_report.html") -> None:
    """Generate an HTML report."""
    html_report = """
    <html>
    <head>
        <title>Network Security Scan Report</title>
        <style>
            table { width: 100%; border-collapse: collapse; }
            th, td { border: 1px solid black; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <h1>Network Security Scan Report</h1>
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
    
    filepath = os.path.join(LOG_DIR, filename)
    with open(filepath, "w") as file:
        file.write(html_report)
    logger.info(f"HTML report saved to {filepath}")

def save_scan_results_to_json(scan_results: List[Dict], filename: str = "scan_results.json") -> None:
    """Save scan results to a JSON file."""
    filepath = os.path.join(LOG_DIR, filename)
    with open(filepath, "w") as file:
        json.dump(scan_results, file, indent=4)
    logger.info(f"Scan results saved to {filepath}")

def run_nmap_scan(ip: str) -> None:
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

def load_config() -> Dict:
    """Load configuration from a file."""
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    return config

def save_config(config: Dict) -> None:
    """Save configuration to a file."""
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)

def interactive_mode() -> None:
    """Run the scanner in interactive mode."""
    target = input("Enter target IP or domain: ")
    ip = resolve_domain_to_ip(target)
    if not ip:
        print("Invalid target.")
        return
    
    print(f"Scanning target: {ip}")
    scan_results = scan_for_ddos_vulnerabilities(ip)
    print_scan_report(scan_results)

async def main_async():
    """Main function to run the advanced network scanner asynchronously."""
    parser = argparse.ArgumentParser(description="Advanced Network Scanner and Security Analyzer")
    parser.add_argument("-t", "--target", required=True, help="Target IP address or domain name")
    parser.add_argument("-i", "--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("-m", "--multiple", nargs="+", help="Scan multiple targets")
    args = parser.parse_args()

    if args.interactive:
        interactive_mode()
        return

    if args.multiple:
        targets = args.multiple
        logger.info(f"Scanning multiple targets: {targets}")
        for target in targets:
            ip = resolve_domain_to_ip(target) if not target.replace(".", "").isdigit() else target
            if not ip:
                logger.error(f"Invalid target: {target}")
                continue

            logger.info(f"Scanning target IP: {ip} for vulnerabilities")
            run_nmap_scan(ip)
            firewall_detected = detect_firewall(ip)
            scan_results = scan_for_ddos_vulnerabilities(ip)
            http_https_scan = scan_http_https(ip)

            logger.info("Scan Report:")
            print_scan_report(scan_results)

            # Generate unique filenames based on IP and timestamp
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            html_filename = f"scan_report_{ip}_{timestamp}.html"
            json_filename = f"scan_results_{ip}_{timestamp}.json"

            # Generate and save HTML report
            generate_html_report(scan_results, html_filename)

            # Save scan results to JSON
            save_scan_results_to_json(scan_results, json_filename)
        return

    target = args.target
    ip = resolve_domain_to_ip(target) if not target.replace(".", "").isdigit() else target

    if not ip:
        logger.error("Invalid target.")
        return

    logger.info(f"Scanning target IP: {ip} for vulnerabilities")

    run_nmap_scan(ip)

    firewall_detected = detect_firewall(ip)

    scan_results = scan_for_ddos_vulnerabilities(ip)
    http_https_scan = scan_http_https(ip)

    logger.info("Scan Report:")
    print_scan_report(scan_results)

    # Generate unique filenames based on IP and timestamp
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    html_filename = f"scan_report_{ip}_{timestamp}.html"
    json_filename = f"scan_results_{ip}_{timestamp}.json"

    # Generate and save HTML report
    generate_html_report(scan_results, html_filename)

    # Save scan results to JSON
    save_scan_results_to_json(scan_results, json_filename)

if __name__ == "__main__":
    asyncio.run(main_async())
