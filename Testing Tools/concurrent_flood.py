import requests
from concurrent.futures import ThreadPoolExecutor
import argparse

# Concurrent Connection Flood Script
# Opens multiple simultaneous connections to test MAX_CONCURRENT_REQUESTS_PER_IP (10)
# Usage: python concurrent_flood.py --url http://<your-server-ip>/dashboard --workers 15

def send_request(url):
    try:
        response = requests.get(url, timeout=5)
        print(f"Sent request to {url}, Status: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error sending request: {e}")

def main():
    parser = argparse.ArgumentParser(description="Concurrent Connection Flood Simulator")
    parser.add_argument("--url", required=True, help="Target URL (e.g., http://<your-server-ip>/dashboard)")
    parser.add_argument("--workers", type=int, default=15, help="Number of concurrent workers")
    args = parser.parse_args()

    print(f"Starting Concurrent Flood attack on {args.url} with {args.workers} workers...")
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        executor.map(lambda _: send_request(args.url), range(args.workers))
    print("Attack completed.")

if __name__ == "__main__":
    main()