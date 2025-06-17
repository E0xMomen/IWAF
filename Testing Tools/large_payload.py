import requests
import argparse

# Large Payload Attack Script
# Sends a large POST payload to test MAX_CONTENT_LENGTH (10MB)
# Usage: python large_payload.py --url http://<your-server-ip>/login --size 11000000

def large_payload_attack(url, size):
    try:
        data = "A" * size  # Generate large payload
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = requests.post(url, data=data, headers=headers, timeout=10)
        print(f"Sent {size} byte payload, Status: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error sending payload: {e}")

def main():
    parser = argparse.ArgumentParser(description="Large Payload Attack Simulator")
    parser.add_argument("--url", required=True, help="Target URL (e.g., http://<your-server-ip>/login)")
    parser.add_argument("--size", type=int, default=11000000, help="Payload size in bytes")
    args = parser.parse_args()

    print(f"Starting Large Payload attack on {args.url} with {args.size} byte payload...")
    large_payload_attack(args.url, args.size)
    print("Attack completed.")

if __name__ == "__main__":
    main()