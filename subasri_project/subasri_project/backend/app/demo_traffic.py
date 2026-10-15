"""Generates real, authorized local network traffic against 127.0.0.1 so live
packet capture has genuine packets to sniff, aggregate into flows, and classify
in real time — no synthetic feature vectors, no manual /predict calls.

Everything here targets localhost only (traffic that originates and terminates
on this machine), so it never touches another host on the network.

Run:  python -m app.demo_traffic
"""
import http.server
import random
import socket
import threading
import time

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 8765


def _run_target_server():
    """A trivial local HTTP server that acts as the destination for demo
    traffic — gives the 'normal' and 'brute force' flows somewhere real to
    connect to."""
    handler = http.server.SimpleHTTPRequestHandler
    server = http.server.ThreadingHTTPServer((TARGET_HOST, TARGET_PORT), handler)
    server.serve_forever()


def _normal_traffic_burst():
    """A handful of ordinary short-lived HTTP connections, like a user
    browsing — few packets, normal spacing, clean handshake + teardown."""
    for _ in range(random.randint(2, 5)):
        try:
            s = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=1)
            s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            s.recv(4096)
            s.close()
        except OSError:
            pass
        time.sleep(random.uniform(0.3, 1.2))


def _port_scan_burst():
    """Rapid-fire SYN connection attempts across many ports in a fraction of
    a second — the exact shape a port scanner produces: many tiny flows, high
    SYN count, near-zero payload."""
    ports = random.sample(range(1024, 65000), 40)
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            s.connect_ex((TARGET_HOST, port))
            s.close()
        except OSError:
            pass


def _brute_force_burst():
    """Many quick connect-send-close cycles at one open port, like repeated
    login attempts against a single service."""
    for _ in range(random.randint(10, 20)):
        try:
            s = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=0.5)
            s.sendall(b"POST /login HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            s.close()
        except OSError:
            pass
        time.sleep(random.uniform(0.02, 0.08))


def main():
    server_thread = threading.Thread(target=_run_target_server, daemon=True)
    server_thread.start()
    time.sleep(0.5)
    print(f"Local demo target listening on {TARGET_HOST}:{TARGET_PORT}")
    print("Generating continuous local traffic (normal bursts + periodic port-scan/brute-force patterns)...")
    print("Press Ctrl+C to stop.")

    cycle = 0
    try:
        while True:
            _normal_traffic_burst()
            cycle += 1
            if cycle % 4 == 0:
                print("[demo_traffic] firing a port-scan-shaped burst against localhost")
                _port_scan_burst()
            if cycle % 7 == 0:
                print("[demo_traffic] firing a brute-force-shaped burst against localhost")
                _brute_force_burst()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
