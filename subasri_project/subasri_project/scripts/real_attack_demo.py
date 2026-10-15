import socket
import time
import sys

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def run_real_port_scan():
    target_ip = get_local_ip()
    print(f"🎯 Target IP (Your Wi-Fi interface): {target_ip}")
    print("🚀 Launching real TCP port scan across 100 ports...")

    scanned_ports = 0
    start_time = time.time()
    
    for port in range(20, 120):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.02)
            s.connect((target_ip, port))
            s.close()
        except Exception:
            pass
        scanned_ports += 1

    elapsed = time.time() - start_time
    print(f"✅ Finished real scan of {scanned_ports} ports in {elapsed:.2f} seconds!")
    print(f"📡 Real TCP packets sent over Wi-Fi interface ({target_ip}). Check your NIDS dashboard!")

if __name__ == "__main__":
    run_real_port_scan()
