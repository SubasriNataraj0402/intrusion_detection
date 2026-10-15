"""Continuous demo simulator for NIDS Platform.
Generates realistic traffic flows (Normal, Port Scan, DDoS, Brute Force, Unknown Anomaly)
and pushes them into the ML pipeline, DB, and WebSockets every 2 seconds.
"""
import random
import time
from app.pipeline import process_flow

SOURCE_IPS = ["192.168.1.105", "10.0.0.12", "172.16.0.45", "192.168.1.200", "10.0.0.88"]
DEST_IPS = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "10.0.0.5"]

def generate_flow_payload(attack_type: str = "normal"):
    src = random.choice(SOURCE_IPS)
    dst = random.choice(DEST_IPS)
    
    if attack_type == "port_scan":
        return {
            "duration": round(random.uniform(0.01, 0.08), 3),
            "total_packets": random.randint(30, 60),
            "total_bytes": random.randint(2000, 5000),
            "avg_packet_size": random.randint(60, 90),
            "syn_count": random.randint(30, 60),
            "ack_count": 0,
            "fin_count": 0,
            "packets_per_sec": random.randint(500, 1200),
            "bytes_per_sec": random.randint(40000, 90000),
            "source_ip": src,
            "destination_ip": dst,
            "source_port": random.randint(1024, 65535),
            "destination_port": random.randint(1, 1024),
            "protocol": "TCP"
        }
    elif attack_type == "ddos":
        packets = random.randint(500, 2000)
        bytes_total = packets * random.randint(1000, 1400)
        dur = round(random.uniform(0.1, 0.5), 3)
        return {
            "duration": dur,
            "total_packets": packets,
            "total_bytes": bytes_total,
            "avg_packet_size": random.randint(1000, 1400),
            "syn_count": int(packets * 0.8),
            "ack_count": int(packets * 0.2),
            "fin_count": 0,
            "packets_per_sec": int(packets / dur),
            "bytes_per_sec": int(bytes_total / dur),
            "source_ip": src,
            "destination_ip": dst,
            "source_port": random.randint(1024, 65535),
            "destination_port": 80,
            "protocol": "TCP"
        }
    elif attack_type == "brute_force":
        return {
            "duration": round(random.uniform(0.05, 0.2), 3),
            "total_packets": random.randint(15, 35),
            "total_bytes": random.randint(1000, 3000),
            "avg_packet_size": random.randint(80, 120),
            "syn_count": random.randint(5, 10),
            "ack_count": random.randint(10, 25),
            "fin_count": random.randint(1, 5),
            "packets_per_sec": random.randint(150, 400),
            "bytes_per_sec": random.randint(15000, 35000),
            "source_ip": src,
            "destination_ip": dst,
            "source_port": random.randint(1024, 65535),
            "destination_port": 22,
            "protocol": "TCP"
        }
    elif attack_type == "anomaly":
        return {
            "duration": round(random.uniform(5.0, 15.0), 3),
            "total_packets": random.randint(1, 3),
            "total_bytes": random.randint(9000, 15000),
            "avg_packet_size": random.randint(4000, 7000),
            "syn_count": 0,
            "ack_count": 1,
            "fin_count": 0,
            "packets_per_sec": random.randint(1, 5),
            "bytes_per_sec": random.randint(8000, 12000),
            "source_ip": src,
            "destination_ip": dst,
            "source_port": random.randint(1024, 65535),
            "destination_port": random.randint(1024, 65535),
            "protocol": "UDP"
        }
    else: # normal
        packets = random.randint(10, 30)
        bytes_total = packets * random.randint(300, 800)
        dur = round(random.uniform(0.5, 3.0), 3)
        return {
            "duration": dur,
            "total_packets": packets,
            "total_bytes": bytes_total,
            "avg_packet_size": random.randint(300, 800),
            "syn_count": 1,
            "ack_count": packets - 2,
            "fin_count": 1,
            "packets_per_sec": int(packets / dur),
            "bytes_per_sec": int(bytes_total / dur),
            "source_ip": src,
            "destination_ip": dst,
            "source_port": random.randint(1024, 65535),
            "destination_port": random.choice([80, 443, 8080]),
            "protocol": "TCP"
        }

def main():
    print("Starting continuous NIDS demo traffic simulator...")
    attack_choices = ["normal", "normal", "normal", "port_scan", "ddos", "brute_force", "anomaly"]
    count = 0
    try:
        while True:
            choice = random.choice(attack_choices)
            payload = generate_flow_payload(choice)
            res = process_flow(payload, persist_traffic=True)
            count += 1
            attack_name = res.get("attack_name", "unknown")
            is_anomaly = res.get("is_anomaly", False)
            conf = res.get("confidence", 0.0)
            print(f"[{count}] Processed flow: intent={choice} -> predicted={attack_name} (conf={conf:.2f}, anomaly={is_anomaly})")
            time.sleep(2.0)
    except KeyboardInterrupt:
        print("\nSimulator stopped.")

if __name__ == "__main__":
    main()
