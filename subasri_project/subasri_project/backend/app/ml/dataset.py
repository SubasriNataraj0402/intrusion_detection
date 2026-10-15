"""
Synthetic labeled flow-feature dataset generator.

There is no bundled real-world attack capture, so this module generates flow-level
feature vectors whose statistical shape mirrors well-documented behavior of each
traffic class (e.g. port scans produce many short flows with high SYN counts and
near-zero bytes; DDoS floods produce very high packets/sec with tiny average packet
size; brute force produces many short-lived flows to a single port with high ACK
counts). It is meant to make the pipeline trainable and demonstrable end-to-end,
not to substitute for training on a real captured/labeled dataset (e.g. CICIDS2017)
before any production use.
"""
import numpy as np
import pandas as pd

FEATURE_COLUMNS = [
    "duration",
    "total_packets",
    "total_bytes",
    "avg_packet_size",
    "syn_count",
    "ack_count",
    "fin_count",
    "packets_per_sec",
    "bytes_per_sec",
]

LABELS = ["normal", "port_scan", "ddos", "brute_force"]


def _clip_nonneg(arr):
    return np.clip(arr, 0, None)


def _make_normal_bulk(n, rng):
    """Longer-lived normal sessions (WAN/LAN-scale): downloads, streaming,
    multi-request keep-alive connections."""
    duration = rng.gamma(3.0, 2.0, n)
    total_packets = rng.poisson(30, n) + 1
    avg_packet_size = rng.normal(500, 150, n)
    avg_packet_size = np.clip(avg_packet_size, 40, 1500)
    total_bytes = total_packets * avg_packet_size
    syn_count = rng.poisson(1, n) + 1
    ack_count = _clip_nonneg(total_packets - syn_count - rng.poisson(1, n))
    fin_count = rng.binomial(1, 0.6, n)
    duration = _clip_nonneg(duration) + 0.05
    packets_per_sec = total_packets / duration
    bytes_per_sec = total_bytes / duration
    return duration, total_packets, total_bytes, avg_packet_size, syn_count, ack_count, fin_count, packets_per_sec, bytes_per_sec


def _make_normal_fast(n, rng):
    """Fast single request/response flows: local API calls, health checks,
    loopback traffic, same-datacenter microservice calls. Sub-50ms round
    trips push packets/sec and bytes/sec very high despite being entirely
    benign — the discriminating signal is a clean handshake/close shape
    (one connection's worth of SYN/SYN-ACK, data, then a FIN close), not
    raw rate. Since flows are tracked bidirectionally, a normal handshake
    contributes ~2 SYN-flagged packets (the SYN and the SYN-ACK)."""
    duration = rng.uniform(0.0003, 0.05, n)
    total_packets = rng.poisson(6, n) + 3
    avg_packet_size = rng.normal(250, 90, n)
    avg_packet_size = np.clip(avg_packet_size, 40, 1200)
    total_bytes = total_packets * avg_packet_size
    syn_count = rng.choice([1, 2], size=n, p=[0.15, 0.85])
    fin_count = rng.choice([0, 1], size=n, p=[0.1, 0.9])
    ack_count = _clip_nonneg(total_packets - syn_count - fin_count)
    packets_per_sec = total_packets / duration
    bytes_per_sec = total_bytes / duration
    return duration, total_packets, total_bytes, avg_packet_size, syn_count, ack_count, fin_count, packets_per_sec, bytes_per_sec


def _make_normal(n, rng):
    half = n // 2
    bulk = _make_normal_bulk(n - half, rng)
    fast = _make_normal_fast(half, rng)
    return tuple(np.concatenate([b, f]) for b, f in zip(bulk, fast))


def _make_port_scan(n, rng):
    """Covers both scan styles: stealth/half-open (attacker only ever sends
    bare SYNs, no reply captured on their side) and full-connect scans
    against closed ports (SYN out, RST/ACK back — 2 packets, no data, no
    clean FIN close)."""
    duration = rng.uniform(0.0002, 0.3, n)
    is_full_connect = rng.random(n) < 0.5

    total_packets = np.where(is_full_connect, 2, rng.poisson(1, n) + 1)
    avg_packet_size = rng.normal(55, 12, n)
    avg_packet_size = np.clip(avg_packet_size, 40, 100)
    total_bytes = total_packets * avg_packet_size
    syn_count = np.where(is_full_connect, 1, total_packets)
    ack_count = np.where(is_full_connect, 1, 0)
    fin_count = np.zeros(n)
    packets_per_sec = total_packets / duration
    bytes_per_sec = total_bytes / duration
    return duration, total_packets, total_bytes, avg_packet_size, syn_count, ack_count, fin_count, packets_per_sec, bytes_per_sec


def _make_ddos(n, rng):
    duration = rng.uniform(0.05, 2.0, n)
    total_packets = rng.poisson(5000, n) + 500
    avg_packet_size = rng.normal(80, 20, n)
    avg_packet_size = np.clip(avg_packet_size, 40, 200)
    total_bytes = total_packets * avg_packet_size
    syn_count = (total_packets * rng.uniform(0.6, 0.95, n)).astype(int)
    ack_count = _clip_nonneg(total_packets - syn_count)
    fin_count = np.zeros(n)
    packets_per_sec = total_packets / duration
    bytes_per_sec = total_bytes / duration
    return duration, total_packets, total_bytes, avg_packet_size, syn_count, ack_count, fin_count, packets_per_sec, bytes_per_sec


def _make_brute_force(n, rng):
    duration = rng.uniform(0.2, 3.0, n)
    total_packets = rng.poisson(12, n) + 4
    avg_packet_size = rng.normal(150, 40, n)
    avg_packet_size = np.clip(avg_packet_size, 60, 400)
    total_bytes = total_packets * avg_packet_size
    syn_count = rng.poisson(1, n) + 1
    ack_count = _clip_nonneg(total_packets - syn_count)
    fin_count = rng.binomial(1, 0.3, n)
    packets_per_sec = total_packets / duration
    bytes_per_sec = total_bytes / duration
    return duration, total_packets, total_bytes, avg_packet_size, syn_count, ack_count, fin_count, packets_per_sec, bytes_per_sec


_GENERATORS = {
    "normal": _make_normal,
    "port_scan": _make_port_scan,
    "ddos": _make_ddos,
    "brute_force": _make_brute_force,
}


def generate_dataset(n_per_class: int = 5000, seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    frames = []
    for label, gen in _GENERATORS.items():
        cols = gen(n_per_class, rng)
        df = pd.DataFrame(dict(zip(FEATURE_COLUMNS, cols)))
        df["label"] = label
        frames.append(df)
    full = pd.concat(frames, ignore_index=True)
    full = full.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    return full


def export_dataset_to_csv(output_path: str = "dataset.csv", n_per_class: int = 5000, seed: int = 42) -> str:
    """Generates the synthetic flow feature dataset and exports it to a CSV file."""
    df = generate_dataset(n_per_class=n_per_class, seed=seed)
    df.to_csv(output_path, index=False)
    print(f"Exported {len(df)} samples ({n_per_class} per class) to {output_path}")
    return output_path


if __name__ == "__main__":
    import sys
    out_file = sys.argv[1] if len(sys.argv) > 1 else "dataset.csv"
    export_dataset_to_csv(output_path=out_file)

