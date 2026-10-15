"""
Downloads the real-world NSL-KDD benchmark dataset, maps its 41 network features
to our platform's 9 flow features, and outputs backend/real_nsl_kdd.csv.
"""
import urllib.request
import os
import pandas as pd
import numpy as np

NSL_KDD_URL = "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain+.txt"
OUTPUT_CSV = os.path.join(os.path.dirname(__file__), "..", "backend", "real_nsl_kdd.csv")

# Attack type mapping to our 4 target labels
ATTACK_MAPPING = {
    "normal": "normal",
    
    # DoS / DDoS attacks
    "neptune": "ddos",
    "smurf": "ddos",
    "back": "ddos",
    "pod": "ddos",
    "teardrop": "ddos",
    "land": "ddos",
    "apache2": "ddos",
    "mailbomb": "ddos",
    "processtable": "ddos",
    "udpstorm": "ddos",
    
    # Port Scans / Probes
    "portsweep": "port_scan",
    "ipsweep": "port_scan",
    "nmap": "port_scan",
    "satan": "port_scan",
    "mscan": "port_scan",
    "saint": "port_scan",
    
    # Brute Force / Unauthorized Access
    "guess_passwd": "brute_force",
    "ftp_write": "brute_force",
    "imap": "brute_force",
    "phf": "brute_force",
    "multihop": "brute_force",
    "warezmaster": "brute_force",
    "warezclient": "brute_force",
    "spy": "brute_force",
    "snmpguess": "brute_force",
    "httptunnel": "brute_force",
    "sendmail": "brute_force",
    "named": "brute_force",
    "xlock": "brute_force",
    "xsnoop": "brute_force",
    "buffer_overflow": "brute_force",
    "loadmodule": "brute_force",
    "rootkit": "brute_force",
    "perl": "brute_force",
    "sqlattack": "brute_force",
    "xterm": "brute_force",
    "ps": "brute_force"
}

COLUMN_NAMES = [
    "duration_raw", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "raw_label", "difficulty"
]


LOCAL_CACHE_FILE = r"C:\Users\Gayathri\.gemini\antigravity-ide\brain\4d4906aa-9c87-432b-a31b-9f774edf676a\.system_generated\steps\120\content.md"

def download_and_convert():
    print(f"Processing NSL-KDD benchmark dataset...")
    if os.path.exists(LOCAL_CACHE_FILE):
        print(f"Reading cached dataset from {LOCAL_CACHE_FILE}")
        with open(LOCAL_CACHE_FILE, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith("Title:") and not line.startswith("Description:") and not line.startswith("Source:") and not line.startswith("---")]
        from io import StringIO
        content = "\n".join(lines)
        df_raw = pd.read_csv(StringIO(content), header=None, names=COLUMN_NAMES)
    else:
        req = urllib.request.Request(NSL_KDD_URL, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        with urllib.request.urlopen(req) as response:
            content = response.read().decode('utf-8')
        from io import StringIO
        df_raw = pd.read_csv(StringIO(content), header=None, names=COLUMN_NAMES)
        
    print(f"Loaded {len(df_raw)} raw records.")



    # Map raw attack names to target labels
    df_raw["label"] = df_raw["raw_label"].map(ATTACK_MAPPING).fillna("normal")

    # Map NSL-KDD attributes to platform's 9 flow features
    duration = np.maximum(df_raw["duration_raw"].astype(float), 0.001)
    src_bytes = df_raw["src_bytes"].astype(float)
    dst_bytes = df_raw["dst_bytes"].astype(float)
    total_bytes = src_bytes + dst_bytes

    # Packet counts estimation based on bytes and count fields
    total_packets = np.maximum(df_raw["count"].astype(float) + df_raw["srv_count"].astype(float), 1)
    avg_packet_size = total_bytes / total_packets
    avg_packet_size = np.clip(avg_packet_size, 40, 1500)

    # Estimate TCP flags from flag field & error rates
    syn_count = np.where(df_raw["flag"].isin(["S0", "S1", "S2", "S3"]), total_packets * 0.8, 1.0)
    ack_count = np.where(df_raw["flag"].isin(["SF", "ACK"]), total_packets * 0.8, 1.0)
    fin_count = np.where(df_raw["flag"].isin(["SF", "RSTO", "RSTR"]), 1.0, 0.0)

    packets_per_sec = total_packets / duration
    bytes_per_sec = total_bytes / duration

    df_out = pd.DataFrame({
        "duration": duration,
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "avg_packet_size": avg_packet_size,
        "syn_count": syn_count,
        "ack_count": ack_count,
        "fin_count": fin_count,
        "packets_per_sec": packets_per_sec,
        "bytes_per_sec": bytes_per_sec,
        "label": df_raw["label"]
    })

    # Filter out extreme outliers to ensure clean scaling
    df_out = df_out[
        (df_out["packets_per_sec"] < 1e6) & 
        (df_out["bytes_per_sec"] < 1e8)
    ].reset_index(drop=True)

    df_out.to_csv(OUTPUT_CSV, index=False)
    print(f"\nSuccessfully converted and saved {len(df_out)} records to {OUTPUT_CSV}")
    print("\nClass breakdown:")
    print(df_out["label"].value_counts())


if __name__ == "__main__":
    download_and_convert()
