import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from app.config import settings


@dataclass
class Flow:
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    start_time: float
    last_seen: float
    total_packets: int = 0
    total_bytes: int = 0
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0

    def to_features(self) -> dict:
        duration = max(self.last_seen - self.start_time, 1e-3)
        avg_packet_size = self.total_bytes / max(self.total_packets, 1)
        return {
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "duration": round(duration, 4),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "avg_packet_size": round(avg_packet_size, 2),
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "fin_count": self.fin_count,
            "packets_per_sec": round(self.total_packets / duration, 2),
            "bytes_per_sec": round(self.total_bytes / duration, 2),
        }


class FlowTracker:
    """Aggregates raw packets into bidirectional flows keyed by 5-tuple.

    A flow is emitted (via on_flow_complete) when it sees a FIN, or after
    settings.flow_timeout_seconds of inactivity (reaped by a background thread).
    This mirrors how NetFlow/CICFlowMeter-style exporters bucket packets before
    computing flow-level ML features.
    """

    def __init__(self, on_flow_complete: Callable[[dict], None]):
        self._flows: dict[tuple, Flow] = {}
        self._lock = threading.Lock()
        self._on_flow_complete = on_flow_complete
        self._stop = threading.Event()
        self._reaper = threading.Thread(target=self._reap_loop, daemon=True)

    def start(self):
        self._reaper.start()

    def stop(self):
        self._stop.set()

    def _key(self, src_ip, dst_ip, sport, dport, proto):
        # Canonicalize direction so both sides of a conversation share one flow.
        a = (src_ip, sport)
        b = (dst_ip, dport)
        if a <= b:
            return (a, b, proto)
        return (b, a, proto)

    def add_packet(self, src_ip, dst_ip, sport, dport, proto, size, syn, ack, fin):
        now = time.time()
        key = self._key(src_ip, dst_ip, sport, dport, proto)
        with self._lock:
            flow = self._flows.get(key)
            if flow is None and proto == "TCP" and not syn:
                # A non-SYN packet with no matching open flow is almost always a
                # stray piece of a TCP connection's close sequence (the final
                # ACK arriving just after the flow already completed on FIN) —
                # not the start of a new conversation. Starting a phantom flow
                # for it produces bogus 1-2 packet "flows" that look identical
                # to a port scan. Drop it instead, matching how NetFlow-style
                # exporters bound a flow's lifetime to SYN...FIN/timeout.
                return
            if flow is None:
                flow = Flow(
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=sport,
                    destination_port=dport,
                    protocol=proto,
                    start_time=now,
                    last_seen=now,
                )
                self._flows[key] = flow

            flow.total_packets += 1
            flow.total_bytes += size
            flow.last_seen = now
            if syn:
                flow.syn_count += 1
            if ack:
                flow.ack_count += 1
            if fin:
                flow.fin_count += 1

            finished = None
            if fin:
                finished = self._flows.pop(key, None)

        if finished is not None:
            self._on_flow_complete(finished.to_features())

    def flush_all(self):
        """Force-complete every currently open flow immediately (used for offline
        pcap replay, where there's no live reaper thread to wait on)."""
        with self._lock:
            remaining = list(self._flows.values())
            self._flows.clear()
        for flow in remaining:
            self._on_flow_complete(flow.to_features())

    def _reap_loop(self):
        while not self._stop.is_set():
            time.sleep(2)
            now = time.time()
            expired = []
            with self._lock:
                for key, flow in list(self._flows.items()):
                    if now - flow.last_seen > settings.flow_timeout_seconds:
                        expired.append(self._flows.pop(key))
            for flow in expired:
                self._on_flow_complete(flow.to_features())
