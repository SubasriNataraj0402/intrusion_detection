import logging
import threading
from typing import Callable, Optional

from app.config import settings
from app.capture.flow_tracker import FlowTracker

logger = logging.getLogger("nids.capture")


class PacketSniffer:
    """Live packet capture using Scapy.

    Requires elevated privileges (run the backend with sudo, or grant the
    interpreter CAP_NET_RAW/CAP_NET_ADMIN on Linux) and a real network
    interface (settings.capture_interface, e.g. 'en0' on macOS, 'eth0' on
    Linux). If capture cannot start (no permission, bad interface), this
    logs a clear error instead of crashing the API process.
    """

    def __init__(self, on_flow_complete: Callable[[dict], None]):
        self.tracker = FlowTracker(on_flow_complete)
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def _handle_packet(self, pkt):
        try:
            from scapy.layers.inet import IP, TCP, UDP
        except ImportError:
            return

        if IP not in pkt:
            return
        ip = pkt[IP]
        size = len(pkt)

        if TCP in pkt:
            tcp = pkt[TCP]
            sport, dport = int(tcp.sport), int(tcp.dport)
            if sport in settings.capture_exclude_ports or dport in settings.capture_exclude_ports:
                return
            flags = tcp.flags
            self.tracker.add_packet(
                ip.src, ip.dst, sport, dport, "TCP", size,
                syn=bool(flags & 0x02), ack=bool(flags & 0x10), fin=bool(flags & 0x01),
            )
        elif UDP in pkt:
            udp = pkt[UDP]
            sport, dport = int(udp.sport), int(udp.dport)
            if sport in settings.capture_exclude_ports or dport in settings.capture_exclude_ports:
                return
            self.tracker.add_packet(
                ip.src, ip.dst, sport, dport, "UDP", size,
                syn=False, ack=False, fin=False,
            )
        else:
            self.tracker.add_packet(ip.src, ip.dst, 0, 0, "OTHER", size, False, False, False)

    def _run(self):
        try:
            from scapy.all import sniff
        except ImportError:
            logger.error("scapy is not installed; live capture disabled")
            return
        try:
            sniff(
                iface=settings.capture_interface,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _pkt: self._stop.is_set(),
            )
        except PermissionError:
            logger.error(
                "Permission denied opening interface '%s'. Live packet capture needs "
                "root/admin privileges — restart the backend with sudo (macOS/Linux) "
                "or run as Administrator (Windows).",
                settings.capture_interface,
            )
        except OSError as exc:
            logger.error(
                "Could not open interface '%s': %s. Check CAPTURE_INTERFACE in .env "
                "matches a real interface (see `ifconfig`/`ip link`).",
                settings.capture_interface, exc,
            )

    def start(self):
        if not settings.capture_enabled:
            logger.info("Live capture disabled (CAPTURE_ENABLED=false); skipping sniffer start.")
            return
        self.tracker.start()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("Started packet capture on interface '%s'.", settings.capture_interface)

    def stop(self):
        self._stop.set()
        self.tracker.stop()
