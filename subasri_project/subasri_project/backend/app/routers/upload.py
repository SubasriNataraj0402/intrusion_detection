import tempfile
import os

from fastapi import APIRouter, Depends, UploadFile, File, HTTPException

from app.capture.flow_tracker import FlowTracker
from app.models import User
from app.pipeline import process_flow
from app.security import get_current_user

router = APIRouter(tags=["upload"])

MAX_UPLOAD_BYTES = 50 * 1024 * 1024


@router.post("/upload-pcap")
async def upload_pcap(file: UploadFile = File(...), _user: User = Depends(get_current_user)):
    if not file.filename.endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="File must be a .pcap/.pcapng/.cap capture")

    contents = await file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="File too large (max 50MB)")

    try:
        from scapy.all import rdpcap
        from scapy.layers.inet import IP, TCP, UDP
    except ImportError:
        raise HTTPException(status_code=500, detail="scapy is not installed on the server")

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(contents)
            tmp_path = tmp.name

        packets = rdpcap(tmp_path)

        results = []

        def on_flow(features: dict):
            outcome = process_flow(features, persist_traffic=True)
            if "error" not in outcome:
                results.append({**features, **outcome})

        tracker = FlowTracker(on_flow)
        for pkt in packets:
            if IP not in pkt:
                continue
            ip = pkt[IP]
            size = len(pkt)
            if TCP in pkt:
                tcp = pkt[TCP]
                flags = tcp.flags
                tracker.add_packet(
                    ip.src, ip.dst, int(tcp.sport), int(tcp.dport), "TCP", size,
                    syn=bool(flags & 0x02), ack=bool(flags & 0x10), fin=bool(flags & 0x01),
                )
            elif UDP in pkt:
                udp = pkt[UDP]
                tracker.add_packet(ip.src, ip.dst, int(udp.sport), int(udp.dport), "UDP", size, False, False, False)
            else:
                tracker.add_packet(ip.src, ip.dst, 0, 0, "OTHER", size, False, False, False)
        tracker.flush_all()

        return {"flows_processed": len(results), "results": results}
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
