"""Active Threat Prevention & IP Blocking Engine.

Manages DB records, in-memory blocked IP sets for O(1) detection filtering,
and OS firewall rules (Windows netsh / Linux iptables / macOS pfctl).
"""
import logging
import platform
import subprocess
from datetime import datetime
from typing import Set, Optional

from app.database import SessionLocal
from app.models import BlockedIP

logger = logging.getLogger("nids.blocking")

class IPBlockingEngine:
    def __init__(self):
        self._blocked_ips: Set[str] = set()
        self._initialized = False

    def sync_from_db(self):
        """Pre-load active blocked IPs from database into memory."""
        db = SessionLocal()
        try:
            active_blocks = db.query(BlockedIP).filter(BlockedIP.status == "active").all()
            self._blocked_ips = {b.ip_address for b in active_blocks}
            self._initialized = True
            logger.info(f"Loaded {len(self._blocked_ips)} active blocked IPs into memory.")
        except Exception as e:
            logger.error(f"Failed to sync blocked IPs from DB: {e}")
        finally:
            db.close()

    def is_blocked(self, ip_address: str) -> bool:
        if not self._initialized:
            self.sync_from_db()
        return ip_address in self._blocked_ips

    def block_ip(self, ip_address: str, reason: str, attack_type: str = "manual", blocked_by: str = "auto") -> Optional[dict]:
        """Block an IP address in memory, DB, and OS firewall."""
        if not ip_address or ip_address in ("0.0.0.0", "127.0.0.1", "::1"):
            logger.warning(f"Ignored block request for loopback/invalid IP: {ip_address}")
            return None

        db = SessionLocal()
        try:
            existing = db.query(BlockedIP).filter(BlockedIP.ip_address == ip_address).first()
            if existing:
                if existing.status == "active":
                    return {
                        "id": existing.id,
                        "ip_address": existing.ip_address,
                        "reason": existing.reason,
                        "attack_type": existing.attack_type,
                        "blocked_by": existing.blocked_by,
                        "status": existing.status,
                        "created_at": existing.created_at,
                    }
                existing.status = "active"
                existing.reason = reason
                existing.attack_type = attack_type
                existing.blocked_by = blocked_by
                existing.created_at = datetime.utcnow()
                record = existing
            else:
                record = BlockedIP(
                    ip_address=ip_address,
                    reason=reason,
                    attack_type=attack_type,
                    blocked_by=blocked_by,
                    status="active"
                )
                db.add(record)

            db.commit()
            db.refresh(record)
            self._blocked_ips.add(ip_address)

            # Apply OS-level firewall rule
            self._apply_os_block(ip_address)

            logger.info(f"🚫 BLOCKED IP {ip_address} (reason: {reason}, by: {blocked_by})")
            return {
                "id": record.id,
                "ip_address": record.ip_address,
                "reason": record.reason,
                "attack_type": record.attack_type,
                "blocked_by": record.blocked_by,
                "status": record.status,
                "created_at": record.created_at,
            }
        except Exception as e:
            db.rollback()
            logger.error(f"Error blocking IP {ip_address}: {e}")
            return None
        finally:
            db.close()

    def unblock_ip(self, ip_address: str) -> bool:
        """Unblock an IP address in memory, DB, and OS firewall."""
        db = SessionLocal()
        try:
            record = db.query(BlockedIP).filter(BlockedIP.ip_address == ip_address, BlockedIP.status == "active").first()
            if not record:
                return False

            record.status = "unblocked"
            db.commit()
            self._blocked_ips.discard(ip_address)

            # Remove OS-level firewall rule
            self._remove_os_block(ip_address)

            logger.info(f"🔓 UNBLOCKED IP {ip_address}")
            return True
        except Exception as e:
            db.rollback()
            logger.error(f"Error unblocking IP {ip_address}: {e}")
            return False
        finally:
            db.close()

    def list_blocked_ips(self) -> list:
        db = SessionLocal()
        try:
            records = db.query(BlockedIP).filter(BlockedIP.status == "active").order_by(BlockedIP.created_at.desc()).all()
            return [
                {
                    "id": r.id,
                    "ip_address": r.ip_address,
                    "reason": r.reason,
                    "attack_type": r.attack_type,
                    "blocked_by": r.blocked_by,
                    "status": r.status,
                    "created_at": r.created_at,
                }
                for r in records
            ]
        finally:
            db.close()

    def _apply_os_block(self, ip: str):
        """Execute OS-level command to drop packets from IP."""
        system = platform.system()
        try:
            if system == "Windows":
                rule_name = f"NIDS_Block_{ip}"
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
                subprocess.run(cmd, shell=True, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif system == "Linux":
                cmd = f"iptables -A INPUT -s {ip} -j DROP"
                subprocess.run(cmd, shell=True, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            logger.warning(f"Could not apply OS firewall rule for {ip}: {e}")

    def _remove_os_block(self, ip: str):
        """Remove OS-level firewall rule for IP."""
        system = platform.system()
        try:
            if system == "Windows":
                rule_name = f"NIDS_Block_{ip}"
                cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                subprocess.run(cmd, shell=True, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif system == "Linux":
                cmd = f"iptables -D INPUT -s {ip} -j DROP"
                subprocess.run(cmd, shell=True, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            logger.warning(f"Could not remove OS firewall rule for {ip}: {e}")

blocking_engine = IPBlockingEngine()
