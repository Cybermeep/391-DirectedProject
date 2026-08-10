"""
Packet-count tracker, bucketed by hour, persisted to app.db
"""

from collections import defaultdict
from datetime import datetime
from threading import Lock

from sqlalchemy import Column, String, Integer

from auth.models import Base, get_auth_session

FLUSH_INTERVAL_SECONDS = 30

_lock = Lock()
_hourly_counts = defaultdict(int)
_loaded_from_db = False
_last_flush = 0.0


class PacketHourlyStat(Base):
    """One row per hour-bucket, holding the packet count seen in that hour."""

    __tablename__ = "packet_hourly_stats"

    hour_key = Column(String(20), primary_key=True)  # 'YYYY-MM-DD HH:00'
    packet_count = Column(Integer, default=0)


def _load_from_db() -> None:
    global _loaded_from_db
    session = get_auth_session()
    try:
        for row in session.query(PacketHourlyStat).all():
            _hourly_counts[row.hour_key] = row.packet_count
        _loaded_from_db = True
    except Exception:

        pass
    finally:
        session.close()


def _flush_to_db() -> None:
    session = get_auth_session()
    try:
        with _lock:
            snapshot = dict(_hourly_counts)
        for hour_key, count in snapshot.items():
            existing = session.query(PacketHourlyStat).filter_by(hour_key=hour_key).first()
            if existing:
                existing.packet_count = count
            else:
                session.add(PacketHourlyStat(hour_key=hour_key, packet_count=count))
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


def record_packet(when: datetime = None) -> None:
    global _last_flush

    if not _loaded_from_db:
        _load_from_db()

    when = when or datetime.utcnow()
    hour_key = when.strftime('%Y-%m-%d %H:00')
    with _lock:
        _hourly_counts[hour_key] += 1

    now_ts = when.timestamp()
    if now_ts - _last_flush > FLUSH_INTERVAL_SECONDS:
        _last_flush = now_ts
        _flush_to_db()


def get_hourly_counts() -> dict:
    if not _loaded_from_db:
        _load_from_db()
    with _lock:
        return dict(_hourly_counts)
