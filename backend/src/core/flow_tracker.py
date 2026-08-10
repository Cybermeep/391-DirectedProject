"""
Tracks in-progress network flows in memory and hands completed ones off
for feature computation
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Callable

from ml_pipeline.live_features import PacketRecord

FlowKey = Tuple[str, str, int, int, int]  # (ip_a, ip_b, port_a, port_b, protocol) - normalized

# A flow with no new packets for this long is considered finished even
# without seeing FIN/RST (e.g. UDP, or a TCP connection that just stops).
DEFAULT_IDLE_TIMEOUT_SECONDS = 15.0

MAX_FLOW_DURATION_SECONDS = 120.0

# Safety cap on total tracked flows so a real flood can't exhaust memory
# on the capture host itself.
MAX_ACTIVE_FLOWS = 5000


@dataclass
class _ActiveFlow:
    dst_port: int
    protocol: int
    initiator_ip: str
    responder_ip: str
    records: List[PacketRecord] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0


def make_flow_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int) -> Tuple[FlowKey, str]:

    if (src_ip, src_port) <= (dst_ip, dst_port):
        key = (src_ip, dst_ip, src_port, dst_port, protocol)
        return key, "fwd"
    else:
        key = (dst_ip, src_ip, dst_port, src_port, protocol)
        return key, "bwd"


class LiveFlowTracker:


    def __init__(
        self,
        on_flow_complete: Callable[[List[PacketRecord], int, int, str, str], None],
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT_SECONDS,
        max_flow_duration: float = MAX_FLOW_DURATION_SECONDS,
    ):
        self._flows: Dict[FlowKey, _ActiveFlow] = {}
        self._on_flow_complete = on_flow_complete
        self._idle_timeout = idle_timeout
        self._max_flow_duration = max_flow_duration

        self._initiators: Dict[FlowKey, Tuple[str, int]] = {}

    def add_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        record: PacketRecord,
        now: Optional[float] = None,
    ) -> None:
        now = now if now is not None else time.time()
        key, _ = make_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)

        if key not in self._flows:
            if len(self._flows) >= MAX_ACTIVE_FLOWS:
                # Drop the oldest flow rather than let memory grow
                # unbounded during a real flood.
                oldest_key = min(self._flows, key=lambda k: self._flows[k].first_seen)
                self._finish_flow(oldest_key)

            self._initiators[key] = (src_ip, src_port)
            self._flows[key] = _ActiveFlow(
                dst_port=dst_port, protocol=protocol,
                initiator_ip=src_ip, responder_ip=dst_ip,
                first_seen=now,
            )

        flow = self._flows[key]
        initiator_ip, initiator_port = self._initiators[key]
        record.direction = "fwd" if (src_ip, src_port) == (initiator_ip, initiator_port) else "bwd"

        flow.records.append(record)
        flow.last_seen = now

        if record.fin or record.rst:
            self._finish_flow(key)
        elif now - flow.first_seen > self._max_flow_duration:
            self._finish_flow(key)

    def reap_idle_flows(self, now: Optional[float] = None) -> int:
        """Call periodically (e.g. once a second) to flush flows that have gone quiet."""
        now = now if now is not None else time.time()
        to_finish = [
            key for key, flow in self._flows.items() if now - flow.last_seen > self._idle_timeout
        ]
        for key in to_finish:
            self._finish_flow(key)
        return len(to_finish)

    def active_flow_count(self) -> int:
        return len(self._flows)

    def _finish_flow(self, key: FlowKey) -> None:
        flow = self._flows.pop(key, None)
        self._initiators.pop(key, None)
        if flow and flow.records:
            self._on_flow_complete(flow.records, flow.dst_port, flow.protocol, flow.initiator_ip, flow.responder_ip)
