"""
Live flow feature computation - the missing link between raw capture and
the trained model / rule engine.

IMPORTANT CONTEXT (see AUDIT.md for the full writeup): the pre-existing
`feature_extraction/` package (basic_features.py, count_features.py, etc.)
produces a *different* schema (snake_case keys like `syn_count`,
`total_duration`) than what the trained model expects (CICFlowMeter-style
keys like `SYN_Flag_Cnt`, `Flow_Duration`). The two were never actually
wired together. Rather than bolt a translation layer onto extractors
whose semantics don't line up, this module computes the model's exact
78-field schema directly from raw packet timing/length/flag data.

This prioritizes *internal consistency* - so rule thresholds you
calibrate against your own live traffic behave predictably - over
guaranteed byte-for-byte parity with whatever the original CICFlowMeter
tool computed when the training set was built. Two conventions in
particular are assumptions, called out below:

  1. Duration/IAT fields are in MICROSECONDS (the common convention for
     the CSE-CIC-IDS2018 dataset this model was trained on).
  2. "Bulk transfer" fields (Fwd_Byts/b_Avg etc.) and true multi-subflow
     stats are approximated as 0 / single-subflow, since they require
     CICFlowMeter's specific bulk-detection heuristic and rarely matter
     for short demo flows.

If you need publication-grade parity, capture a pcap, run the real
CICFlowMeter tool on it, and compare column-by-column against
`compute_flow_features` on the same packets.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

# Idle-period threshold: a gap between consecutive packets longer than
# this is considered "idle" time rather than part of an "active" burst,
# matching CICFlowMeter's default of 1,000,000 microseconds (1 second).
IDLE_THRESHOLD_US = 1_000_000.0


@dataclass
class PacketRecord:
    """
    A minimal, scapy-independent representation of one captured packet,
    used as the unit of input to flow tracking and feature computation.
    Keeping this decoupled from scapy means the feature math below can be
    fully unit-tested without scapy/Npcap installed.
    """

    timestamp: float  # seconds, e.g. time.time()
    length: int  # total packet length in bytes
    direction: str  # 'fwd' or 'bwd'
    header_len: int = 40  # IP + TCP/UDP header bytes (approximate if unknown)
    payload_len: int = 0
    tcp_window: Optional[int] = None
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False
    psh: bool = False
    urg: bool = False
    ece: bool = False
    cwe: bool = False


def _safe_mean(values: List[float]) -> float:
    return float(statistics.fmean(values)) if values else 0.0


def _safe_std(values: List[float]) -> float:
    return float(statistics.pstdev(values)) if len(values) > 1 else 0.0


def _iat_stats(timestamps_us: List[float]) -> Dict[str, float]:
    """Inter-arrival-time stats (microseconds) for a sorted list of packet timestamps."""
    if len(timestamps_us) < 2:
        return {"tot": 0.0, "mean": 0.0, "std": 0.0, "max": 0.0, "min": 0.0}
    diffs = [b - a for a, b in zip(timestamps_us, timestamps_us[1:])]
    return {
        "tot": sum(diffs),
        "mean": _safe_mean(diffs),
        "std": _safe_std(diffs),
        "max": max(diffs),
        "min": min(diffs),
    }


def _active_idle_stats(timestamps_us: List[float]) -> Dict[str, Dict[str, float]]:
    """
    Split a flow's packet timestamps into alternating active bursts / idle
    gaps (CICFlowMeter-style), and return mean/std/max/min for each.
    """
    if len(timestamps_us) < 2:
        return {
            "active": {"mean": 0.0, "std": 0.0, "max": 0.0, "min": 0.0},
            "idle": {"mean": 0.0, "std": 0.0, "max": 0.0, "min": 0.0},
        }

    active_durations: List[float] = []
    idle_durations: List[float] = []

    burst_start = timestamps_us[0]
    last_ts = timestamps_us[0]

    for ts in timestamps_us[1:]:
        gap = ts - last_ts
        if gap > IDLE_THRESHOLD_US:
            active_durations.append(last_ts - burst_start)
            idle_durations.append(gap)
            burst_start = ts
        last_ts = ts

    active_durations.append(last_ts - burst_start)

    def _stats(vals: List[float]) -> Dict[str, float]:
        if not vals:
            return {"mean": 0.0, "std": 0.0, "max": 0.0, "min": 0.0}
        return {"mean": _safe_mean(vals), "std": _safe_std(vals), "max": max(vals), "min": min(vals)}

    return {"active": _stats(active_durations), "idle": _stats(idle_durations)}


def compute_flow_features(records: List[PacketRecord], dst_port: int, protocol: int) -> Dict[str, Any]:
    """
    Compute the model's full 78-feature schema for one completed flow.

    Args:
        records: packets belonging to this flow, in capture order.
        dst_port: destination port of the flow's initiating (forward) side.
        protocol: numeric IP protocol (6=TCP, 17=UDP, 1=ICMP).

    Returns:
        Dict matching rules.ast_nodes.FEATURE_FIELDS exactly.
    """
    if not records:
        return {}

    records = sorted(records, key=lambda r: r.timestamp)
    fwd = [r for r in records if r.direction == "fwd"]
    bwd = [r for r in records if r.direction == "bwd"]

    all_ts_us = [r.timestamp * 1_000_000 for r in records]
    fwd_ts_us = [r.timestamp * 1_000_000 for r in fwd]
    bwd_ts_us = [r.timestamp * 1_000_000 for r in bwd]

    duration_us = (all_ts_us[-1] - all_ts_us[0]) if len(all_ts_us) > 1 else 0.0
    duration_s = duration_us / 1_000_000.0

    fwd_lengths = [r.length for r in fwd]
    bwd_lengths = [r.length for r in bwd]
    all_lengths = [r.length for r in records]

    flow_iat = _iat_stats(all_ts_us)
    fwd_iat = _iat_stats(fwd_ts_us)
    bwd_iat = _iat_stats(bwd_ts_us)
    active_idle = _active_idle_stats(all_ts_us)

    total_bytes = sum(all_lengths)
    total_pkts = len(records)

    fwd_init_win = next((r.tcp_window for r in fwd if r.tcp_window is not None), 0) or 0
    bwd_init_win = next((r.tcp_window for r in bwd if r.tcp_window is not None), 0) or 0

    fwd_seg_sizes = [r.payload_len for r in fwd] or [0]
    bwd_seg_sizes = [r.payload_len for r in bwd] or [0]

    features = {
        "Dst_Port": dst_port,
        "Protocol": protocol,
        "Flow_Duration": duration_us,
        "Tot_Fwd_Pkts": len(fwd),
        "Tot_Bwd_Pkts": len(bwd),
        "TotLen_Fwd_Pkts": sum(fwd_lengths),
        "TotLen_Bwd_Pkts": sum(bwd_lengths),
        "Fwd_Pkt_Len_Max": max(fwd_lengths) if fwd_lengths else 0,
        "Fwd_Pkt_Len_Min": min(fwd_lengths) if fwd_lengths else 0,
        "Fwd_Pkt_Len_Mean": _safe_mean(fwd_lengths),
        "Fwd_Pkt_Len_Std": _safe_std(fwd_lengths),
        "Bwd_Pkt_Len_Max": max(bwd_lengths) if bwd_lengths else 0,
        "Bwd_Pkt_Len_Min": min(bwd_lengths) if bwd_lengths else 0,
        "Bwd_Pkt_Len_Mean": _safe_mean(bwd_lengths),
        "Bwd_Pkt_Len_Std": _safe_std(bwd_lengths),
        "Flow_Byts/s": (total_bytes / duration_s) if duration_s > 0 else 0.0,
        "Flow_Pkts/s": (total_pkts / duration_s) if duration_s > 0 else 0.0,
        "Flow_IAT_Mean": flow_iat["mean"],
        "Flow_IAT_Std": flow_iat["std"],
        "Flow_IAT_Max": flow_iat["max"],
        "Flow_IAT_Min": flow_iat["min"],
        "Fwd_IAT_Tot": fwd_iat["tot"],
        "Fwd_IAT_Mean": fwd_iat["mean"],
        "Fwd_IAT_Std": fwd_iat["std"],
        "Fwd_IAT_Max": fwd_iat["max"],
        "Fwd_IAT_Min": fwd_iat["min"],
        "Bwd_IAT_Tot": bwd_iat["tot"],
        "Bwd_IAT_Mean": bwd_iat["mean"],
        "Bwd_IAT_Std": bwd_iat["std"],
        "Bwd_IAT_Max": bwd_iat["max"],
        "Bwd_IAT_Min": bwd_iat["min"],
        "Fwd_PSH_Flags": sum(1 for r in fwd if r.psh),
        "Bwd_PSH_Flags": sum(1 for r in bwd if r.psh),
        "Fwd_URG_Flags": sum(1 for r in fwd if r.urg),
        "Bwd_URG_Flags": sum(1 for r in bwd if r.urg),
        "Fwd_Header_Len": sum(r.header_len for r in fwd),
        "Bwd_Header_Len": sum(r.header_len for r in bwd),
        "Fwd_Pkts/s": (len(fwd) / duration_s) if duration_s > 0 else 0.0,
        "Bwd_Pkts/s": (len(bwd) / duration_s) if duration_s > 0 else 0.0,
        "Pkt_Len_Min": min(all_lengths) if all_lengths else 0,
        "Pkt_Len_Max": max(all_lengths) if all_lengths else 0,
        "Pkt_Len_Mean": _safe_mean(all_lengths),
        "Pkt_Len_Std": _safe_std(all_lengths),
        "Pkt_Len_Var": (_safe_std(all_lengths) ** 2),
        "FIN_Flag_Cnt": sum(1 for r in records if r.fin),
        "SYN_Flag_Cnt": sum(1 for r in records if r.syn),
        "RST_Flag_Cnt": sum(1 for r in records if r.rst),
        "PSH_Flag_Cnt": sum(1 for r in records if r.psh),
        "ACK_Flag_Cnt": sum(1 for r in records if r.ack),
        "URG_Flag_Cnt": sum(1 for r in records if r.urg),
        "CWE_Flag_Count": sum(1 for r in records if r.cwe),
        "ECE_Flag_Cnt": sum(1 for r in records if r.ece),
        "Down/Up_Ratio": (len(bwd) / len(fwd)) if fwd else 0.0,
        "Pkt_Size_Avg": _safe_mean(all_lengths),
        "Fwd_Seg_Size_Avg": _safe_mean(fwd_seg_sizes),
        "Bwd_Seg_Size_Avg": _safe_mean(bwd_seg_sizes),
        # Bulk-transfer averages: approximated as 0 (see module docstring).
        "Fwd_Byts/b_Avg": 0.0,
        "Fwd_Pkts/b_Avg": 0.0,
        "Fwd_Blk_Rate_Avg": 0.0,
        "Bwd_Byts/b_Avg": 0.0,
        "Bwd_Pkts/b_Avg": 0.0,
        "Bwd_Blk_Rate_Avg": 0.0,
        # Single-subflow approximation (see module docstring).
        "Subflow_Fwd_Pkts": len(fwd),
        "Subflow_Fwd_Byts": sum(fwd_lengths),
        "Subflow_Bwd_Pkts": len(bwd),
        "Subflow_Bwd_Byts": sum(bwd_lengths),
        "Init_Fwd_Win_Byts": fwd_init_win,
        "Init_Bwd_Win_Byts": bwd_init_win,
        "Fwd_Act_Data_Pkts": sum(1 for r in fwd if r.payload_len > 0),
        "Fwd_Seg_Size_Min": min(fwd_lengths) if fwd_lengths else 0,
        "Active_Mean": active_idle["active"]["mean"],
        "Active_Std": active_idle["active"]["std"],
        "Active_Max": active_idle["active"]["max"],
        "Active_Min": active_idle["active"]["min"],
        "Idle_Mean": active_idle["idle"]["mean"],
        "Idle_Std": active_idle["idle"]["std"],
        "Idle_Max": active_idle["idle"]["max"],
        "Idle_Min": active_idle["idle"]["min"],
    }

    return features
