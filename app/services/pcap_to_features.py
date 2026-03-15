# pip install scapy numpy

"""
PCAP to CICIDS2017 Feature Extractor
=====================================
Reads a PCAP file and extracts the same 52 network flow features used by the
CICIDS2017 dataset, so the output can be fed directly into the trained KitNET model.

Feature order matches feature_columns in app/services/cicids_loader.py exactly.
"""

import numpy as np
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

try:
    import scapy.all as scapy
except ImportError:
    raise ImportError("scapy is required: pip install scapy")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ACTIVE_TIMEOUT = 1.0  # seconds — gap >= this is considered Idle


# ---------------------------------------------------------------------------
# Feature names (must match feature_columns in cicids_loader.py exactly)
# ---------------------------------------------------------------------------

FEATURE_NAMES = [
    "Source Port",
    "Destination Port",
    "Protocol",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "Fwd Header Length",
    "Bwd Header Length",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

assert len(FEATURE_NAMES) == 52, "Feature list must have exactly 52 entries"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_stats(arr: List[float]) -> Tuple[float, float, float, float]:
    """Return (mean, std, max, min) from a list; returns (0,0,0,0) if empty."""
    if not arr:
        return 0.0, 0.0, 0.0, 0.0
    a = np.array(arr, dtype=float)
    return float(a.mean()), float(a.std()), float(a.max()), float(a.min())


def _active_idle_stats(
    timestamps: List[float],
) -> Tuple[Tuple[float, float, float, float], Tuple[float, float, float, float]]:
    """
    Split inter-packet gaps into Active (gap < ACTIVE_TIMEOUT) and
    Idle (gap >= ACTIVE_TIMEOUT) periods, then return stats for each.

    Returns:
        (active_mean, active_std, active_max, active_min),
        (idle_mean,   idle_std,   idle_max,   idle_min)
    """
    if len(timestamps) < 2:
        return (0.0, 0.0, 0.0, 0.0), (0.0, 0.0, 0.0, 0.0)

    sorted_ts = sorted(timestamps)
    gaps = [sorted_ts[i + 1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]

    active_periods: List[float] = []
    idle_periods: List[float] = []

    for gap in gaps:
        if gap < ACTIVE_TIMEOUT:
            active_periods.append(gap)
        else:
            idle_periods.append(gap)

    return _safe_stats(active_periods), _safe_stats(idle_periods)


def _tcp_flags(pkt) -> Dict[str, int]:
    """Extract individual TCP flag counts from a single packet (0 or 1 each)."""
    flags = {"FIN": 0, "SYN": 0, "RST": 0, "PSH": 0, "ACK": 0, "URG": 0}
    if pkt.haslayer(scapy.TCP):
        f = pkt[scapy.TCP].flags
        flags["FIN"] = 1 if f & 0x01 else 0
        flags["SYN"] = 1 if f & 0x02 else 0
        flags["RST"] = 1 if f & 0x04 else 0
        flags["PSH"] = 1 if f & 0x08 else 0
        flags["ACK"] = 1 if f & 0x10 else 0
        flags["URG"] = 1 if f & 0x20 else 0
    return flags


def _payload_len(pkt) -> int:
    """Length of the transport-layer payload (TCP/UDP data bytes)."""
    if pkt.haslayer(scapy.TCP):
        return len(pkt[scapy.TCP].payload)
    if pkt.haslayer(scapy.UDP):
        return len(pkt[scapy.UDP].payload)
    return 0


def _header_len(pkt) -> int:
    """IP + transport header length in bytes."""
    total = 0
    if pkt.haslayer(scapy.IP):
        total += pkt[scapy.IP].ihl * 4  # IP header
    if pkt.haslayer(scapy.TCP):
        total += pkt[scapy.TCP].dataofs * 4  # TCP header
    elif pkt.haslayer(scapy.UDP):
        total += 8  # UDP header is always 8 bytes
    return total


# ---------------------------------------------------------------------------
# Flow key builder
# ---------------------------------------------------------------------------

def _flow_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int):
    """
    Bidirectional 5-tuple key — identical regardless of packet direction.
    """
    if (src_ip, src_port) <= (dst_ip, dst_port):
        return (src_ip, dst_ip, src_port, dst_port, proto)
    return (dst_ip, src_ip, dst_port, src_port, proto)


# ---------------------------------------------------------------------------
# Per-packet info extraction
# ---------------------------------------------------------------------------

def _parse_packet(pkt) -> Optional[dict]:
    """
    Extract per-packet metadata. Returns None for non-IP or malformed packets.
    """
    try:
        if not pkt.haslayer(scapy.IP):
            return None

        ip = pkt[scapy.IP]
        src_ip = ip.src
        dst_ip = ip.dst
        proto = ip.proto  # 6=TCP, 17=UDP, etc.

        src_port = 0
        dst_port = 0
        if pkt.haslayer(scapy.TCP):
            src_port = pkt[scapy.TCP].sport
            dst_port = pkt[scapy.TCP].dport
        elif pkt.haslayer(scapy.UDP):
            src_port = pkt[scapy.UDP].sport
            dst_port = pkt[scapy.UDP].dport

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "proto": proto,
            "timestamp": float(pkt.time),
            "payload_len": _payload_len(pkt),
            "header_len": _header_len(pkt),
            "flags": _tcp_flags(pkt),
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Flow aggregation
# ---------------------------------------------------------------------------

class _FlowRecord:
    """Accumulates per-packet data for one bidirectional flow."""

    __slots__ = (
        "key", "fwd_key",
        "fwd_timestamps", "bwd_timestamps",
        "fwd_payload_lens", "bwd_payload_lens",
        "fwd_header_lens", "bwd_header_lens",
        "all_timestamps",
        "fin", "syn", "rst", "psh", "ack", "urg",
    )

    def __init__(self, key, fwd_key):
        self.key = key          # canonical (lo_ip, hi_ip, lo_port, hi_port, proto)
        self.fwd_key = fwd_key  # (src_ip, dst_ip, src_port, dst_port) of first packet

        self.fwd_timestamps:   List[float] = []
        self.bwd_timestamps:   List[float] = []
        self.fwd_payload_lens: List[int]   = []
        self.bwd_payload_lens: List[int]   = []
        self.fwd_header_lens:  List[int]   = []
        self.bwd_header_lens:  List[int]   = []
        self.all_timestamps:   List[float] = []

        self.fin = self.syn = self.rst = 0
        self.psh = self.ack = self.urg = 0

    def add_packet(self, info: dict) -> None:
        ts   = info["timestamp"]
        plen = info["payload_len"]
        hlen = info["header_len"]
        f    = info["flags"]

        self.all_timestamps.append(ts)

        direction_key = (info["src_ip"], info["dst_ip"],
                         info["src_port"], info["dst_port"])
        if direction_key == self.fwd_key:
            self.fwd_timestamps.append(ts)
            self.fwd_payload_lens.append(plen)
            self.fwd_header_lens.append(hlen)
        else:
            self.bwd_timestamps.append(ts)
            self.bwd_payload_lens.append(plen)
            self.bwd_header_lens.append(hlen)

        self.fin += f["FIN"]
        self.syn += f["SYN"]
        self.rst += f["RST"]
        self.psh += f["PSH"]
        self.ack += f["ACK"]
        self.urg += f["URG"]


# ---------------------------------------------------------------------------
# Feature vector builder
# ---------------------------------------------------------------------------

def _iat_stats(timestamps: List[float]) -> Tuple[float, float, float, float]:
    """Inter-arrival time stats for a sorted list of timestamps."""
    if len(timestamps) < 2:
        return 0.0, 0.0, 0.0, 0.0
    sorted_ts = sorted(timestamps)
    iats = [sorted_ts[i + 1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]
    return _safe_stats(iats)


def _build_feature_vector(flow: _FlowRecord) -> np.ndarray:
    """Compute the 52-feature vector for a completed flow."""

    all_ts = sorted(flow.all_timestamps)
    fwd_ts = sorted(flow.fwd_timestamps)
    bwd_ts = sorted(flow.bwd_timestamps)

    # --- Basic counts ---
    n_fwd = len(fwd_ts)
    n_bwd = len(bwd_ts)
    n_total = n_fwd + n_bwd

    src_ip, dst_ip, src_port, dst_port, proto = flow.key

    # --- Durations ---
    flow_duration = (all_ts[-1] - all_ts[0]) if len(all_ts) >= 2 else 0.0
    flow_duration_us = flow_duration * 1_000_000  # CICIDS uses microseconds

    # --- Rates (per second, guard divide-by-zero) ---
    dur = flow_duration if flow_duration > 0 else 1e-9
    total_bytes = sum(flow.fwd_payload_lens) + sum(flow.bwd_payload_lens)
    flow_bytes_s   = total_bytes / dur
    flow_packets_s = n_total / dur
    fwd_packets_s  = n_fwd / dur
    bwd_packets_s  = n_bwd / dur

    # --- Packet length stats ---
    fwd_mean, fwd_std, fwd_max, fwd_min = _safe_stats(flow.fwd_payload_lens)
    bwd_mean, bwd_std, bwd_max, bwd_min = _safe_stats(flow.bwd_payload_lens)

    all_lens = flow.fwd_payload_lens + flow.bwd_payload_lens
    pkt_mean, pkt_std, pkt_max, pkt_min = _safe_stats(all_lens)

    # --- IAT stats (in seconds, matching CICIDS microsecond scale via raw values) ---
    flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = _iat_stats(all_ts)
    fwd_iat_mean,  fwd_iat_std,  fwd_iat_max,  fwd_iat_min  = _iat_stats(fwd_ts)
    bwd_iat_mean,  bwd_iat_std,  bwd_iat_max,  bwd_iat_min  = _iat_stats(bwd_ts)

    # --- Header lengths ---
    fwd_hdr = sum(flow.fwd_header_lens)
    bwd_hdr = sum(flow.bwd_header_lens)

    # --- Active / Idle ---
    (act_mean, act_std, act_max, act_min), \
    (idl_mean, idl_std, idl_max, idl_min) = _active_idle_stats(all_ts)

    # --- Assemble in CICIDS feature_columns order ---
    features = np.array([
        float(src_port),            # Source Port
        float(dst_port),            # Destination Port
        float(proto),               # Protocol
        flow_duration_us,           # Flow Duration (microseconds)
        float(n_fwd),               # Total Fwd Packets
        float(n_bwd),               # Total Backward Packets
        float(sum(flow.fwd_payload_lens)),  # Total Length of Fwd Packets
        float(sum(flow.bwd_payload_lens)),  # Total Length of Bwd Packets
        fwd_max,                    # Fwd Packet Length Max
        fwd_min,                    # Fwd Packet Length Min
        fwd_mean,                   # Fwd Packet Length Mean
        fwd_std,                    # Fwd Packet Length Std
        bwd_max,                    # Bwd Packet Length Max
        bwd_min,                    # Bwd Packet Length Min
        bwd_mean,                   # Bwd Packet Length Mean
        bwd_std,                    # Bwd Packet Length Std
        flow_bytes_s,               # Flow Bytes/s
        flow_packets_s,             # Flow Packets/s
        fwd_packets_s,              # Fwd Packets/s
        bwd_packets_s,              # Bwd Packets/s
        flow_iat_mean,              # Flow IAT Mean
        flow_iat_std,               # Flow IAT Std
        flow_iat_max,               # Flow IAT Max
        flow_iat_min,               # Flow IAT Min
        fwd_iat_mean,               # Fwd IAT Mean
        fwd_iat_std,                # Fwd IAT Std
        fwd_iat_max,                # Fwd IAT Max
        fwd_iat_min,                # Fwd IAT Min
        bwd_iat_mean,               # Bwd IAT Mean
        bwd_iat_std,                # Bwd IAT Std
        bwd_iat_max,                # Bwd IAT Max
        bwd_iat_min,                # Bwd IAT Min
        float(flow.fin),            # FIN Flag Count
        float(flow.syn),            # SYN Flag Count
        float(flow.rst),            # RST Flag Count
        float(flow.psh),            # PSH Flag Count
        float(flow.ack),            # ACK Flag Count
        float(flow.urg),            # URG Flag Count
        float(fwd_hdr),             # Fwd Header Length
        float(bwd_hdr),             # Bwd Header Length
        pkt_min,                    # Min Packet Length
        pkt_max,                    # Max Packet Length
        pkt_mean,                   # Packet Length Mean
        pkt_std,                    # Packet Length Std
        act_mean,                   # Active Mean
        act_std,                    # Active Std
        act_max,                    # Active Max
        act_min,                    # Active Min
        idl_mean,                   # Idle Mean
        idl_std,                    # Idle Std
        idl_max,                    # Idle Max
        idl_min,                    # Idle Min
    ], dtype=float)

    assert len(features) == 52
    return features


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_feature_names() -> List[str]:
    """
    Returns the 52 feature name strings in the exact order matching
    feature_columns in app/services/cicids_loader.py.
    """
    return list(FEATURE_NAMES)


def extract_features_from_pcap(pcap_path: str) -> List[dict]:
    """
    Read a PCAP file and extract CICIDS2017-compatible flow features.

    Returns a list of dicts, one per bidirectional flow:
        {
            "features":      np.ndarray of shape (52,),
            "src_ip":        str,
            "dst_ip":        str,
            "src_port":      int,
            "dst_port":      int,
            "protocol":      int,
            "flow_duration": float  (seconds),
            "packet_count":  int,
            "start_time":    float  (unix timestamp of first packet),
        }
    """
    try:
        packets = scapy.rdpcap(pcap_path)
    except Exception as e:
        print(f"Error reading PCAP file '{pcap_path}': {e}")
        return []

    if len(packets) == 0:
        print("PCAP file is empty.")
        return []

    # --- Pass 1: group packets into flows ---
    flows: Dict[tuple, _FlowRecord] = {}

    for pkt in packets:
        info = _parse_packet(pkt)
        if info is None:
            continue

        key = _flow_key(
            info["src_ip"], info["dst_ip"],
            info["src_port"], info["dst_port"],
            info["proto"],
        )

        if key not in flows:
            fwd_key = (info["src_ip"], info["dst_ip"],
                       info["src_port"], info["dst_port"])
            flows[key] = _FlowRecord(key, fwd_key)

        flows[key].add_packet(info)

    if not flows:
        print("No valid IP flows found in PCAP.")
        return []

    # --- Pass 2: compute feature vectors ---
    results = []
    for key, flow in flows.items():
        src_ip, dst_ip, src_port, dst_port, proto = key

        try:
            feature_vec = _build_feature_vector(flow)
        except Exception as e:
            print(f"Error computing features for flow {key}: {e}")
            continue

        all_ts = sorted(flow.all_timestamps)
        results.append({
            "features":      feature_vec,
            "src_ip":        src_ip,
            "dst_ip":        dst_ip,
            "src_port":      int(src_port),
            "dst_port":      int(dst_port),
            "protocol":      int(proto),
            "flow_duration": (all_ts[-1] - all_ts[0]) if len(all_ts) >= 2 else 0.0,
            "packet_count":  len(flow.all_timestamps),
            "start_time":    all_ts[0] if all_ts else 0.0,
        })

    return results


# ---------------------------------------------------------------------------
# CLI test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        flows = extract_features_from_pcap(sys.argv[1])
        print(f"Extracted {len(flows)} flows")
        if flows:
            print(f"First flow features shape: {flows[0]['features'].shape}")
            print(
                f"First flow: {flows[0]['src_ip']}:{flows[0]['src_port']}"
                f" -> {flows[0]['dst_ip']}:{flows[0]['dst_port']}"
            )
    else:
        print("Usage: python pcap_to_features.py <file.pcap>")
        print(f"Feature count: {len(get_feature_names())}")
        print("Features:", get_feature_names())
