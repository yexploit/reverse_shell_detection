import argparse
import time
import math
import csv
from collections import defaultdict

from scapy.all import sniff, rdpcap, TCP, IP, Raw


# -----------------------------
# Configuration
# -----------------------------
LAB_SUBNET = "192.168.56.0/24"
VICTIM_IP = "192.168.56.20"
ATTACKER_IP = "192.168.56.10"

COMMON_PORTS = {80, 443, 53, 22, 25, 110, 143}
LONG_SESSION_THRESHOLD_SEC = 60  # seconds
HIGH_ENTROPY_THRESHOLD = 7.0     # bits/byte, max is 8
MIN_PAYLOAD_LEN_FOR_ENTROPY = 32

SUSPICIOUS_IPS_FILE = "suspicious_ips.log"
CONNECTION_LOG = "connection_events.csv"


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for a bytes payload."""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    data_len = float(len(data))
    entropy = 0.0
    for count in freq.values():
        p = count / data_len
        entropy -= p * math.log2(p)
    return entropy


def log_suspicious_ip(ip: str, reason: str) -> None:
    """Append a suspicious IP and reason to a log file."""
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {ip} - {reason}\n"
    with open(SUSPICIOUS_IPS_FILE, "a", encoding="utf-8") as f:
        f.write(line)


def write_connection_event(src: str, dst: str, dst_port: int) -> None:
    """Append a connection event to CSV for later visualization."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    header = ["timestamp", "src_ip", "dst_ip", "dst_port"]

    try:
        new_file = False
        try:
            with open(CONNECTION_LOG, "r", encoding="utf-8") as _:
                pass
        except FileNotFoundError:
            new_file = True

        with open(CONNECTION_LOG, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if new_file:
                writer.writerow(header)
            writer.writerow([timestamp, src, dst, dst_port])
    except OSError:
        # Logging failure should not crash the analyzer
        pass


class SessionInfo:
    """Track statistics about a TCP session."""

    def __init__(self, first_ts: float) -> None:
        self.first_ts = first_ts
        self.last_ts = first_ts
        self.byte_count = 0
        self.packet_count = 0
        self.high_entropy_packets = 0

    def update(self, ts: float, payload_bytes: bytes, is_high_entropy: bool) -> None:
        self.last_ts = ts
        self.byte_count += len(payload_bytes)
        self.packet_count += 1
        if is_high_entropy:
            self.high_entropy_packets += 1

    @property
    def duration(self) -> float:
        return self.last_ts - self.first_ts


sessions = {}


def process_packet(pkt) -> None:
    """Scapy packet callback for both live and offline analysis."""
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return

    ip = pkt[IP]
    tcp = pkt[TCP]

    # Focus only on outbound traffic from the victim
    if ip.src != VICTIM_IP:
        return

    dst_port = tcp.dport
    key = (ip.src, tcp.sport, ip.dst, dst_port)
    ts = float(pkt.time)

    payload = b""
    if pkt.haslayer(Raw):
        payload = bytes(pkt[Raw].load)

    entropy = shannon_entropy(payload) if len(payload) >= MIN_PAYLOAD_LEN_FOR_ENTROPY else 0.0
    high_entropy = entropy >= HIGH_ENTROPY_THRESHOLD

    if key not in sessions:
        sessions[key] = SessionInfo(ts)
    sessions[key].update(ts, payload, high_entropy)

    # 1. Suspicious outbound to non-standard port
    if dst_port not in COMMON_PORTS and dst_port >= 1024:
        reason = f"Outbound to non-standard port {dst_port}"
        print(f"[ALERT] {ip.src} -> {ip.dst}:{dst_port} - {reason}")
        log_suspicious_ip(ip.dst, reason)
        write_connection_event(ip.src, ip.dst, dst_port)

    # 2. High-entropy payloads
    if high_entropy:
        reason = f"High-entropy payload (H={entropy:.2f}) to {ip.dst}:{dst_port}"
        print(f"[ALERT] {ip.src} -> {ip.dst}:{dst_port} - {reason}")
        log_suspicious_ip(ip.dst, reason)
        write_connection_event(ip.src, ip.dst, dst_port)

    # 3. Long-lived sessions
    session = sessions[key]
    if session.duration > LONG_SESSION_THRESHOLD_SEC:
        reason = f"Long-lived TCP session duration={session.duration:.1f}s to {ip.dst}:{dst_port}"
        print(f"[ALERT] {ip.src} -> {ip.dst}:{dst_port} - {reason}")
        log_suspicious_ip(ip.dst, reason)
        write_connection_event(ip.src, ip.dst, dst_port)


def analyze_pcap(pcap_file: str) -> None:
    """Offline analysis of a PCAP file."""
    print(f"[*] Reading PCAP file: {pcap_file}")
    packets = rdpcap(pcap_file)
    for pkt in packets:
        process_packet(pkt)
    print("[*] PCAP analysis complete.")


def live_capture(interface: str) -> None:
    """Live capture on a given interface."""
    print(f"[*] Starting live capture on interface: {interface}")
    bpf_filter = f"tcp and src host {VICTIM_IP}"
    sniff(iface=interface, filter=bpf_filter, prn=process_packet, store=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="Lab Reverse Shell Traffic Analyzer")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--interface", help="Interface for live capture (e.g., eth0)")
    group.add_argument("-r", "--read-pcap", help="PCAP file to analyze")

    args = parser.parse_args()

    print("[*] Lab Reverse Shell Network Detection Analyzer")
    print(f"[*] Victim IP: {VICTIM_IP}, Attacker IP: {ATTACKER_IP}")

    if args.interface:
        live_capture(args.interface)
    else:
        analyze_pcap(args.read_pcap)


if __name__ == "__main__":
    main()

