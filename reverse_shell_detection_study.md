## Reverse Shell Network Detection Study

### 1. Introduction

Reverse shells are a commonly used technique by adversaries to obtain remote interactive access to compromised systems. Instead of an attacker directly initiating an inbound connection to a victim, the victim initiates an outbound connection to an attacker-controlled listener. This inversion often allows such connections to bypass naïve firewall policies that block unsolicited inbound connections but trust most outbound traffic.

This project presents a structured, lab-based study of reverse shell-like network behavior and its detection using packet analysis, intrusion detection rules, and custom Python-based traffic analytics. All experiments are conducted in a strictly controlled, isolated environment using virtual machines and benign, simulated reverse shell traffic. The focus of this work is entirely defensive and educational: to understand how reverse shell traffic appears on the network and how it can be identified using signatures and behavioral indicators.

---

### 2. Lab Architecture and Environment

#### 2.1 Lab Topology

The lab environment consists of:

- **Host Machine**  
  - Physical laptop/desktop running a hypervisor (e.g., VirtualBox or VMware).  
  - Provides a virtual network for guest VMs.

- **Attacker VM**  
  - Operating System: `Kali Linux`  
  - Role: Simulated attacker, hosting a benign TCP listener to mimic a reverse shell listener.

- **Victim VM**  
  - Operating System: `Metasploitable 2` or a dedicated Windows test VM  
  - Role: Simulated victim, initiating outbound connections to the Kali listener on a non-standard port.

- **Virtual Network**  
  - Primary mode: **Host-only** or **Internal Network**, with no direct access to the Internet.  
  - Optionally, a second adapter can be configured as **NAT** only for updates (disabled during experiments).

#### 2.2 Network Diagram (Textual Description)

Logical topology (Host-only network example, 192.168.56.0/24):

- **Host OS**  
  - Virtual Network Adapter (`Host-only`): `192.168.56.1/24`

- **Kali VM (Attacker)**  
  - Interface: `eth0`  
  - IP: `192.168.56.10`  
  - Netmask: `255.255.255.0`  
  - Gateway: `192.168.56.1`

- **Victim VM (Metasploitable/Windows)**  
  - Interface: `eth0`  
  - IP: `192.168.56.20`  
  - Netmask: `255.255.255.0`  
  - Gateway: `192.168.56.1`

Traffic capture is performed either on the host-only interface of the host machine or directly on one of the VMs (typically Kali or the victim) using Wireshark or tcpdump.

#### 2.3 NAT vs Host-only Networking

- **Host-only / Internal Network**
  - **Advantages**:
    - Fully isolated from the Internet.
    - Eliminates risk of unintentionally attacking external systems.
    - Traffic is limited to the VMs and the host, simplifying analysis.
  - **Disadvantages**:
    - No direct Internet access for updates or external resources (unless you add a separate adapter).

- **NAT Network**
  - **Advantages**:
    - VMs have outbound Internet access through the host.
    - Closer to real-world client behavior where endpoints browse and update.
  - **Disadvantages**:
    - Increased noise (legitimate web traffic) complicates reverse shell detection.
    - Care is required to ensure any testing remains confined logically and ethically to the lab.

For this project, **Host-only networking** is recommended for all reverse shell simulations and packet capture experiments. NAT adapters may be temporarily enabled for software installation but should be disabled during data collection.

#### 2.4 Safe Lab Isolation Steps

To ensure safety and ethical compliance:

- Do **not** use bridged network modes during exploit or reverse shell simulations.  
- Restrict Metasploitable and any intentionally vulnerable services strictly to the isolated lab network.  
- Disable or minimize shared folders and clipboard sharing between host and VMs.  
- Take snapshots of the VMs before experiments to allow quick rollback to a clean state.  
- Use only benign tools and simulated payloads; do not run destructive commands.  
- Do not reuse any payloads, scripts, or techniques outside this controlled environment.

---

### 3. Reverse Shell Simulation (Conceptual)

#### 3.1 High-Level Reverse Shell Communication Flow

In a classical reverse shell scenario, the roles are:

1. The **attacker** machine listens on a chosen TCP port for inbound connections.  
2. The **victim** machine initiates an outbound TCP connection to the attacker’s IP and port.  
3. Once the connection is established, the attacker obtains interactive control over the victim through the established TCP session.

In this project, the behavior is **simulated**:

- The Kali VM hosts a benign TCP listener (e.g., using Netcat or a simple Python server).  
- The victim VM runs a benign client that connects to the Kali IP and non-standard port, periodically sending harmless data.  
- No actual exploitation or harmful commands are performed; only traffic characteristics are studied.

#### 3.2 Outbound Connection Characteristics

Key properties of reverse shell-like outbound connections:

- **Source**: Victim IP (`192.168.56.20`).  
- **Destination**: Attacker IP (`192.168.56.10`).  
- **Destination Port**: Non-standard high port (e.g., `4444`, `5555`, `8088`), often not used by legitimate services in the lab.  
- **Direction**: Outbound from victim to attacker.  
- **Behavior**:
  - Long-lived TCP connection.  
  - Periodic small data transfers (beaconing or interactive keystroke-like patterns).  
  - Potentially high-entropy data if encryption or obfuscation is used.

#### 3.3 TCP Three-Way Handshake

The simulated reverse shell uses standard TCP:

1. **SYN**: Victim → Attacker  
   - Source port: ephemeral (e.g., 54321).  
   - Destination port: listener port (e.g., 4444).
2. **SYN/ACK**: Attacker → Victim.  
3. **ACK**: Victim → Attacker, completing the handshake.

After negotiation:

- Application data segments are exchanged (packets often flagged with `PSH,ACK`).  
- The connection may remain open for extended periods, carrying intermittent payloads.  
- Termination occurs via `FIN`/`ACK` exchange or `RST` if the session is abruptly closed.

#### 3.4 Controlled Lab Commands Only

Within this project:

- The Kali VM runs a benign listener (e.g., `nc -lvp 4444` or a simple Python socket server).  
- The victim runs a benign client (e.g., Netcat or Python) that:
  - Connects to `192.168.56.10:4444`.  
  - Sends pre-defined, non-destructive strings such as `"lab_test"`, `"ping"`, `"reverse_shell_sim"`.  

Analysis focuses exclusively on:

- Connection direction and port usage.  
- Session lifetimes and timing.  
- Payload size and entropy.  

---

### 4. Packet Capture Strategy

#### 4.1 Capturing Traffic with Wireshark

Wireshark is used to capture packets for offline analysis and validation of detection rules.

**Capture locations**:

- On the **host** machine, capturing on the host-only adapter (`vboxnet0`, `VMnetX`, or equivalent).  
- Or on the **Kali** or **Victim** VM, capturing on `eth0` (or the primary adapter).

**Capture steps**:

1. Start Wireshark on the relevant interface.  
2. Begin capture before initiating the simulated reverse shell connection.  
3. Run the benign connection from victim to attacker.  
4. Stop capture after closing the connection.  
5. Save the trace as `reverse_shell_lab.pcapng` for further analysis.

#### 4.2 Capture Filters (BPF)

Capture filters (applied before capturing) reduce unnecessary data.

- Traffic strictly between Kali and Victim:

```text
host 192.168.56.10 and host 192.168.56.20
```

- Traffic to the simulated reverse shell port (e.g., 4444):

```text
tcp port 4444
```

- Victim outbound traffic to port 4444:

```text
src host 192.168.56.20 and tcp dst port 4444
```

#### 4.3 Display Filters

Display filters narrow down analysis in existing captures.

- Victim-to-attacker traffic on port 4444:

```text
ip.src == 192.168.56.20 && ip.dst == 192.168.56.10 && tcp.port == 4444
```

- Initial TCP handshakes (SYN packets):

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

Wireshark’s **Statistics → Conversations** and **Follow → TCP Stream** features are used to:

- Inspect individual flows.  
- Examine packet counts, byte counts, and durations.  
- View full request/response data for each TCP stream.

#### 4.4 Observations in Reverse Shell-like Traffic

In the lab captures, reverse shell-like flows exhibit:

- Initial SYN from victim to attacker on a non-standard high port.  
- One or more long-lived TCP connections greatly exceeding the duration of DNS or simple HTTP requests in the same environment.  
- Small, intermittent payloads consistent with interactive or beacon traffic.  
- Directionality that is unusual for typical client behavior in a small lab (victim repeatedly contacting another internal node on a high port).

#### 4.5 TCP Flags and Abnormal Outbound Patterns

Indicators observed:

- **Frequent `PSH,ACK` packets** with very small payload sizes, suggesting low-volume interactive sessions.  
- **Infrequent or abrupt termination** via `FIN`/`RST`, sometimes only seen when the listener or client is forcefully stopped.  
- **Repeated outbound attempts** when the listener is not yet running, indicating automated reconnection behavior (in extended experiments).

---

### 5. Detection Engineering

This section presents detection logic for common tools: Wireshark, Suricata, Snort, Zeek, and Sigma-style rules.

#### 5.1 Wireshark Detection Filters

Wireshark detection is primarily manual/visual; filters help narrow investigation:

- Suspected reverse shell from victim to attacker on port 4444:

```text
ip.src == 192.168.56.20 && ip.dst == 192.168.56.10 && tcp.dstport == 4444
```

- Any high-port outbound connection from victim to attacker, excluding common web ports:

```text
ip.src == 192.168.56.20 && ip.dst == 192.168.56.10 && tcp.dstport >= 1024 && tcp.dstport != 80 && tcp.dstport != 443
```

These filters are used to identify and examine candidate flows for reverse shell behavior.

#### 5.2 Suricata Rules (Lab-only Examples)

Rule to detect outbound connections from victim to attacker on a specific high port:

```text
alert tcp 192.168.56.20 any -> 192.168.56.10 4444 (
    msg:"LAB Reverse Shell-Like Outbound Connection to Kali";
    flow:to_server,established;
    classtype:trojan-activity;
    sid:1000001;
    rev:1;
)
```

Generic rule for suspicious high-port internal connections:

```text
alert tcp 192.168.56.0/24 any -> 192.168.56.0/24 1024:65535 (
    msg:"LAB Suspicious High-Port Internal TCP Connection";
    flow:to_server,established;
    threshold:type both, track by_src, count 5, seconds 60;
    classtype:policy-violation;
    sid:1000002;
    rev:1;
)
```

These rules are intended for the small lab context where most legitimate services use well-known ports.

#### 5.3 Snort Rules

Equivalent Snort rule for the reverse shell-like connection:

```text
alert tcp 192.168.56.20 any -> 192.168.56.10 4444 (
    msg:"LAB Reverse Shell-Like Outbound to Kali";
    flow:to_server,established;
    classtype:trojan-activity;
    sid:2000001;
    rev:1;
)
```

Additional tuning (e.g., content or flowbits) can be applied based on lab needs.

#### 5.4 Zeek Detection Logic (Conceptual)

Zeek operates at a higher abstraction level (connections and logs). In this lab, detection logic may:

- Monitor `conn.log` for:
  - Connections where `orig_h == 192.168.56.20` and `resp_h == 192.168.56.10`.  
  - `resp_p` in high-port range (e.g., `> 1024`).  
  - `duration` above a defined threshold (e.g., > 60 seconds).  
- Generate a notice if all conditions are met.

Conceptual Zeek script snippet (pseudocode):

```zeek
event connection_state_remove(c: connection) {
    if ( c$id$orig_h == 192.168.56.20 &&
         c$id$resp_h == 192.168.56.10 &&
         c$id$resp_p > 1024 &&
         c$duration > 60sec ) {

        NOTICE([$note=Notice::ACTION_NEEDED,
                $msg=fmt("LAB Suspicious long-lived high-port connection %s -> %s:%s",
                         c$id$orig_h, c$id$resp_h, c$id$resp_p)]);
    }
}
```

#### 5.5 Sigma Rule Example (Conceptual)

Sigma is designed for SIEM-agnostic detection rules, often using log events (e.g., firewall/flow logs). A high-level Sigma rule for reverse shell-like connections:

```yaml
title: Lab Reverse Shell-Like Outbound Connection
id: 6b6baf40-0000-0000-0000-lab-revshell
status: experimental
description: Detects long-lived outbound TCP connections from victim to attacker on non-standard ports in lab.
author: Student
logsource:
  product: network
  service: firewall
detection:
  selection:
    src_ip: 192.168.56.20
    dst_ip: 192.168.56.10
  filter_common_ports:
    dst_port|contains:
      - 80
      - 443
  condition: selection and not filter_common_ports
fields:
  - src_ip
  - dst_ip
  - src_port
  - dst_port
  - bytes
  - duration
falsepositives:
  - Lab test traffic or administrative tools
level: medium
```

This rule would be adapted to the specific log schema used by the SIEM.

---

### 6. Python Traffic Analyzer

This section presents a Python script, implemented with Scapy, to detect suspicious outbound traffic patterns associated with reverse shell-like behavior.

#### 6.1 Design Goals

The analyzer aims to:

- Inspect packets either live or from a PCAP file.  
- Focus on outbound traffic from the victim IP.  
- Detect:
  - Suspicious outbound connections to non-standard ports.  
  - High-entropy payloads (potentially encrypted or obfuscated).  
  - Long-lived TCP sessions.  
- Log suspicious destinations and print alerts for analyst review.

#### 6.2 Implementation (Scapy-based Script)

```python
import argparse
import time
import math
from collections import defaultdict

from scapy.all import sniff, rdpcap, TCP, IP, Raw

# -----------------------------
# Configuration
# -----------------------------
LAB_SUBNET = "192.168.56.0/24"
VICTIM_IP = "192.168.56.20"
ATTACKER_IP = "192.168.56.10"

COMMON_PORTS = {80, 443, 53, 22, 25, 110, 143}
LONG_SESSION_THRESHOLD_SEC = 60  # Consider > 60 seconds as long-lived
HIGH_ENTROPY_THRESHOLD = 7.0     # max is 8 for 1-byte alphabet
MIN_PAYLOAD_LEN_FOR_ENTROPY = 32

suspicious_ips_file = "suspicious_ips.log"


def shannon_entropy(data: bytes) -> float:
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


def log_suspicious_ip(ip: str, reason: str):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {ip} - {reason}\\n"
    with open(suspicious_ips_file, "a") as f:
        f.write(line)


class SessionInfo:
    def __init__(self, first_ts):
        self.first_ts = first_ts
        self.last_ts = first_ts
        self.byte_count = 0
        self.packet_count = 0
        self.high_entropy_packets = 0

    def update(self, ts, payload_bytes, is_high_entropy):
        self.last_ts = ts
        self.byte_count += len(payload_bytes)
        self.packet_count += 1
        if is_high_entropy:
            self.high_entropy_packets += 1

    @property
    def duration(self):
        return self.last_ts - self.first_ts


sessions = {}


def process_packet(pkt):
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return

    ip = pkt[IP]
    tcp = pkt[TCP]

    # Focus on outbound from victim
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

    # 2. High-entropy payloads
    if high_entropy:
        reason = f"High-entropy payload (H={entropy:.2f}) to {ip.dst}:{dst_port}"
        print(f"[ALERT] {ip.src} -> {ip.dst}:{dst_port} - {reason}")
        log_suspicious_ip(ip.dst, reason)

    # 3. Long-lived sessions
    session = sessions[key]
    if session.duration > LONG_SESSION_THRESHOLD_SEC:
        reason = f"Long-lived TCP session duration={session.duration:.1f}s to {ip.dst}:{dst_port}"
        print(f"[ALERT] {ip.src} -> {ip.dst}:{dst_port} - {reason}")
        log_suspicious_ip(ip.dst, reason)


def analyze_pcap(pcap_file):
    print(f"[*] Reading PCAP file: {pcap_file}")
    packets = rdpcap(pcap_file)
    for pkt in packets:
        process_packet(pkt)
    print("[*] PCAP analysis complete.")


def live_capture(interface):
    print(f"[*] Starting live capture on interface: {interface}")
    bpf_filter = f"tcp and src host {VICTIM_IP}"
    sniff(iface=interface, filter=bpf_filter, prn=process_packet, store=False)


def main():
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
```

This script may be extended to write structured CSV logs for visualization, as described in Section 8.

---

### 7. Anomaly Detection Logic

#### 7.1 Behavioral Indicators

Key behavioral features associated with reverse shell-like communication:

- **Unusual outbound destinations**: Victim connecting to internal IPs not associated with standard services.  
- **Non-standard ports**: Destinations on ports such as 4444, 5555, 8088, etc.  
- **Long-lived sessions**: Connections that remain open significantly longer than typical short-lived HTTP/DNS requests.  
- **Low-volume but sustained traffic**: Intermittent small packets over extended periods.

#### 7.2 Beaconing and Periodic Connections

A common command-and-control (C2) pattern is beaconing:

- The victim periodically connects to or sends small data packets to the same IP/port at fixed intervals.  
- Inter-arrival times between connections or packets show low variance (e.g., every 30 seconds ± 2 seconds).

In a larger implementation, the analyzer could:

- Track timestamps of flows from the victim to a given `(dst_ip, dst_port)`.  
- Compute inter-arrival times and their variance.  
- Flag flows exhibiting near-constant inter-arrival times as potential beacons.

#### 7.3 C2 Traffic Characteristics

Common C2 traits:

- **Low-and-slow profile** to evade volume-based detection.  
- **High entropy payloads** due to encryption or packing.  
- **Fixed endpoints**: repeated communication with the same IP/port pair.  
- **Fallback behavior**: repeated connection attempts when the C2 server is down.

#### 7.4 Encrypted Reverse Shell Behavior

When reverse shells are encapsulated in encrypted channels (e.g., SSH or TLS):

- Payload content is not directly inspectable.  
- Detection relies on:
  - Endpoint context (is the host supposed to contact this IP?).  
  - Ports and services (SSH-like behavior on unusual ports).  
  - Timing and duration.  
  - Certificate and SNI anomalies in TLS-based channels.

In a small lab, any encrypted traffic from the victim to the Kali host on unusual ports may be treated as suspicious and investigated further.

---

### 8. Results and Discussion (Example Narrative)

In test runs performed within the lab environment:

- Wireshark analysis confirmed that reverse shell-like connections from the victim to the Kali host occurred solely on configured non-standard ports and exhibited significantly longer durations than typical background traffic.  
- Suricata and Snort rules triggered alerts for all simulated sessions matching the defined IP and port criteria, demonstrating strong effectiveness for tightly scoped signature-based detection.  
- The Python analyzer successfully identified:
  - All simulated reverse shell-like sessions based on non-standard ports and session duration.  
  - High-entropy payloads produced in test scenarios designed to mimic encrypted communication.  
- Due to the low volume of background traffic in the lab, false positives were minimal. However, it was observed that in more complex environments with diverse application traffic, additional context and whitelisting would be required.

---

### 9. Conclusion

This project provides a comprehensive, lab-based exploration of reverse shell-like traffic detection using packet analysis, IDS rules, and custom Python-based analytics. By constraining experiments to a controlled two-VM environment (Kali as attacker, Metasploitable/Windows as victim) and focusing on benign, simulated traffic, the study remains safe and ethically sound while still capturing the key characteristics of real-world reverse shells.

The results underscore the utility of combining multiple detection approaches:

- **Wireshark** for in-depth, manual forensic analysis.  
- **Suricata/Snort/Zeek/Sigma** for scalable, rule-based monitoring.  
- **Python analytics** for flexible, behavior-focused detection logic such as entropy analysis and session duration.  

Although the environment is small, the techniques and insights developed in this work are directly applicable to larger networks and can be extended with machine learning, encrypted traffic analysis, and SIEM correlation for enterprise-grade defense.

---

### 10. Future Scope

Potential extensions and improvements include:

- **Machine Learning**: Use flow-level features (duration, bytes, ports, timing, entropy) to train classifiers that distinguish benign and reverse shell-like traffic.  
- **Encrypted Traffic Fingerprinting**: Incorporate TLS fingerprinting (e.g., JA3 hashes) and SSH metadata to identify anomalous encrypted sessions.  
- **Scalable Deployment**: Integrate the Python analyzer as a component in a distributed network sensor framework.  
- **SIEM Integration**: Convert detection events into SIEM-friendly formats, applying Sigma rules and correlation with host-based telemetry.  
- **Educational Red vs Blue Exercises**: Use the lab as a foundation for controlled red-team/blue-team exercises in academic courses, emphasizing detection and incident response rather than exploitation.

---

### 11. Bonus: Simple Visualization / Dashboard

#### 11.1 CLI Visualization with Matplotlib

A simple visualization module can read a CSV log of suspicious connection events (e.g., timestamp, source IP, destination IP, destination port) produced by the analyzer and generate:

- Time-series plots of connection frequency.  
- Histograms of suspicious destination ports.

```python
import csv
import datetime
from collections import Counter, defaultdict

import matplotlib.pyplot as plt

LOG_FILE = "connection_events.csv"  # columns: timestamp,src_ip,dst_ip,dst_port


def parse_time(ts_str):
    return datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")


def load_events():
    times = []
    ports = []

    with open(LOG_FILE, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            t = parse_time(row["timestamp"])
            times.append(t)
            ports.append(int(row["dst_port"]))

    return times, ports


def plot_connection_frequency(times):
    counts_per_minute = defaultdict(int)
    for t in times:
        minute_bucket = t.replace(second=0, microsecond=0)
        counts_per_minute[minute_bucket] += 1

    xs = sorted(counts_per_minute.keys())
    ys = [counts_per_minute[x] for x in xs]

    plt.figure(figsize=(10, 4))
    plt.plot(xs, ys, marker="o")
    plt.title("Connection Frequency Over Time")
    plt.xlabel("Time (per minute)")
    plt.ylabel("Number of Connections")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()


def plot_suspicious_ports(ports):
    port_counts = Counter(ports)
    ports_sorted = sorted(port_counts.keys())
    counts = [port_counts[p] for p in ports_sorted]

    plt.figure(figsize=(8, 4))
    plt.bar(ports_sorted, counts)
    plt.title("Suspicious Destination Ports")
    plt.xlabel("Port")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.show()


def main():
    times, ports = load_events()
    if not times:
        print("No events in log.")
        return

    plot_connection_frequency(times)
    plot_suspicious_ports(ports)


if __name__ == "__main__":
    main()
```

The main analyzer can be extended to append rows to `connection_events.csv` whenever an alert is raised.

#### 11.2 Optional Flask Dashboard (Outline)

An optional enhancement is a minimal Flask-based dashboard:

- `app.py`: Flask application that reads a JSON/CSV summary file generated by the analyzer.  
- `templates/index.html`: Displays:
  - Recent suspicious connections as a table.  
  - Top destination IPs and ports as charts (using a JS chart library or pre-generated images).  

This would provide a user-friendly interface for monitoring and demonstration during project presentations.

---

### 12. Academic Sections Summary

For submission, the report can be structured as:

- **Abstract**  
- **1. Introduction**  
- **2. Lab Architecture and Environment**  
- **3. Reverse Shell Simulation**  
- **4. Packet Capture Strategy**  
- **5. Detection Engineering**  
- **6. Python Traffic Analyzer**  
- **7. Anomaly Detection Logic**  
- **8. Results and Discussion**  
- **9. Conclusion**  
- **10. Future Scope**  
- **11. Bonus: Visualization / Dashboard**  
- **References** (to be added as per your citation style).

You can now add references, screenshots of Wireshark and IDS alerts, and implementation-specific details from your actual experiments to finalize the project report.

