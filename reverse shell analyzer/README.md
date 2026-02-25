## Reverse Shell Network Detection Study

This repository contains a complete college-level cybersecurity project that studies **reverse shell–like network behavior** in a **controlled virtual lab** and develops **network-based detection techniques**.

The goal is defensive: understand how reverse shell traffic looks on the wire and how to detect it using packet captures, IDS rules, and custom Python analytics. All experiments are intended to be run **only on two isolated virtual machines**:

- **Attacker VM**: Kali Linux  
- **Victim VM**: Metasploitable 2 or a Windows test VM  

> **Important**: This project is for educational and defensive research purposes only. All tests must be performed in an isolated lab environment (e.g., host-only or internal virtual networks), never on production or public networks.

---

### 1. Lab Architecture (High Level)

- **Host machine** runs VirtualBox/VMware.  
- Two VMs share a **Host-only/Internal** network, for example:
  - Kali (attacker): `192.168.56.10`
  - Victim: `192.168.56.20`
- All reverse shell–like simulations are outbound from the victim to Kali on a **non-standard TCP port** (e.g., `4444`).

See `reverse_shell_detection_study.md` for full methodology, diagrams, and academic documentation.

---

### 2. Repository Structure

- `reverse_shell_detection_study.md`  
  Full, report-style write-up (introduction, methodology, implementation, results, conclusion, future scope).

- `lab_revshell_analyzer.py`  
  Python script (Scapy-based) that analyzes live traffic or PCAP files to detect:
  - Suspicious outbound connections from the victim.  
  - Use of non-standard ports.  
  - Long-lived TCP sessions.  
  - High-entropy payloads (possible encrypted/obfuscated traffic).  
  - Logs suspicious IPs and writes CSV events for visualization.

- `plot_connections.py`  
  Small visualization script (matplotlib) that reads `connection_events.csv` and plots:
  - Connection frequency over time.  
  - Histogram of suspicious destination ports.

- `rules_suricata_lab.rules`  
  Suricata IDS rules for lab detection of reverse shell–like outbound connections.

- `rules_snort_lab.rules`  
  Snort IDS rules (lab-only) for similar detection logic.

- `zeek_lab_revshell.zeek`  
  Zeek script (conceptual) to raise a notice on long-lived, high-port connections from victim to attacker.

- `sigma_lab_reverse_shell.yml`  
  Example Sigma rule for SIEM-style detection of suspicious outbound connections.

---

### 3. Installation and Requirements

#### 3.1 Python dependencies (on Kali or analysis host)

Install Python 3 dependencies (Scapy and matplotlib are the main ones):

```bash
sudo apt update
sudo apt install -y python3-pip
pip3 install scapy matplotlib
```

If you only need CLI analysis and not plotting, `matplotlib` is optional.

#### 3.2 Tools

- **Wireshark** (or `tcpdump`) for packet capture.  
- Optional IDS tools if you want to run rules:
  - Suricata  
  - Snort  
  - Zeek  

---

### 4. Usage

#### 4.1 Capture Traffic in the Lab

1. Configure host-only/Internal network between:
   - Kali: `192.168.56.10`  
   - Victim: `192.168.56.20`

2. On Kali, start a benign listener, for example:

```bash
nc -lvp 4444
```

3. On the victim, initiate an outbound connection:

```bash
nc 192.168.56.10 4444
```

4. Type a few harmless messages so data flows between victim and Kali.

5. Capture this traffic with Wireshark or tcpdump and save as e.g. `reverse_shell_lab.pcapng`.

#### 4.2 Run the Python Analyzer

Offline (PCAP) analysis:

```bash
python3 lab_revshell_analyzer.py -r reverse_shell_lab.pcapng
```

Live capture on an interface (e.g. `eth0` on Kali, watching victim’s outbound traffic):

```bash
sudo python3 lab_revshell_analyzer.py -i eth0
```

The script will:

- Print `[ALERT]` lines for suspicious connections.  
- Append entries to:
  - `suspicious_ips.log`  
  - `connection_events.csv` (timestamp, source, destination, port)

#### 4.3 Plot Suspicious Connections

Once `connection_events.csv` exists (created by the analyzer), run:

```bash
python3 plot_connections.py
```

This opens:

- A time-series plot of connection counts per minute.  
- A bar chart of suspicious destination ports.

---

### 5. IDS / Detection Rules

You can load and test the rules in an IDS of your choice (lab only):

- Suricata:

  - Add `rules_suricata_lab.rules` to your Suricata rules directory.  
  - Enable it in `suricata.yaml`.  
  - Replay your PCAP using `tcpreplay` or monitor live traffic.

- Snort:

  - Include `rules_snort_lab.rules` in your Snort configuration.  
  - Run Snort in IDS mode on the host-only interface or against PCAP.

- Zeek:

  - Run Zeek with `zeek_lab_revshell.zeek` loaded on captured traffic.  
  - Examine generated `notice.log` entries.

- Sigma:

  - `sigma_lab_reverse_shell.yml` is an example rule that can be adapted to your SIEM’s network log schema.

These rules are tuned for the **small lab environment** (192.168.56.0/24) and should be adapted carefully before any broader use.

---

### 6. Academic Report

The full academic report is in:

- `reverse_shell_detection_study.md`

It contains:

- Abstract, problem statement, objectives.  
- Lab architecture and safe isolation.  
- Reverse shell communication flow (high-level, defensive).  
- Packet capture strategy and Wireshark analysis.  
- Detection engineering (Wireshark filters, Suricata/Snort/Zeek/Sigma logic).  
- Python analyzer design and anomaly detection concepts.  
- Results, conclusion, and future scope.

You can convert this Markdown file to PDF/Word (e.g. using Pandoc) for submission.

---

### 7. GitHub / Version Control Notes

Recommended `.gitignore` entries for this project:

```gitignore
__pycache__/
*.pyc
*.pcap
*.pcapng
suspicious_ips.log
connection_events.csv
```

This keeps large captures and generated logs out of your repository while preserving all source code, rules, and documentation.

