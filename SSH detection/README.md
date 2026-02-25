## SSH Brute-Force Detection in Splunk

This project simulates **SSH brute-force attacks** in a controlled lab and builds **Splunk-based detections and dashboards** to identify credential abuse patterns from `auth.log`.

The environment is designed for **defensive, educational use only** and should be deployed strictly in an isolated lab:

- **Attacker**: Kali Linux (running Nmap / Metasploit brute-force modules)
- **Target**: Linux server (e.g., Metasploitable or Ubuntu) with OpenSSH enabled
- **SIEM**: Splunk instance ingesting `/var/log/auth.log` from the target

---

### 1. Lab Overview

1. Configure an SSH-enabled Linux victim VM and a Kali attacker VM on an isolated network (host-only/internal).
2. Generate SSH brute-force traffic using:
   - Nmap NSE scripts (e.g., `ssh-brute`)
   - Or Metasploit auxiliary modules (e.g., `auxiliary/scanner/ssh/ssh_login`)
3. Forward the victim's `/var/log/auth.log` into Splunk (e.g., via universal forwarder or file monitor).
4. Use Splunk SPL searches and this repo’s Python analyzer to detect:
   - High-rate failed SSH logins
   - Repeated failures followed by a success (possible credential compromise)

Full academic write-up: `ssh_bruteforce_detection_study.md`.

---

### 2. Repository Structure

- `ssh_bruteforce_detection_study.md`  
  Detailed report (introduction, methodology, lab design, SPL queries, results, conclusion).

- `ssh_bruteforce_analyzer.py`  
  Python script that parses `auth.log` and detects brute-force patterns:
  - Multiple failed attempts from same IP in a short time window
  - Success after many failures
  - Writes alerts to console and `suspicious_ssh_ips.log`
  - Optionally logs events to `ssh_events.csv` for visualization

- `plot_ssh_events.py`  
  Matplotlib-based CLI dashboard that visualizes:
  - Failed attempts over time
  - Top attacking IPs

- `splunk_searches_spl.txt`  
  Collection of Splunk SPL queries for detections and dashboards:
  - Brute-force detection search
  - Panel searches for failed attempts, top sources, success-after-fail sequences

---

### 3. Python Requirements

On the analysis host (or directly on the victim/SIEM helper VM):

```bash
sudo apt update
sudo apt install -y python3-pip
pip3 install matplotlib
```

The analyzer uses only the Python standard library; plotting requires `matplotlib`.

---

### 4. Usage

#### 4.1 Collect `auth.log`

On the SSH victim:

1. Enable SSH (e.g., `sudo systemctl enable --now ssh`).
2. Run brute-force attempts from Kali (Nmap / Metasploit).
3. Copy `/var/log/auth.log` (or a time-filtered copy) into this project directory, e.g.:

```bash
sudo cp /var/log/auth.log ./auth.log
sudo chown "$USER":"$USER" ./auth.log
```

#### 4.2 Run the Analyzer

```bash
python3 ssh_bruteforce_analyzer.py -f auth.log
```

You will see console alerts for:

- IPs that exceed a configurable failure threshold in a time window
- IPs that have many failures followed by a success

Alerts are also written to:

- `suspicious_ssh_ips.log`
- `ssh_events.csv` (timestamp, user, source IP, outcome)

#### 4.3 Visualize Events

```bash
python3 plot_ssh_events.py
```

This will show:

- Failed attempts per minute
- Bar chart of top attacking IP addresses

---

### 5. Splunk Content

Use `splunk_searches_spl.txt` as a reference for:

- **Detection searches** to identify brute-force behavior from indexed `auth.log`.
- **Dashboard panels** visualizing:
  - Failed SSH logins over time
  - Top attacking IPs and usernames
  - Success-after-fail sequences

You can copy/paste these SPL searches into Splunk’s Search & Reporting app and into dashboard JSON definitions.

---

### 6. Safety and Ethics

- Run all brute-force simulations only in a **closed lab environment** that you fully control.  
- Never aim brute-force tools at production networks, public servers, or systems you do not own or operate.  
- Use strong, unique passwords on real systems and limit brute-force testing to short, well-bounded experiments.

