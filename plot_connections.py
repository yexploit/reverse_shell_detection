import csv
import datetime
from collections import Counter, defaultdict

import matplotlib.pyplot as plt


LOG_FILE = "connection_events.csv"  # columns: timestamp,src_ip,dst_ip,dst_port


def parse_time(ts_str: str) -> datetime.datetime:
    """Parse timestamp string into datetime."""
    return datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")


def load_events(log_file: str = LOG_FILE):
    """Load connection events from CSV."""
    times = []
    ports = []

    with open(log_file, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            t = parse_time(row["timestamp"])
            times.append(t)
            ports.append(int(row["dst_port"]))

    return times, ports


def plot_connection_frequency(times):
    """Plot number of connections per minute."""
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
    """Plot histogram of suspicious destination ports."""
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
    try:
        times, ports = load_events()
    except FileNotFoundError:
        print("No connection_events.csv file found. Run lab_revshell_analyzer.py first.")
        return

    if not times:
        print("No events in log.")
        return

    plot_connection_frequency(times)
    plot_suspicious_ports(ports)


if __name__ == "__main__":
    main()

