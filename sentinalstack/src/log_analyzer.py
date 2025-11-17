import os
import csv

# -------- SETTINGS --------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE_PATH = os.path.join(BASE_DIR, "logs", "sample.log")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "suspicious_events.csv")

# Keywords that indicate suspicious or important events
SUSPICIOUS_KEYWORDS = ["failed", "error", "warning", "denied", "invalid"]


def ensure_output_dir():
    """Create the output directory if it doesn't exist."""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)


def analyze_log_file(log_path):
    """
    Read the log file line by line.
    Return a list of dictionaries with suspicious events.
    """
    events = []

    if not os.path.exists(log_path):
        print(f"[!] Log file not found: {log_path}")
        return events

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line_number, line in enumerate(f, start=1):
            lower_line = line.lower()

            if any(keyword in lower_line for keyword in SUSPICIOUS_KEYWORDS):
                events.append({
                    "line_number": line_number,
                    "raw_line": line.strip()
                })

    return events


def save_events_to_csv(events, output_path):
    """Save the suspicious events into a CSV file."""
    if not events:
        print("[*] No suspicious events found. Nothing to save.")
        return

    fieldnames = ["line_number", "raw_line"]

    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for event in events:
            writer.writerow(event)

    print(f"[+] Saved {len(events)} suspicious events to: {output_path}")


def main():
    print("[*] SentinelStack - Log Analyzer")
    print(f"[*] Reading log file: {LOG_FILE_PATH}")

    ensure_output_dir()

    events = analyze_log_file(LOG_FILE_PATH)

    print(f"[*] Found {len(events)} suspicious lines.")
    save_events_to_csv(events, OUTPUT_CSV)


if __name__ == "__main__":
    main()
