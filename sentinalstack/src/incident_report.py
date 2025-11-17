import os
import csv
import re
from collections import Counter
from datetime import datetime

import requests  # for IP reputation / geo lookup

# -------- PATH SETTINGS --------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
SUSPICIOUS_CSV = os.path.join(OUTPUT_DIR, "suspicious_events.csv")
INCIDENT_REPORT_PATH = os.path.join(OUTPUT_DIR, "incident_report.txt")

# Regex to detect IPv4 addresses in log lines
IP_REGEX = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")

# Threshold: how many auth failures from the same IP before we flag brute force
BRUTE_FORCE_THRESHOLD = 3

# Public geolocation API (free, no key, okay for demo)
IP_GEO_API = "http://ip-api.com/json/{ip}"


# ---------- CLASSIFICATION & LOADING ----------

def classify_event(raw_line):
    """Classify the type of suspicious event based on keywords."""
    text = raw_line.lower()

    if "failed password" in text or "authentication failure" in text:
        return "authentication_failure"
    if "invalid user" in text or "denied" in text:
        return "access_denied"
    if "error" in text:
        return "application_error"
    if "warning" in text:
        return "application_warning"

    return "other_suspicious"


def extract_ip(raw_line):
    """Try to extract an IP address from the log line."""
    match = IP_REGEX.search(raw_line)
    if match:
        return match.group(0)
    return None


def load_events(csv_path):
    """
    Load suspicious events from the CSV produced by log_analyzer.py.
    Returns a list of event dicts with extra derived fields.
    """
    events = []

    if not os.path.exists(csv_path):
        print(f"[!] Suspicious events CSV not found: {csv_path}")
        return events

    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw_line = row.get("raw_line", "")
            line_number = row.get("line_number", "")

            category = classify_event(raw_line)
            ip = extract_ip(raw_line)

            events.append({
                "line_number": line_number,
                "raw_line": raw_line,
                "category": category,
                "ip": ip,
            })

    return events


# ---------- THREAT INTEL / IP REPUTATION ----------

def fetch_ip_geo(ip, session, cache):
    """
    Get basic geo / ISP info for an IP using a free API.
    Uses a cache dict to avoid repeated lookups.
    """
    if ip in cache:
        return cache[ip]

    url = IP_GEO_API.format(ip=ip)
    try:
        resp = session.get(url, timeout=5)
        data = resp.json()
    except Exception:
        data = {"status": "fail"}

    if data.get("status") != "success":
        info = {
            "country": "Unknown",
            "isp": "Unknown",
            "city": "Unknown",
        }
    else:
        info = {
            "country": data.get("country", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "city": data.get("city", "Unknown"),
        }

    cache[ip] = info
    return info


def rate_ip_risk(ip, auth_fail_count, total_events_for_ip, geo_info):
    """
    Simple heuristic risk rating for an IP based on:
    - country
    - number of auth failures
    - total suspicious events
    """
    country = geo_info.get("country", "Unknown")

    # High risk: many auth failures and foreign country
    if auth_fail_count >= BRUTE_FORCE_THRESHOLD and country not in ("India", "Unknown"):
        return "HIGH"

    # Medium risk: many failures regardless of country
    if auth_fail_count >= BRUTE_FORCE_THRESHOLD:
        return "MEDIUM"

    # Low risk: some suspicious events
    if total_events_for_ip >= 2:
        return "LOW"

    # Only one suspicious event, unclear
    return "INFO"


def determine_overall_severity(total_events, brute_force_ips):
    """
    Compute a simple overall severity level.
    This is heuristic, not perfect — but good enough for MVP.
    """
    has_bruteforce = len(brute_force_ips) > 0

    if has_bruteforce and total_events >= 10:
        return "HIGH"
    if has_bruteforce or total_events >= 5:
        return "MEDIUM"
    if total_events > 0:
        return "LOW"
    return "NONE"


def build_summary(events):
    """
    Build a human-readable incident summary as a string.
    Includes:
    - category breakdown
    - per-IP threat overview (geo/ISP/risk)
    - brute-force candidates
    - overall severity
    """
    if not events:
        return "No suspicious events found. No incident report generated.\n"

    total_events = len(events)

    category_counts = Counter(e["category"] for e in events)
    ip_counts_all = Counter(e["ip"] for e in events if e["ip"])

    failed_auth_ips = Counter(
        e["ip"] for e in events
        if e["category"] == "authentication_failure" and e["ip"]
    )

    # IPs exceeding threshold = potential brute-force
    brute_force_ips = {
        ip: count for ip, count in failed_auth_ips.items()
        if count >= BRUTE_FORCE_THRESHOLD
    }

    severity = determine_overall_severity(total_events, brute_force_ips)

    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Fetch IP geo & risk info
    session = requests.Session()
    ip_geo_cache = {}
    ip_risk_info = {}

    for ip, total_count in ip_counts_all.items():
        auth_fail_count = failed_auth_ips.get(ip, 0)
        geo = fetch_ip_geo(ip, session, ip_geo_cache)
        risk = rate_ip_risk(ip, auth_fail_count, total_count, geo)
        ip_risk_info[ip] = {
            "total_events": total_count,
            "auth_failures": auth_fail_count,
            "country": geo.get("country", "Unknown"),
            "city": geo.get("city", "Unknown"),
            "isp": geo.get("isp", "Unknown"),
            "risk": risk,
        }

    lines = []
    lines.append("SentinelStack - Incident Summary Report")
    lines.append("=" * 60)
    lines.append(f"Generated at     : {generated_at}")
    lines.append(f"Total events     : {total_events}")
    lines.append(f"Overall severity : {severity}")
    lines.append("")

    # Category breakdown
    lines.append("Breakdown by category:")
    for category, count in category_counts.most_common():
        lines.append(f"  - {category}: {count}")
    lines.append("")

    # Per-IP threat overview
    if ip_risk_info:
        lines.append("Per-IP Threat Overview:")
        lines.append("-" * 60)
        for ip, info in ip_risk_info.items():
            lines.append(
                f"IP: {ip} | Risk: {info['risk']} | "
                f"Events: {info['total_events']} "
                f"(auth failures: {info['auth_failures']}) | "
                f"{info['city']}, {info['country']} | ISP: {info['isp']}"
            )
        lines.append("")
    else:
        lines.append("No IP addresses detected in suspicious events.")
        lines.append("")

    # Brute-force candidates
    if brute_force_ips:
        lines.append("Potential brute-force sources (authentication failures):")
        for ip, count in brute_force_ips.items():
            lines.append(
                f"  - {ip}: {count} failed authentication attempts "
                f"(threshold = {BRUTE_FORCE_THRESHOLD})"
            )
        lines.append("")
    else:
        lines.append(
            f"No IPs exceeded the brute-force threshold of "
            f"{BRUTE_FORCE_THRESHOLD} failed logins."
        )
        lines.append("")

    # Sample events
    lines.append("Sample suspicious events (up to 5):")
    lines.append("-" * 60)
    for event in events[:5]:
        lines.append(
            f"[Line {event['line_number']}] "
            f"({event['category']}) "
            f"{event['raw_line']}"
        )
    lines.append("")

    return "\n".join(lines)


# ---------- OUTPUT HELPERS: TXT / MD / HTML ----------

def save_report_txt(report_text, path):
    """Write the incident summary to a plain text file."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(report_text)
    print(f"[+] Text incident report saved to: {path}")


def save_report_md(report_text, path):
    """
    Save the report in Markdown format as a fenced code block.
    Renders neatly on GitHub / Markdown viewers.
    """
    with open(path, "w", encoding="utf-8") as f:
        f.write("```text\n")
        f.write(report_text)
        f.write("\n```")
    print(f"[+] Markdown incident report saved to: {path}")


def _html_escape(text):
    """Minimal HTML escaping for <, >, &."""
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
    )


def save_report_html(report_text, path):
    """
    Save the report as a simple styled HTML page.
    """
    escaped = _html_escape(report_text)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SentinelStack Incident Report</title>
  <style>
    body {{
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background-color: #0b1020;
      color: #e8ecf4;
      margin: 0;
      padding: 24px;
    }}
    .container {{
      max-width: 960px;
      margin: 0 auto;
      background-color: #111827;
      border-radius: 12px;
      padding: 24px 28px;
      box-shadow: 0 18px 40px rgba(0,0,0,0.6);
      border: 1px solid #1f2937;
    }}
    h1 {{
      font-size: 1.4rem;
      margin-top: 0;
      margin-bottom: 12px;
    }}
    .meta {{
      font-size: 0.8rem;
      color: #9ca3af;
      margin-bottom: 16px;
    }}
    pre {{
      font-family: "JetBrains Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 0.78rem;
      white-space: pre-wrap;
      word-wrap: break-word;
      background-color: #020617;
      border-radius: 8px;
      padding: 16px;
      border: 1px solid #1f2937;
      line-height: 1.4;
    }}
  </style>
</head>
<body>
  <div class="container">
    <h1>SentinelStack &mdash; Incident Summary Report</h1>
    <div class="meta">
      Generated by SentinelStack (Python security automation prototype)
    </div>
    <pre>{escaped}</pre>
  </div>
</body>
</html>
"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] HTML incident report saved to: {path}")


# ---------- MAIN ----------

def main():
    print("[*] SentinelStack - Incident Reporter (Threat Intel + Multi-format Output)")
    print(f"[*] Reading suspicious events from: {SUSPICIOUS_CSV}")

    events = load_events(SUSPICIOUS_CSV)
    print(f"[*] Loaded {len(events)} suspicious events.")

    report_text = build_summary(events)

    # Text
    save_report_txt(report_text, INCIDENT_REPORT_PATH)

    # Markdown
    md_path = INCIDENT_REPORT_PATH.replace(".txt", ".md")
    save_report_md(report_text, md_path)

    # HTML
    html_path = INCIDENT_REPORT_PATH.replace(".txt", ".html")
    save_report_html(report_text, html_path)


if __name__ == "__main__":
    main()
