# SentinelStack 🛡️  
### Security Log Analysis & Threat Intelligence Automation (Python)

**SentinelStack** is a lightweight security automation toolkit that analyzes server/application logs, flags suspicious activity, enriches IPs with geolocation + ISP threat context, detects potential brute-force attacks, and generates incident reports in **TXT, Markdown, and HTML**.

---

## 🚀 Features

| Capability | Description |
|-----------|-------------|
| 🔍 Log Parsing | Extracts suspicious events (failed logins, errors, warnings, denied access) |
| 🧠 Threat Intelligence | Fetches Geo/ISP data for IPs using a public API + heuristic risk scoring |
| 🛑 Brute-force Detection | Flags IPs crossing authentication failure thresholds |
| 📊 Incident Summary | Severity rating, category breakdown, sample events |
| 📄 Export Formats | TXT, Markdown (GitHub friendly), and HTML (styled dark theme) |
| 🧱 Modular & Extensible | Can extend into SIEM, dashboards, ISO/DPDP evidence automation |

---

## 🧩 Project Structure

```

SentinelStack/
logs/                ← input .log files
output/              ← generated reports
src/
log_analyzer.py    ← extracts suspicious log events → CSV
incident_report.py ← builds enriched incident report (TXT/MD/HTML)

````

---

## 🛠 Installation

### Python Requirements
- Python 3.8+
- pip

### Install dependencies
```bash
pip install requests
````

---

## ▶ Usage

### 1️⃣ Place your log file

Put your `.log` file here:

```
logs/sample.log
```

### 2️⃣ Run the analyzer (extract suspicious events)

```bash
cd src
python log_analyzer.py
```

Creates:

```
output/suspicious_events.csv
```

### 3️⃣ Generate Threat-Enriched Incident Report

```bash
python incident_report.py
```

Creates:

```
output/incident_report.txt
output/incident_report.md
output/incident_report.html
```

Open `incident_report.html` in any browser for a styled report.

---

## 🧪 Sample Output (Excerpt)

```
Total events     : 14
Overall severity : HIGH

Breakdown by category:
  - authentication_failure: 9
  - application_error: 3
  - application_warning: 2

Per-IP Threat Overview:
IP: 91.203.145.22 | Risk: HIGH | Events: 5 (auth failures: 5) | Berlin, Germany | ISP: Contabo GmbH
IP: 185.244.25.199 | Risk: MEDIUM | Events: 4 (auth failures: 4) | Warsaw, Poland | ISP: Hostinger Intl
```

---

## 🌍 Threat Intelligence Source

This project uses a free public API for geolocation/ISP lookup:

```
http://ip-api.com/json/{ip}
```

You may replace it with:

* AbuseIPDB
* VirusTotal
* GreyNoise
* Shodan

---

## 🧱 Roadmap (Planned Enhancements)

* [ ] PDF reporting
* [ ] Flask web dashboard for real-time analysis
* [ ] Evidence Organizer for ISO 27001 / DPDP Act audits
* [ ] VirusTotal / AbuseIPDB integration
* [ ] SIEM ingestion mode (.json / .ndjson)

---

## 📜 License

MIT License — free for personal & commercial use.

---

## 👤 Author

**Shrinand S Menon**
Cybersecurity & Security Automation Enthusiast
LinkedIn: *https://www.linkedin.com/in/shrinand-s-menon*
GitHub: *https://github.com/Shrinand-Menon*

---

⭐ If you find this useful, please **star the repository**!

````

---

# 📄 LICENSE (MIT) — Copy & Paste

```text
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
````

---

# 🧵 .gitignore (Copy & Paste)

```gitignore
output/
__pycache__/
*.pyc
```

---

# 📁 logs/sample.log (Copy & Paste)

```log
Jan 18 09:15:01 server sshd[1022]: Failed password for invalid user admin from 185.244.25.199 port 54321 ssh2
Jan 18 09:15:03 server sshd[1023]: Failed password for invalid user admin from 185.244.25.199 port 54322 ssh2
Jan 18 09:15:05 server sshd[1024]: Failed password for invalid user admin from 185.244.25.199 port 54323 ssh2
Jan 18 09:15:06 server sshd[1025]: Failed password for invalid user admin from 185.244.25.199 port 54324 ssh2

Jan 18 09:17:10 server sshd[1055]: Failed password for user root from 91.203.145.22 port 42420 ssh2
Jan 18 09:17:12 server sshd[1056]: Failed password for user root from 91.203.145.22 port 42421 ssh2
Jan 18 09:17:14 server sshd[1057]: Failed password for user root from 91.203.145.22 port 42422 ssh2
Jan 18 09:17:16 server sshd[1058]: Failed password for user root from 91.203.145.22 port 42423 ssh2
Jan 18 09:17:18 server sshd[1059]: Failed password for user root from 91.203.145.22 port 42424 ssh2

Jan 18 09:22:45 server app[2200]: ERROR: Database connection timeout
Jan 18 09:23:12 server app[2201]: WARNING: High memory usage detected
Jan 18 09:24:30 server app[2202]: INFO: User session started for user alice
```

---
