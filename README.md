Cyber Secret Scanner Pro 

Developed by **[Meera V Nair (meeravnair)](https://github.com/meeravnair)**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.11+-brightgreen.svg)](https://python.org)

**Cyber Secret Scanner Pro** is a production-grade, modular static application security testing (SAST) tool designed to scan directories recursively and detect exposed secrets, credentials, API keys, private keys, database connection strings, passwords, and sensitive configurations.

Developed for enterprise auditing, it incorporates precompiled high-fidelity regex signatures, Shannon entropy heuristic analysis, and duplicate detection. It generates beautiful, interactive HTML reports with an embedded risk scoring index dashboard, alongside machine-readable JSON and CSV feeds.

---

## Key Features

*   **Recursive Directory Auditing:** Traverses folders efficiently, filtering out binary files and unsupported extensions to optimize scanning.
*   **Dual-Engine Scanning:**
    *   *Signature Engine:* Evaluates lines against **45 custom security signatures** covering AWS, Google Cloud, GitHub, Slack, Discord, Stripe, Twilio, OpenAI, database connection URIs, cryptographic PEM keyblocks, and more.
    *   *Entropy Engine:* Calculates **Shannon Entropy** on code variable assignments to detect random cryptographic keys and tokens that don't match specific regular expressions.
*   **Risk Scoring Algorithm:** Computes a normalized security score (0 to 100) using custom severity weights (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
*   **Interactive Dashboard Reports:** Generates dark-mode-first HTML dashboards with responsive Chart.js data distributions, column sorting, global search, and severity filters.
*   **High Performance & Safe Execution:** Limit scanning on excessively large files (>10MB) and safely attempts multiple encodings (UTF-8, UTF-16, Latin-1, CP1252) to prevent crashes.
*   **SHA-256 File Integrity Check:** Computes integrity hashes for every scanned file for complete security auditing logs.

---

## 📁 Project Structure

```
CyberSecretScanner/
│   .gitignore
│   config.py          # Global scanner and risk weights configurations
│   LICENSE            # MIT License terms
│   logger.py          # Colorama console logging setup
│   models.py          # Dataclass OOP model structures
│   patterns.py        # Library of 45 precompiled regex signatures
│   README.md          # Technical documentation
│   requirements.txt   # Third-party dependency definitions
│   report.py          # Report generators (CSV, JSON, Jinja2 HTML)
│   scanner.py         # Main scanning engine and CLI runner
│   utils.py           # Shannon entropy, binary checkers, and hashing utilities
├───reports/           # Auto-saved output directory for reports
├───samples/           # Vulnerable code samples for scanning verification
│       sample.env
│       sample.json
│       sample.py
│       sample.txt
└───templates/
        report.html    # Jinja2 template for interactive dashboard
```

---

## 🛠️ Installation & Setup

1. **Prerequisites:** Python 3.11+ is required.
2. **Clone/Extract** the project to your workspace directory.
3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
<img width="388" height="110" alt="Screenshot 2026-07-01 110811" src="https://github.com/user-attachments/assets/3d897c6b-dc95-43b1-aba1-76c081dba9f5" />

---

## 💻 Usage

Run the scanner directly from the command line by pointing to the target folder you want to audit:

```bash
# Scan the sample vulnerable directory (default output is written inside reports/)
python scanner.py samples/

# Scan the current directory with a custom output location
python scanner.py . --output-dir audit_logs/

# Scan with custom Shannon Entropy threshold override (e.g. 5.2 for higher random threshold)
python scanner.py samples/ --entropy 5.2

# Exclude specific report formats
python scanner.py samples/ --no-csv --no-json
```
<img width="530" height="254" alt="Screenshot 2026-07-01 110827" src="https://github.com/user-attachments/assets/bb0375b8-d3c4-4855-9179-9797320a4beb" />

### CLI Command Options

| Argument | Description | Default |
| :--- | :--- | :--- |
| `target` | Directory path to scan recursively | `.` (current directory) |
| `-o`, `--output-dir` | Directory where reports are stored | `reports` |
| `-l`, `--log-file` | Path to write execution log file | `scanner.log` |
| `--entropy` | Override default Shannon Entropy threshold (default: 4.5) | `4.5` |
| `--no-html` | Skip HTML report generation | `False` |
| `--no-json` | Skip JSON report generation | `False` |
| `--no-csv` | Skip CSV report generation | `False` |

---

## 📊 Output Formats

Every scan produces three distinct reports saved inside `reports/`:
1.  **HTML Dashboard (`scan_report.html`):** An interactive, fully responsive, self-contained dashboard. Includes interactive search, severity-filtering dropdown, file sort indicators, details drawer with secret description, and Chart.js telemetry charts.
2.  **JSON Database (`scan_report.json`):** Contains complete audit data structure including scanned file lists, SHA-256 hashes, vulnerability details, and scanning execution metadata.
3.  **CSV Logfile (`scan_report.csv`):** Standard flat spreadsheet file listing findings, suitable for importing into custom SOC/SIEM setups.
<img width="522" height="416" alt="Screenshot 2026-07-01 110848" src="https://github.com/user-attachments/assets/1c40eb25-fd24-4792-9999-23ee8fe9900c" />
<img width="586" height="386" alt="image" src="https://github.com/user-attachments/assets/56a7871c-62a3-42e8-bc7b-f4f5398b5500" />

---

## 🛡️ Future Improvements

*   **Pre-commit Hook Integration:** Add Git pre-commit configuration blocks to prevent developers from committing exposed secrets.
*   **Git History Scans:** Traverse Git history/commits to identify deleted secrets.
*   **Multiprocessing:** Use Python `multiprocessing` to run multi-file scanning concurrently, enhancing speed on huge code bases.
*   **CI/CD Pipeline Integration:** Provide GitHub Action configurations to automate scanning in pull requests.

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
