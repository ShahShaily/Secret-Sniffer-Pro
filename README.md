# 🛡️ SEC-SNIFFER PRO
**"High-Precision Real-time Secret Scanner & Security Auditor Tool"**

SEC-SNIFFER PRO is a professional-grade Static Application Security Testing (SAST) engine designed to find hardcoded credentials, API keys, and tokens before they lead to a breach.
Unlike traditional scanners that flood you with junk findings, SEC-SNIFFER PRO focuses on Accuracy, Context, and Actionable Results.

* **🚀 Why Choose SEC-SNIFFER PRO?**
Standard scanners often generate thousands of results, 90% of which are "False Positives" (junk data). SEC-SNIFFER PRO is engineered for high-fidelity detection—delivering fewer alerts, but ensuring every result is a verified True Positive.

## 🌟 Key Features

* **🤖 AI-Powered Leak Analysis**: Uses intelligent logic to verify "threat potential." It analyzes variable names and code context to confirm real credentials, acting like a virtual security researcher.
* **📉 Smart False-Positive Shield**: Advanced filtering automatically ignores dummy data (e.g., test_password) and common placeholders that usually trigger false alarms.
* **🎯 Heuristic Entropy Discovery**: Uses Shannon Entropy to catch "silent" leaks—randomly generated strings like encryption keys or custom tokens that standard regex misses.
* **📍 Exact Line-Level Precision**: Points you to the Exact Line Number and file path for every finding, allowing for instant verification and lightning-fast fixes.
* **⚠️ Intelligent Risk Classification**: Performs a Permission Audit. If a secret is found in a "World-Readable" file, the risk is automatically escalated to CRITICAL.
* **🛰️ Live 'Watchdog' Monitoring**: Monitors your project live. The moment you save a file, the 'Watchdog' logic re-scans it in seconds for immediate feedback.
* **🔔 Instant Audio-Visual Alerts**: Triggers a Windows Beep and a visual GUI warning the moment a critical leak is detected, preventing secrets from ever being committed.
* **⚡ Performance Optimized**: Multi-threaded engine intelligently skips heavy folders like node_modules and .git for lightning-fast scanning of large repositories.
* **📊 Professional Reporting**: Generates audit-ready reports in Interactive HTML Dashboard, JSON, and CSV formats for seamless security documentation.
* **🖥️ Responsive GUI**: A clean, multi-threaded Tkinter interface that stays smooth and responsive even during heavy background operations.

**📊 Professional Reporting Suite**

* **Audit-ready reports are generated in three formats**:
* **Interactive HTML Dashboard**: A dark-themed, searchable UI with color-coded risk badges and fix instructions.
* **JSON Output**: Clean, structured data ready for CI/CD Pipelines or automated security workflows.
* **CSV Export**: Spreadsheet-friendly format for compliance and deep-dive audits.

## 🛠️ Technical Stack

* **Language:** Python 3.x
* **Logic**: AI-Contextual Filtering + Hybrid Regex + Shannon Entropy.
* **UI**: Responsive Tkinter with asynchronous Queue handling.
* **Remediation**: Built-in guidance for .env migration and secret rotation.

## 🚀 How to Use

1. **Clone the Repository:**
   git clone [https://github.com/ShahShaily/SEC-SNIFFER-PRO.git](https://github.com/ShahShaily/SEC-SNIFFER-PRO.git)
2. **Launch the Application:**
   python sensitive_finder.py
3. **Operation**:
   Click the 'Browse' button to select your target project folder.
   Click 'Start Monitor' to begin the security audit.
   The tool will run in the background. If a secret is saved in any file, you will hear a Beep Alert instantly!
  
    **Disclaimer**
*  This project is intended for educational purposes and authorized security auditing only. Always obtain explicit permission before scanning third-party repositories.
