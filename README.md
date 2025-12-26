# Secret-Sniffer-Pro: SAST Security Auditor

Secret-Sniffer-Pro is a Python-based security tool designed for real-time directory monitoring. It identifies hidden vulnerabilities and hardcoded credentials within source code to prevent potential data breaches.

## How It Works
 **Directory Scanning:** Automatically traverses through all sub-folders (controllers, models, views) to ensure full coverage.
 **Content Analysis:** Reads file content line-by-line to identify sensitive patterns rather than just looking at file names.
 **Pattern Matching:** Uses optimized logic to detect Passwords, API Tokens, and Admin access keys.

## Risk Classification
 **Critical:** Hardcoded secrets, tokens, or admin credentials found in the code.
 **High:** Exposed sensitive files like .env or database configurations.

## Project Results: E-Commerce Audit
Tested this auditor on a Node.js e-commerce project with the following results:
 **Total Risks:** 15 security leaks identified.
 **Target Files:** Found exposed data in app.js, auth.js, and user.js.
 **Impact:** Identified potential unauthorized admin access points.

## Tech Stack
 **Language:** Python
 **Core Logic:** Automated 10-second refresh intervals for continuous surveillance.

## Future Roadmap
 Adding Gemini API for advanced threat analysis.
 Supporting PDF and JSON report exports.
 Cloud secret scanning for AWS and Azure keys.
