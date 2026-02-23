# Linux_Privilege_Escalation_Automation-Toolkit


Overview:
This toolkit automates the detection of privilege escalation opportunities on Linux systems. It is designed for red-team enumeration and blue-team auditing without performing any exploits, making it safe for production environments.

Key Features:

SUID/SGID Binary Scanner: Detect binaries that could allow privilege escalation.

Weak File & Directory Permissions: Identify world-writable files and misconfigured critical system files.

Cron Job Vulnerability Scanner: Detect writable scripts and timing-based privilege escalation vectors.

Service Misconfiguration Detection: Scan systemd services, insecure PATHs, and sudo misconfigurations.

Kernel Vulnerability Analyzer: Check kernel version against known CVEs and suggest mitigations.

Risk Scoring Engine (CVSS-lite): Assigns severity levels for actionable insights.

False-Positive Filtering: Filters common benign SUID binaries and cron entries for clarity.

Automated Reporting: Generates structured reports with findings, severity, and remediation guidance.

Benefits:

Hands-on exposure to Linux security and misconfigurations.

Learn automated security auditing like a real-world penetration tester.

SOC-ready reporting with actionable insights for administrators.
