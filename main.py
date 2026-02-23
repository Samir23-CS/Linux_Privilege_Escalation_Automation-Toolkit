#!/usr/bin/env python3

from modules.suid_scan import scan_suid_binaries
from modules.permission_scan import scan_weak_permissions
from modules.cron_scan import scan_cron_jobs
from modules.service_scan import scan_services
from modules.kernel_scan import scan_kernel_vulnerabilities
from modules.system_info import get_system_info

import os
from datetime import datetime


# ============================================================
# BANNER
# ============================================================

def banner():
    print("=" * 60)
    print(" Linux Privilege Escalation Automation Toolkit ")
    print(" Detection | Security Auditing Framework ")
    print("=" * 60)


# ============================================================
# FALSE POSITIVE FILTERING
# ============================================================

SAFE_SUID_BINARIES = {
    "/usr/bin/passwd",
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/chsh",
    "/usr/bin/chfn"
}

SAFE_CRON_PATHS = {
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly"
}


def is_false_positive(item):
    path = item.get("details", "")
    item_type = item.get("type", "")

    if item_type == "SUID Binary" and path in SAFE_SUID_BINARIES:
        return True

    if item_type == "Cron Job":
        for safe in SAFE_CRON_PATHS:
            if path.startswith(safe):
                return True

    return False


# ============================================================
# CVSS-LITE RISK SCORING
# ============================================================

def calculate_risk_score(item):
    severity_weight = {
        "CRITICAL": 9,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 2
    }

    base_sev = item.get("severity", "LOW")
    score = severity_weight.get(base_sev, 2)

    issue_text = item.get("issue", "").lower()
    item_type = item.get("type", "")

    if "world-writable" in issue_text:
        score += 2

    if item_type == "SUID Binary":
        score += 3

    if item_type == "Cron Job":
        score += 2

    return min(score, 10)


def score_to_severity(score):
    if score >= 9:
        return "CRITICAL"
    elif score >= 7:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    else:
        return "LOW"


# ============================================================
# SCHEMA NORMALIZATION
# ============================================================

def normalize_item(item):
    """
    Enforces consistent structure across all modules.
    """

    return {
        "type": item.get("type", "Security Finding"),
        "severity": item.get("severity", "LOW"),
        "issue": item.get("issue", "Unspecified Issue"),
        "details": item.get("details", item.get("path", "N/A")),
        "mitigation": item.get("mitigation", "Review and remediate accordingly.")
    }


# ============================================================
# REPORT GENERATION
# ============================================================

def generate_report(findings):
    os.makedirs("reports", exist_ok=True)
    report_path = "reports/report.txt"

    with open(report_path, "w") as report:
        header = (
            "============================================================\n"
            " Linux Privilege Escalation Automation Toolkit Report\n"
            " Detection-Only | Security Auditing Framework\n"
            f" Generated At: {datetime.now()}\n"
            "============================================================\n\n"
        )

        print(header)
        report.write(header)

        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for item in findings:
            block = (
                f"[{item['severity']}] {item['type']} (Risk Score: {item['risk_score']})\n"
                f"Issue      : {item['issue']}\n"
                f"Details    : {item['details']}\n"
                f"Mitigation : {item['mitigation']}\n"
                "--------------------------------------------------\n"
            )

            print(block)
            report.write(block)
            summary[item["severity"]] += 1

        footer = (
            "\n================ SCAN SUMMARY ================\n"
            f"CRITICAL : {summary['CRITICAL']}\n"
            f"HIGH     : {summary['HIGH']}\n"
            f"MEDIUM   : {summary['MEDIUM']}\n"
            f"LOW      : {summary['LOW']}\n"
            "================================================\n"
        )

        print(footer)
        report.write(footer)

    print(f"[+] Report saved to {report_path}")


# ============================================================
# MAIN
# ============================================================

def main():
    banner()

    raw_findings = []

    # Collect findings safely
    modules = [
        get_system_info,
        scan_suid_binaries,
        scan_weak_permissions,
        scan_cron_jobs,
        scan_services,
        scan_kernel_vulnerabilities
    ]

    for module in modules:
        try:
            results = module()
            if isinstance(results, list):
                raw_findings.extend(results)
        except Exception as e:
            print(f"[!] Module error: {module.__name__} -> {e}")

    final_findings = []

    for item in raw_findings:
        if not isinstance(item, dict):
            continue

        normalized = normalize_item(item)

        if is_false_positive(normalized):
            continue

        score = calculate_risk_score(normalized)
        normalized["risk_score"] = score
        normalized["severity"] = score_to_severity(score)

        final_findings.append(normalized)

    generate_report(final_findings)


if __name__ == "__main__":
    main()
