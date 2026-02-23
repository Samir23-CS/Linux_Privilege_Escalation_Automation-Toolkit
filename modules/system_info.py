import os
import platform
import subprocess
import pwd
import grp
from datetime import datetime


def get_system_info():
    findings = []

    try:
        current_user = pwd.getpwuid(os.getuid()).pw_name
        user_id = os.getuid()
        groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]
        hostname = platform.node()
        kernel_version = platform.release()
        architecture = platform.machine()
        os_info = platform.platform()

        is_root = user_id == 0

        findings.append({
            "severity": "INFO",
            "issue": "Current User",
            "details": f"User: {current_user} (UID: {user_id})",
            "mitigation": "Ensure least privilege access is enforced."
        })

        findings.append({
            "severity": "INFO",
            "issue": "Group Membership",
            "details": f"Groups: {', '.join(groups)}",
            "mitigation": "Review sensitive group memberships (sudo, docker, etc)."
        })

        findings.append({
            "severity": "INFO",
            "issue": "Root Privilege Check",
            "details": "User is root." if is_root else "User is NOT root.",
            "mitigation": "Run scans as non-root for realistic privilege escalation testing."
        })

        findings.append({
            "severity": "INFO",
            "issue": "System Information",
            "details": f"Hostname: {hostname} | OS: {os_info} | Kernel: {kernel_version} | Arch: {architecture}",
            "mitigation": "Ensure OS and kernel are regularly patched."
        })

        # Check sudo privileges
        try:
            sudo_check = subprocess.run(
                ["sudo", "-l"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if "NOPASSWD" in sudo_check.stdout:
                findings.append({
                    "severity": "HIGH",
                    "issue": "Sudo Misconfiguration",
                    "details": "NOPASSWD entry detected in sudo configuration.",
                    "mitigation": "Review /etc/sudoers and restrict NOPASSWD entries."
                })
            else:
                findings.append({
                    "severity": "INFO",
                    "issue": "Sudo Configuration",
                    "details": "No obvious NOPASSWD entries detected.",
                    "mitigation": "Periodically audit sudo privileges."
                })

        except Exception:
            findings.append({
                "severity": "INFO",
                "issue": "Sudo Check",
                "details": "Unable to evaluate sudo privileges.",
                "mitigation": "Run 'sudo -l' manually to inspect privileges."
            })

    except Exception as e:
        findings.append({
            "severity": "ERROR",
            "issue": "System Info Collection Failed",
            "details": str(e),
            "mitigation": "Verify script permissions and environment."
        })

    return findings
