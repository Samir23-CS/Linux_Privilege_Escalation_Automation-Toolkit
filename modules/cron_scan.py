import os
import stat

CRON_PATHS = [
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly"
]


def is_world_writable(path):
    try:
        mode = os.stat(path).st_mode
        return bool(mode & stat.S_IWOTH)
    except:
        return False


def is_root_owned(path):
    try:
        return os.stat(path).st_uid == 0
    except:
        return False


def scan_cron_jobs():
    findings = []

    print("[*] Scanning for vulnerable cron jobs...")

    for path in CRON_PATHS:

        if not os.path.exists(path):
            continue

        # Case 1: /etc/crontab (system-wide cron file)
        if os.path.isfile(path):

            try:
                with open(path, "r") as f:
                    lines = f.readlines()

                for line in lines:
                    if line.strip().startswith("#") or not line.strip():
                        continue

                    if "root" in line:
                        parts = line.split()
                        if len(parts) >= 7:
                            script_path = parts[-1]

                            if os.path.exists(script_path):

                                if is_world_writable(script_path):

                                    findings.append({
                                        "severity": "CRITICAL",
                                        "issue": "Writable Root Cron Script",
                                        "details": f"{script_path} executed by root via /etc/crontab.",
                                        "exploitation": "Attacker can modify the script to execute arbitrary commands as root.",
                                        "mitigation": "Restrict write permissions and ensure script is owned by root."
                                    })

            except:
                continue

        # Case 2: Cron directories
        if os.path.isdir(path):

            for root, dirs, files in os.walk(path):
                for file in files:
                    full_path = os.path.join(root, file)

                    if not os.path.isfile(full_path):
                        continue

                    # Cron directories are executed by root by default
                    if is_world_writable(full_path):

                        findings.append({
                            "severity": "CRITICAL",
                            "issue": "Writable Cron Script",
                            "details": f"{full_path} is world-writable and executed by root.",
                            "exploitation": "Attacker can inject malicious commands to gain root access.",
                            "mitigation": "Remove world-writable permissions and restrict access to root only."
                        })

                    elif not is_root_owned(full_path):

                        findings.append({
                            "severity": "HIGH",
                            "issue": "Cron Script Not Owned by Root",
                            "details": f"{full_path} is executed by root but not owned by root.",
                            "exploitation": "Improper ownership could allow privilege escalation if ownership changes.",
                            "mitigation": "Ensure all cron scripts are owned by root."
                        })

    return findings
