import subprocess
import os
import stat


def is_world_writable(path):
    try:
        mode = os.stat(path).st_mode
        return bool(mode & stat.S_IWOTH)
    except Exception:
        return False


def is_root_owned(path):
    try:
        return os.stat(path).st_uid == 0
    except Exception:
        return False


def scan_services():
    findings = []
    print("[*] Scanning systemd services for misconfigurations...")

    try:
        result = subprocess.run(
            ["systemctl", "list-unit-files", "--type=service", "--no-pager"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        services = [
            line.split()[0]
            for line in result.stdout.splitlines()
            if line.endswith("enabled")
        ]

        for service_name in services:
            try:
                service_content = subprocess.run(
                    ["systemctl", "cat", service_name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True
                )

                for line in service_content.stdout.splitlines():
                    line = line.strip()

                    if line.startswith("ExecStart="):
                        exec_path = line.split("=", 1)[1].strip()

                        # Remove systemd "-" ignore-failure prefix
                        exec_path = exec_path.lstrip("-")

                        # Remove arguments if present
                        exec_path = exec_path.split()[0]

                        # Ensure path exists before checking
                        if not os.path.exists(exec_path):
                            continue

                        # ----------------------------
                        # 1️⃣ World-Writable Check
                        # ----------------------------
                        if is_world_writable(exec_path):
                            findings.append({
                                "type": "Service Misconfiguration",
                                "severity": "CRITICAL",
                                "issue": "Writable Binary Executed by systemd Service",
                                "details": f"{exec_path} used by {service_name} is world-writable.",
                                "mitigation": "Remove world-writable permission and restrict ownership to root."
                            })

                        # ----------------------------
                        # 2️⃣ Non-Root Ownership Check
                        # ----------------------------
                        elif not is_root_owned(exec_path):
                            findings.append({
                                "type": "Service Misconfiguration",
                                "severity": "HIGH",
                                "issue": "Service Binary Not Owned by Root",
                                "details": f"{exec_path} used by {service_name} is not owned by root.",
                                "mitigation": "Ensure service binaries are owned by root."
                            })

                        # ----------------------------
                        # 3️⃣ User Directory Execution
                        # ----------------------------
                        if exec_path.startswith("/home/"):
                            findings.append({
                                "type": "Service Misconfiguration",
                                "severity": "CRITICAL",
                                "issue": "Service Executing User-Controlled Binary",
                                "details": f"{service_name} executes binary inside user directory: {exec_path}",
                                "mitigation": "Move service binary to secure root-owned directory."
                            })

            except Exception:
                continue

    except Exception as e:
        findings.append({
            "type": "Service Scan",
            "severity": "LOW",
            "issue": "Service Scan Failed",
            "details": str(e),
            "mitigation": "Ensure systemctl is available and script has required permissions."
        })

    return findings
