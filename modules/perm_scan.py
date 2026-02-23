import subprocess
import os

CRITICAL_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/crontab"
]

def scan_weak_permissions():
    findings = []
    print("[*] Scanning for weak file and directory permissions...")

    try:
        # 1️⃣ World-writable files
        cmd_files = ["find", "/", "-type", "f", "-perm", "-0002"]
        result_files = subprocess.run(
            cmd_files,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        for file in result_files.stdout.splitlines():
            findings.append({
                "path": file,
                "issue": "World-writable file",
                "risk": "High",
                "description": "Any user can modify this file"
            })

        # 2️⃣ World-writable directories
        cmd_dirs = ["find", "/", "-type", "d", "-perm", "-0002"]
        result_dirs = subprocess.run(
            cmd_dirs,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        for directory in result_dirs.stdout.splitlines():
            findings.append({
                "path": directory,
                "issue": "World-writable directory",
                "risk": "Medium",
                "description": "Any user can write files here"
            })

        # 3️⃣ Critical system file permissions
        for path in CRITICAL_PATHS:
            if os.path.exists(path):
                perm = oct(os.stat(path).st_mode)[-3:]
                if perm[-1] in ["2", "6", "7"]:
                    findings.append({
                        "path": path,
                        "issue": "Weak critical file permissions",
                        "risk": "Critical",
                        "description": f"Insecure permissions detected: {perm}"
                    })

    except Exception as e:
        print(f"[!] Permission scan error: {e}")

    return findings
