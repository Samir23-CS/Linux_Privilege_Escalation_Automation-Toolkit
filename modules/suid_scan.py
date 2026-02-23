import os
import subprocess


# Known high-risk GTFOBins (expand as needed)
GTFO_BINS = {
    "nmap": "Can execute interactive shell via --interactive.",
    "vim": "Can spawn shell via :!sh.",
    "find": "Can execute arbitrary commands via -exec.",
    "bash": "Spawns elevated shell directly.",
    "cp": "Can overwrite protected files.",
    "less": "Can spawn shell via !sh.",
    "more": "Can spawn shell via !sh.",
    "nano": "Can execute commands via spell function.",
    "perl": "Can execute arbitrary commands.",
    "python": "Can execute arbitrary commands.",
    "awk": "Can execute system commands.",
    "man": "Can spawn shell via !sh."
}


def scan_suid_binaries():
    findings = []
    default_suid_count = 0

    print("[*] Scanning for SUID/SGID binaries...")

    SAFE_SYSTEM_PATHS = (
        "/usr/bin/",
        "/usr/sbin/",
        "/bin/",
        "/sbin/",
        "/usr/lib/"
    )

    try:
        result = subprocess.run(
            ["find", "/", "-perm", "-4000", "-o", "-perm", "-2000", "-type", "f"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        binaries = result.stdout.splitlines()

        for binary in binaries:
            binary_name = os.path.basename(binary)

            # ----------------------------
            # 1️⃣ High-Risk GTFOBins
            # ----------------------------
            if binary_name in GTFO_BINS:
                findings.append({
                    "type": "SUID/SGID Binary",
                    "severity": "HIGH",
                    "issue": "Exploitable SUID/SGID Binary",
                    "details": f"{binary} detected with SUID/SGID bit set.",
                    "exploitation": GTFO_BINS[binary_name],
                    "mitigation": "Remove SUID/SGID bit if unnecessary and restrict execution."
                })

            # ----------------------------
            # 2️⃣ Suspicious Custom Location
            # ----------------------------
            elif not binary.startswith(SAFE_SYSTEM_PATHS):
                findings.append({
                    "type": "SUID/SGID Binary",
                    "severity": "CRITICAL",
                    "issue": "Suspicious SUID/SGID Binary Location",
                    "details": f"{binary} detected outside standard system paths.",
                    "exploitation": "Binary located outside trusted system directories.",
                    "mitigation": "Investigate origin and remove SUID/SGID bit if unauthorized."
                })

            # ----------------------------
            # 3️⃣ Default System SUID (Aggregate)
            # ----------------------------
            else:
                default_suid_count += 1
                continue

        # Aggregate baseline system SUID
        if default_suid_count > 0:
            findings.append({
                "type": "SUID/SGID Binary",
                "severity": "LOW",
                "issue": "Default System SUID/SGID Binaries Detected",
                "details": f"{default_suid_count} standard system SUID/SGID binaries found.",
                "exploitation": "Baseline system configuration.",
                "mitigation": "Review only if system integrity is questionable."
            })

    except Exception as e:
        findings.append({
            "type": "SUID/SGID Binary",
            "severity": "ERROR",
            "issue": "SUID Scan Failed",
            "details": str(e),
            "exploitation": "Scan could not complete.",
            "mitigation": "Run script with appropriate permissions."
        })

    return findings
