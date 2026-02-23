import subprocess
import re


# Known high-profile local privilege escalation CVEs (reference only)
KNOWN_KERNEL_LPE = {
    "Dirty COW": "CVE-2016-5195",
    "Dirty Pipe": "CVE-2022-0847",
    "OverlayFS": "CVE-2023-0386"
}


def parse_kernel_version(version_string):
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", version_string)
    if match:
        return tuple(map(int, match.groups()))
    return None


def scan_kernel_vulnerabilities():
    findings = []

    print("[*] Scanning kernel version for known vulnerabilities...")

    try:
        kernel_version = subprocess.check_output(
            ["uname", "-r"],
            text=True
        ).strip()

        parsed = parse_kernel_version(kernel_version)

        if not parsed:
            findings.append({
                "severity": "INFO",
                "issue": "Kernel Version Detection",
                "details": f"Kernel version: {kernel_version}",
                "exploitation": "Manual review required for vulnerability assessment.",
                "mitigation": "Verify kernel version format and patch status."
            })
            return findings

        major, minor, patch = parsed

        # Very old kernel
        if major < 4:
            findings.append({
                "severity": "CRITICAL",
                "issue": "End-of-Life Kernel Detected",
                "details": f"Kernel version: {kernel_version}",
                "exploitation": "Older kernels are highly likely to be vulnerable to multiple local privilege escalation exploits.",
                "mitigation": "Upgrade immediately to a supported LTS kernel version."
            })

        # Potential Dirty COW exposure
        elif major == 4 and minor < 8:
            findings.append({
                "severity": "HIGH",
                "issue": "Potential Dirty COW Vulnerability",
                "details": f"Kernel version: {kernel_version} | Reference: {KNOWN_KERNEL_LPE['Dirty COW']}",
                "exploitation": "Dirty COW allows local users to gain write access to read-only memory mappings.",
                "mitigation": "Upgrade kernel to patched version."
            })

        # Potential Dirty Pipe exposure
        elif major == 5 and minor < 16:
            findings.append({
                "severity": "HIGH",
                "issue": "Potential Dirty Pipe Vulnerability",
                "details": f"Kernel version: {kernel_version} | Reference: {KNOWN_KERNEL_LPE['Dirty Pipe']}",
                "exploitation": "Dirty Pipe allows overwriting read-only files, leading to privilege escalation.",
                "mitigation": "Upgrade to 5.16.11+ or vendor-patched release."
            })

        else:
            findings.append({
                "severity": "LOW",
                "issue": "Kernel Version Check",
                "details": f"Kernel version: {kernel_version}",
                "exploitation": "No obvious outdated major version detected. Still verify vendor patch level.",
                "mitigation": "Continue regular patching and monitor security advisories."
            })

    except Exception as e:
        findings.append({
            "severity": "ERROR",
            "issue": "Kernel Scan Failed",
            "details": str(e),
            "exploitation": "Scan could not complete.",
            "mitigation": "Run manually using 'uname -r' to verify kernel version."
        })

    return findings
