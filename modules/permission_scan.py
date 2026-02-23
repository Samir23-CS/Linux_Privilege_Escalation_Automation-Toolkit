import os
import stat


EXCLUDED_PATHS = (
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/snap"
)


def is_excluded(path):
    return any(path.startswith(excluded) for excluded in EXCLUDED_PATHS)


def scan_weak_permissions():
    findings = []
    print("[*] Scanning for weak file and directory permissions...")

    for root, dirs, files in os.walk("/", topdown=True):

        # Proper directory pruning (prevents descending into excluded paths)
        dirs[:] = [
            d for d in dirs
            if not is_excluded(os.path.join(root, d))
        ]

        # ---------- Directory Checks ----------
        for name in dirs:
            path = os.path.join(root, name)

            try:
                st = os.lstat(path)

                # Skip symbolic links
                if stat.S_ISLNK(st.st_mode):
                    continue

                # Skip special filesystem objects
                if (
                    stat.S_ISSOCK(st.st_mode) or
                    stat.S_ISFIFO(st.st_mode) or
                    stat.S_ISCHR(st.st_mode) or
                    stat.S_ISBLK(st.st_mode)
                ):
                    continue

                # Check world-writable directory
                if st.st_mode & stat.S_IWOTH:

                    # Ignore sticky-bit directories (e.g., /tmp)
                    if st.st_mode & stat.S_ISVTX:
                        continue

                    findings.append({
                        "type": "Weak Permission",
                        "severity": "HIGH",
                        "issue": "World-Writable Directory Detected",
                        "details": path,
                        "mitigation": "Restrict directory permissions and validate ownership."
                    })

            except (PermissionError, FileNotFoundError):
                continue

        # ---------- File Checks ----------
        for name in files:
            path = os.path.join(root, name)

            try:
                st = os.lstat(path)

                # Skip symbolic links
                if stat.S_ISLNK(st.st_mode):
                    continue

                # Skip special filesystem objects
                if (
                    stat.S_ISSOCK(st.st_mode) or
                    stat.S_ISFIFO(st.st_mode) or
                    stat.S_ISCHR(st.st_mode) or
                    stat.S_ISBLK(st.st_mode)
                ):
                    continue

                # Check world-writable file
                if st.st_mode & stat.S_IWOTH:

                    # Escalate severity if owned by root
                    if st.st_uid == 0:
                        severity = "CRITICAL"
                    else:
                        severity = "HIGH"

                    findings.append({
                        "type": "Weak Permission",
                        "severity": severity,
                        "issue": "World-Writable File Detected",
                        "details": path,
                        "mitigation": "Restrict permissions using chmod and verify ownership."
                    })

            except (PermissionError, FileNotFoundError):
                continue

    return findings
