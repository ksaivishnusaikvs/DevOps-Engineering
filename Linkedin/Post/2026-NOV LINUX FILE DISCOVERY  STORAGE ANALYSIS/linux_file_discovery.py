#!/usr/bin/env python3
"""
linux_file_discovery.py  v2.3  -  Linux file discovery & reporting (REPORT ONLY, NEVER DELETES)
===========================================================================================
Python 3.8+, standard library only.  AWS / Azure / GCP / on-prem Linux.

WHAT IT DOES
  1 detect cloud  2 walk the disks  3 find files unused for N days  4 find secrets (name + content)
  5 add last-modified, last-activity, owner and "modified by" (from auditd)  6 colour TUI with tables
  7 PDF/Word/HTML/Excel/CSV/JSON/TXT reports (every file)
  8 send the SAME report to Slack, Teams and Discord (summary, graphs, every age group) + attach the report files

SAFETY
  * No delete / move / chmod / write-to-scanned-dir code exists in this script.
  * Content is read (read-only, O_NOATIME) only to look for secrets; secret VALUES are never stored or sent.
  * Symlinks are never followed; /proc /sys /dev ... are skipped; reports are written 0600 (dir 0700).

SETTINGS  (all in this file - see the block "WEBHOOKS + SLACK FILE UPLOAD" near the top)
  SLACK_WEBHOOK_URL, TEAMS_WEBHOOK_URL, DISCORD_WEBHOOK_URL   -> the chat messages
  SLACK_BOT_TOKEN, SLACK_CHANNEL_ID                            -> only for attaching files to Slack
  These are passwords: keep this file private:  chmod 600 linux_file_discovery.py
  (Environment variables / /etc/file_discovery.env still work as a fallback for any value left empty.)

WHY SLACK GOT THE MESSAGE BUT NOT THE FILES
  Slack "Incoming Webhooks" can only post text. Files need a Slack app with a bot token:
    1. api.slack.com/apps -> Create New App -> From scratch
    2. OAuth & Permissions -> Bot Token Scopes: files:write  (and chat:write)  -> Install to Workspace
    3. copy the xoxb-... token into SLACK_BOT_TOKEN
    4. in the Slack channel type:  /invite @YourAppName
    5. channel ID: right-click channel -> View details -> bottom (C0123...) into SLACK_CHANNEL_ID
    6. paste the token and the channel ID into SLACK_BOT_TOKEN / SLACK_CHANNEL_ID at the top of this file
    7. check it:  ./linux_file_discovery.py --test-notify
  Teams webhooks also cannot carry files (Teams gets the full summary, graphs and age groups).

WHO MODIFIED A FILE?
  Linux stores only the OWNER and timestamps, never "who edited it". Real answers need auditd:
      sudo ./linux_file_discovery.py --audit-setup      (prints the 4 commands to enable it)
  After that the "MODIFIED BY" column shows e.g. "ubuntu via vim" or "ubuntu as root via sudo".
  Until then it shows "unknown" - the OWNER column is the best clue.

EXAMPLES
  sudo ./linux_file_discovery.py                         # scan, show TUI, save reports, post to Slack+Discord
  sudo ./linux_file_discovery.py --full --top 0          # nothing hidden, every file in the terminal
  sudo ./linux_file_discovery.py --chat-full             # every file in chat too (paginated)
  ./linux_file_discovery.py --test-notify                # 10-second webhook + Slack-token check, no scan
  0 2 * * 0 root /usr/local/bin/linux_file_discovery.py >> /var/log/file_discovery.log 2>&1
"""
import argparse
import csv
import ctypes
import fcntl
import fnmatch
import grp
import html as htmllib
import json
import logging
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterator, List, Optional, Tuple

log = logging.getLogger("file_discovery")
VERSION = "2.3"
USER_AGENT = f"linux-file-discovery/{VERSION} (report-only)"

# --------------------------------------------------------------------------- #
# CONFIGURATION
# --------------------------------------------------------------------------- #
DEFAULT_ROOTS = ["/", "/home", "/home/ubuntu"]
DEFAULT_EXCLUDES = {"/proc", "/sys", "/dev", "/run", "/snap",
                    "/var/lib/docker", "/var/lib/containerd", "/var/lib/kubelet"}
SYSTEM_PATHS = {"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/boot",
                "/var/lib/dpkg", "/var/lib/snapd", "/var/lib/pam", "/var/cache/apt"}
CONTENT_SCAN_MAX_SIZE = 1024 * 1024
CONTENT_READ_BYTES = 256 * 1024
LARGE_FILE_BYTES = 100 * 1024 * 1024
DISCORD_UPLOAD_LIMIT = 9 * 1024 * 1024
ENV_KEYS = ("SLACK_WEBHOOK_URL", "TEAMS_WEBHOOK_URL", "DISCORD_WEBHOOK_URL", "SLACK_BOT_TOKEN", "SLACK_CHANNEL_ID")

# --------------------------------------------------------------------------- #
# WEBHOOKS + SLACK FILE UPLOAD - paste everything here (no env file needed).
# These are passwords: keep this file private (chmod 600) and never share it or commit it to Git.
# A value that is empty or contains PASTE / XXXX / "..." is treated as "not set".
# --------------------------------------------------------------------------- #
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/T0B5X0AGYJZ/B0CkwYzHFgvEFQx"
TEAMS_WEBHOOK_URL = "https://PASTE-YOUR-TEAMS-WEBHOOK-HERE"
DISCORD_WEBHOOK_URL = "h04116/ctqZ41q6o5v3WC3XPNCrjAhmlCV-XjBOE0YPoEgu_NHXBgGo"
# Needed ONLY to attach PDF / Word / Excel / HTML / CSV files to Slack (webhooks cannot carry files):
SLACK_BOT_TOKEN = "xoxb765444850-uDlVUCfOv8TY2qIghMs3PgXW"        # api.slack.com/apps -> OAuth & Permissions (scope files:write)
SLACK_CHANNEL_ID = "C0CHER"              # channel ID like C0123ABCDEF (not the name); run /invite @YourApp there
CONFIG_URLS = {"slack": SLACK_WEBHOOK_URL, "teams": TEAMS_WEBHOOK_URL, "discord": DISCORD_WEBHOOK_URL}


def cfg(name: str) -> str:
    """Value from the constants above; falls back to an environment variable / env file if the constant is not filled in."""
    v = re.sub(r"\s+", "", str(globals().get(name, "") or "")).strip("'\"")
    if v and not any(x in v.upper() for x in ("PASTE", "XXXX")) and not v.endswith("..."):
        return v
    return os.environ.get(name, "").strip()


ENV_FILES = ["/etc/file_discovery.env", os.path.expanduser("~/.file_discovery.env")]
SLACK_API = "https://slack.com/api"
AUDIT_LOG = "/var/log/audit/audit.log"
AUDIT_KEY = "file_watch"

# Age groups, oldest first: (min days, label, hint, tui 256-colour, discord ansi code, slack emoji, embed colour)
BANDS = [
    (365, "1 year +",     "a year or older",   196, 31, "🟥", 0xE74C3C),
    (180, "6-12 months",  "6 to 12 months",    202, 31, "🟥", 0xE74C3C),
    (90,  "3-6 months",   "3 to 6 months",     208, 33, "🟧", 0xE67E22),
    (30,  "1-3 months",   "1 to 3 months",     220, 33, "🟨", 0xF1C40F),
    (14,  "2-4 weeks",    "2 to 4 weeks",      190, 32, "🟨", 0xF1C40F),
    (7,   "1-2 weeks",    "7 to 13 days",      154, 32, "🟩", 0x2ECC71),
    (3,   "3-6 days",     "3 to 6 days",        82, 36, "🟩", 0x2ECC71),
    (1,   "1-2 days",     "1 to 2 days",        45, 36, "🟦", 0x3498DB),
]
BAND = {b[0]: b for b in BANDS}
RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
RISK_256 = {"CRITICAL": 196, "HIGH": 208, "MEDIUM": 220, "LOW": 78}
RISK_ANSI = {"CRITICAL": 31, "HIGH": 33, "MEDIUM": 33, "LOW": 32}
RISK_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}


# --------------------------------------------------------------------------- #
# DATA MODEL
# --------------------------------------------------------------------------- #
@dataclass
class FileRecord:
    path: str
    directory: str
    name: str
    size: int
    owner: str
    group: str
    perms: str
    age_days: int
    band: int
    modified: str            # last content modification (UTC)
    accessed: str
    changed: str
    created: str             # birth time, "" when the filesystem does not record it
    last_active: str         # newest of the timestamps picked by --age-basis
    category: str
    what: str
    modified_by: str = "unknown"
    sensitive: List[str] = field(default_factory=list)
    risk: str = "LOW"


class ScanStats:
    def __init__(self):
        self.files_seen = self.dirs_seen = self.permission_errors = self.other_errors = self.symlinks = 0
        self.denied: List[str] = []
        self.skipped_dirs: List[str] = []
        self.other_fs: List[str] = []
        self.truncated = False


# --------------------------------------------------------------------------- #
# SMALL HELPERS
# --------------------------------------------------------------------------- #
def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{int(n)} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def human_duration(days: int) -> str:
    plural = lambda n, w: f"{n} {w}" + ("" if n == 1 else "s")          # noqa: E731
    if days < 1:
        return "today"
    if days < 30:
        return plural(days, "day")
    if days < 365:
        mo, d = divmod(days, 30)
        return plural(mo, "month") + (f" {plural(d, 'day')}" if d else "")
    y, rem = divmod(days, 365)
    mo = rem // 30
    return plural(y, "year") + (f" {plural(mo, 'month')}" if mo else "")


def fc(n: int) -> str:
    """Right-aligned '  1,234 files' / '      1 file ' for charts."""
    return f"{n:>7,} file" + ("s" if n != 1 else " ")


def nfiles(n: int) -> str:
    return f"{n:,} file" + ("" if n == 1 else "s")


def tail(s: str, n: int) -> str:
    """Shorten from the LEFT so the file name stays visible: '...dir/file.txt'."""
    return s if len(s) <= n else "…" + s[-(n - 1):]


def head(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n - 1] + "…"


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def vlen(s: str) -> int:
    return len(ANSI_RE.sub("", s))


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


_owner_cache: Dict[int, str] = {}
_group_cache: Dict[int, str] = {}


def owner_name(uid: int) -> str:
    if uid not in _owner_cache:
        try:
            _owner_cache[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            _owner_cache[uid] = str(uid)
    return _owner_cache[uid]


def group_name(gid: int) -> str:
    if gid not in _group_cache:
        try:
            _group_cache[gid] = grp.getgrgid(gid).gr_name
        except KeyError:
            _group_cache[gid] = str(gid)
    return _group_cache[gid]


def load_env_files() -> None:
    """Read KEY=VALUE secrets from env files (only the known keys; real environment wins)."""
    paths = list(ENV_FILES)
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            paths.append(os.path.join(pwd.getpwnam(sudo_user).pw_dir, ".file_discovery.env"))
        except KeyError:
            pass
    for p in paths:
        try:
            if os.stat(p).st_mode & 0o077:
                log.warning("%s is readable by other users - run: chmod 600 %s", p, p)
            with open(p, encoding="utf-8") as fh:
                for line in fh:
                    k, sep, v = line.strip().partition("=")
                    k = k.replace("export ", "").strip()
                    if sep and k in ENV_KEYS and not os.environ.get(k):
                        os.environ[k] = v.strip().strip("'\"")
        except OSError:
            continue


# --------------------------------------------------------------------------- #
# STEP 1 - ENVIRONMENT DETECTION
# --------------------------------------------------------------------------- #
def _http(url: str, method: str = "GET", headers: Optional[dict] = None, timeout: float = 1.0) -> Optional[str]:
    try:
        req = urllib.request.Request(url, method=method, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as resp:      # nosec - fixed link-local URLs
            return resp.read().decode("utf-8", "replace")
    except Exception:
        return None


def detect_cloud() -> str:
    token = _http("http://169.254.169.254/latest/api/token", "PUT", {"X-aws-ec2-metadata-token-ttl-seconds": "60"})
    if token and _http("http://169.254.169.254/latest/meta-data/instance-id", "GET", {"X-aws-ec2-metadata-token": token}):
        return "AWS"
    if _http("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "GET", {"Metadata": "true"}):
        return "Azure"
    if _http("http://metadata.google.internal/computeMetadata/v1/instance/id", "GET", {"Metadata-Flavor": "Google"}):
        return "GCP"
    return "On-Prem"


# --------------------------------------------------------------------------- #
# STEP 2 - SAFE DIRECTORY WALKER
# --------------------------------------------------------------------------- #
def walk_files(root: str, excludes: set, one_fs: bool, seen_dirs: set, stats: ScanStats) -> Iterator[Tuple[str, os.stat_result]]:
    try:
        root_dev = os.lstat(root).st_dev
    except OSError as exc:
        log.warning("Cannot access root %s: %s", root, exc)
        stats.other_errors += 1
        return
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            st = os.lstat(current)
        except OSError:
            stats.other_errors += 1
            continue
        key = (st.st_dev, st.st_ino)
        if key in seen_dirs:
            continue
        seen_dirs.add(key)
        if one_fs and st.st_dev != root_dev:
            if len(stats.other_fs) < 50:
                stats.other_fs.append(current)
            continue
        stats.dirs_seen += 1
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_symlink():
                            stats.symlinks += 1
                        elif entry.is_dir(follow_symlinks=False):
                            if entry.path not in excludes:
                                stack.append(entry.path)
                            elif len(stats.skipped_dirs) < 100:
                                stats.skipped_dirs.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            stats.files_seen += 1
                            yield entry.path, entry.stat(follow_symlinks=False)
                    except PermissionError:
                        stats.permission_errors += 1
                        if len(stats.denied) < 500:
                            stats.denied.append(entry.path)
                    except OSError:
                        stats.other_errors += 1
        except PermissionError:
            stats.permission_errors += 1
            if len(stats.denied) < 500:
                stats.denied.append(current)
        except OSError:
            stats.other_errors += 1


# --------------------------------------------------------------------------- #
# STEP 3 - AGE, CREATION TIME, CLASSIFICATION
# --------------------------------------------------------------------------- #
def band_of(age_days: int, min_age: int) -> Optional[int]:
    if age_days < min_age:
        return None
    for b in BANDS:
        if age_days >= b[0]:
            return b[0]
    return None


AGE_BASIS = {
    "all": lambda st: max(st.st_mtime, st.st_atime, st.st_ctime),
    "access-modify": lambda st: max(st.st_mtime, st.st_atime),
    "modify": lambda st: st.st_mtime,
}


class _StatxTs(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_int64), ("tv_nsec", ctypes.c_uint32), ("_r", ctypes.c_int32)]


class _Statx(ctypes.Structure):
    _fields_ = [("stx_mask", ctypes.c_uint32), ("stx_blksize", ctypes.c_uint32), ("stx_attributes", ctypes.c_uint64),
                ("stx_nlink", ctypes.c_uint32), ("stx_uid", ctypes.c_uint32), ("stx_gid", ctypes.c_uint32),
                ("stx_mode", ctypes.c_uint16), ("_s0", ctypes.c_uint16), ("stx_ino", ctypes.c_uint64),
                ("stx_size", ctypes.c_uint64), ("stx_blocks", ctypes.c_uint64), ("stx_attributes_mask", ctypes.c_uint64),
                ("stx_atime", _StatxTs), ("stx_btime", _StatxTs), ("stx_ctime", _StatxTs), ("stx_mtime", _StatxTs),
                ("stx_rdev_major", ctypes.c_uint32), ("stx_rdev_minor", ctypes.c_uint32),
                ("stx_dev_major", ctypes.c_uint32), ("stx_dev_minor", ctypes.c_uint32), ("_s2", ctypes.c_uint64 * 14)]


try:
    _STATX = ctypes.CDLL(None, use_errno=True).statx
except (OSError, AttributeError):
    _STATX = None


def created_str(path: str) -> str:
    """Birth time via statx(2); '' when the kernel/filesystem does not record it."""
    if _STATX is None:
        return ""
    try:
        buf = _Statx()
        if _STATX(-100, os.fsencode(path), 0x100, 0x800, ctypes.byref(buf)) != 0:
            return ""
        return iso(buf.stx_btime.tv_sec) if (buf.stx_mask & 0x800 and buf.stx_btime.tv_sec > 0) else ""
    except Exception:
        return ""


CLASSIFIERS = [
    ("core_dump", r"(/core(\.\d+)?$|/var/crash/|\.core$)", "Crash dump. Large, may contain secrets from memory. Usually safe to remove."),
    ("log", r"(\.log(\.\d+)?(\.gz)?$|/var/log/)", "Application/system log. Old logs are normally rotated or archived."),
    ("cache_temp", r"(^/tmp/|^/var/tmp/|/var/cache/|/\.cache/|\.tmp$|\.temp$)", "Temporary or cache data. Programs recreate it."),
    ("backup_copy", r"(\.bak$|\.old$|\.orig$|\.backup$|~$|\.swp$|\.save$)", "Manual backup / editor leftover. Check it is not the only copy."),
    ("package_archive", r"(\.deb$|\.rpm$|\.tar$|\.tgz$|\.tar\.(gz|bz2|xz)$|\.zip$|\.7z$|\.iso$)", "Installer or archive download, often a leftover."),
    ("database_dump", r"(\.sql(\.gz)?$|\.dump$|\.sqlite3?$|\.db$|\.bson$)", "Database dump/file. May hold business or personal data."),
    ("build_artifact", r"(/node_modules/|/__pycache__/|\.pyc$|\.o$|/target/|/dist/|/build/)", "Build/dependency output. Can be regenerated."),
    ("media_image", r"(\.mp4$|\.mkv$|\.avi$|\.mov$|\.img$|\.qcow2$|\.vmdk$)", "Large media or disk image. Confirm the owner still needs it."),
    ("config_file", r"(\.conf$|\.cfg$|\.ini$|\.ya?ml$|\.json$|\.toml$)", "Configuration file. A service may still use it even if rarely read."),
]
_CLS = [(c, re.compile(p, re.I), d) for c, p, d in CLASSIFIERS]


def classify(path: str) -> Tuple[str, str]:
    for category, rx, desc in _CLS:
        if rx.search(path):
            return category, desc
    return "other", "General file - no known pattern. Ask the owner whether it is still needed."


# --------------------------------------------------------------------------- #
# STEP 4 - SENSITIVE FILE DETECTION
# --------------------------------------------------------------------------- #
NAME_RULES = [
    ("private_key", ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "*.pem", "*.key", "*.ppk", "*.p12", "*.pfx", "*.jks", "*.keystore"]),
    ("certificate", ["*.crt", "*.cer", "*.der", "*.csr"]),
    ("secrets", [".env", ".env.*", "*.env", "secrets.*", "*.secret", "*.secrets", ".netrc", ".pgpass", ".htpasswd",
                 ".git-credentials", ".npmrc", ".pypirc", ".dockercfg", "credentials", "credentials.*", "terraform.tfstate",
                 "terraform.tfstate.backup", "*.tfvars", "shadow", "gshadow", "*.kdbx", "kubeconfig"]),
    ("password", ["*password*", "*passwd*"]),
    ("token", ["*token*"]),
    ("confidential", ["*confidential*", "*secret*"]),
]
PATH_RULES = [("cloud_credentials", "/.aws/credentials"), ("kubernetes_config", "/.kube/config"),
              ("docker_credentials", "/.docker/config.json"), ("ssh_material", "/.ssh/")]
STRONG_RULES = [
    ("private_key_block", re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY")),
    ("aws_access_key", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("google_api_key", re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("jwt_token", re.compile(rb"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.")),
]
WEAK_RULES = [   # run on the file WITHOUT its comment lines, so "# password=changeme" is not a finding
    ("password_assignment", re.compile(rb"(?i)(?<![A-Za-z])(?:password|passwd|pwd)\s*[=:]\s*(?![\$\{<%\(\s])\S{4,}")),
    ("api_secret_assignment", re.compile(rb"(?i)(?<![A-Za-z])(?:api[_-]?key|secret|token)\s*[=:]\s*['\"]?[A-Za-z0-9_\-/+=]{16,}")),
]
_COMMENT_LINES = re.compile(rb"(?m)^[ \t]*(?:#|;|//).*$")
CONTENT_NAMES = {n for n, _ in STRONG_RULES + WEAK_RULES}
WEAK_NAME_ONLY = {"password", "token", "confidential"}
CODE_EXT = (".py", ".pyi", ".js", ".mjs", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php", ".c", ".h", ".cc",
            ".cpp", ".hpp", ".rs", ".cs", ".pl", ".lua", ".swift", ".kt", ".scala", ".md", ".rst", ".html")
VENDOR_PARTS = ("/site-packages/", "/dist-packages/", "/node_modules/", "/.venv/", "/venv/", "/vendor/", "/.git/",
                "/__pycache__/", "/.cache/", "/.npm/", "/.cargo/", "/.codex/", "/plugins/", "/templates/", "/examples/")


def is_vendor(path: str) -> bool:
    low = path.lower()
    return any(p in low for p in VENDOR_PARTS)


def sensitive_by_name(path: str) -> List[str]:
    found, base, low = set(), os.path.basename(path).lower(), path.lower()
    for label, patterns in NAME_RULES:
        if any(fnmatch.fnmatch(base, p) for p in patterns):
            found.add(label)
    for label, frag in PATH_RULES:
        if frag in low and not (label == "ssh_material" and (base.endswith(".pub") or base == "known_hosts")):
            found.add(label)
    return sorted(found)


def _read_head(path: str, size: int) -> Optional[bytes]:
    if size == 0 or size > CONTENT_SCAN_MAX_SIZE:
        return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        try:
            fd = os.open(path, flags | getattr(os, "O_NOATIME", 0))   # O_NOATIME: our scan must not refresh atime
        except PermissionError:
            fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as fh:
            return fh.read(CONTENT_READ_BYTES)
    except OSError:
        return None


def sensitive_by_content(path: str, size: int) -> List[str]:
    data = _read_head(path, size)
    if not data or b"\x00" in data[:4096]:
        return []
    hits = [n for n, rx in STRONG_RULES if rx.search(data)]
    if not (path.lower().endswith(CODE_EXT) or is_vendor(path)):
        clean = _COMMENT_LINES.sub(b"", data)
        hits += [n for n, rx in WEAK_RULES if rx.search(clean)]
    return hits


def is_public_cert_only(path: str, size: int) -> bool:
    data = _read_head(path, size)
    return bool(data) and b"BEGIN CERTIFICATE" in data and b"PRIVATE KEY" not in data


def risk_level(mode: int, size: int, category: str, sens: List[str], confirmed: bool, vendor: bool) -> str:
    """CRITICAL: sensitive + readable by everybody | HIGH: sensitive | MEDIUM: name-only guess / world-writable / huge."""
    if sens:
        if set(sens) <= ({"certificate"} | WEAK_NAME_ONLY) or (vendor and not confirmed):
            return "MEDIUM"
        if mode & 0o004 or ("private_key" in sens and mode & 0o077):
            return "CRITICAL"
        return "HIGH"
    return "MEDIUM" if (mode & 0o002 or category == "core_dump" or size >= LARGE_FILE_BYTES) else "LOW"


# --------------------------------------------------------------------------- #
# STEP 5 - WHO MODIFIED A FILE  (best effort: auditd)
# --------------------------------------------------------------------------- #
AUDIT_SETUP = f"""
HOW TO MAKE "MODIFIED BY" WORK  (Linux itself never records who edited a file - auditd does)
  1. sudo apt install -y auditd                      # RHEL: sudo dnf install -y audit
  2. Tell auditd which folders to watch (w = write, a = attribute change):
       echo '-w /etc  -p wa -k {AUDIT_KEY}'  | sudo tee    /etc/audit/rules.d/{AUDIT_KEY}.rules
       echo '-w /home -p wa -k {AUDIT_KEY}'  | sudo tee -a /etc/audit/rules.d/{AUDIT_KEY}.rules
       echo '-w /root -p wa -k {AUDIT_KEY}'  | sudo tee -a /etc/audit/rules.d/{AUDIT_KEY}.rules
  3. sudo augenrules --load && sudo systemctl enable --now auditd
  4. Run this script as root again. From now on every edit is recorded with the LOGIN user
     (auid, survives sudo), the program (vim, nano, python ...) and the time.
  Tip: watch only the folders you care about - watching "/" is slow and floods the log.
"""
_AUD_TS = re.compile(r"msg=audit\((\d+)\.\d+:(\d+)\)")


def load_audit_writers(log_path: str, key: str, max_mb: int = 64) -> Tuple[Dict[str, Tuple[float, str]], str]:
    """path -> (time, 'user via program'), parsed from the tail of audit.log. Returns (map, note)."""
    writers: Dict[str, Tuple[float, str]] = {}
    try:
        size = os.path.getsize(log_path)
        fh = open(log_path, "rb")
    except OSError:
        return writers, "no readable audit log (run as root and enable auditd - see --audit-setup)"
    wanted: Dict[str, Tuple[float, str]] = {}
    marker = f'key="{key}"'
    with fh:
        if size > max_mb * 1048576:
            fh.seek(size - max_mb * 1048576)
            fh.readline()
        for raw in fh:
            line = raw.decode("utf-8", "replace")
            m = _AUD_TS.search(line)
            if not m:
                continue
            ts, serial = float(m.group(1)), m.group(2)
            if line.startswith("type=SYSCALL"):
                if marker not in line or "success=yes" not in line:
                    continue
                f = dict(re.findall(r'\b(auid|uid|comm|exe)=("[^"]*"|\S+)', line))
                uid = int(f.get("uid", "0").strip('"') or 0)
                auid = int(f.get("auid", "4294967295").strip('"') or 4294967295)
                comm = f.get("comm", '"?"').strip('"')
                login = owner_name(uid if auid == 4294967295 else auid)
                who = f"{login} via {comm}"
                if auid != 4294967295 and uid != auid:
                    who = f"{login} as {owner_name(uid)} via {comm}"
                wanted[serial] = (ts, who)
            elif line.startswith("type=PATH") and serial in wanted:
                p = re.search(r'name="(/[^"]+)"', line)
                if p and re.search(r"nametype=(NORMAL|CREATE)", line):
                    old = writers.get(p.group(1))
                    if not old or wanted[serial][0] >= old[0]:
                        writers[p.group(1)] = wanted[serial]
            elif line.startswith("type=EOE"):
                wanted.pop(serial, None)
    return writers, f"{len(writers):,} files have an audit trail (rule key '{key}')"


# --------------------------------------------------------------------------- #
# STEP 5b - BUILD ONE INVENTORY ROW
# --------------------------------------------------------------------------- #
def build_record(path: str, st: os.stat_result, now: float, content_scan: bool, basis: str, min_age: int,
                 writers: Dict[str, Tuple[float, str]]) -> Optional[FileRecord]:
    last = AGE_BASIS[basis](st)
    age = int((now - last) // 86400)
    band = band_of(age, min_age)
    if band is None:
        return None
    category, what = classify(path)
    sens = sensitive_by_name(path)
    hits = sensitive_by_content(path, st.st_size) if content_scan else []
    for h in hits:
        if h not in sens:
            sens.append(h)
    if (content_scan and "private_key" in sens and "private_key_block" not in hits
            and path.lower().endswith((".pem", ".key", ".crt")) and is_public_cert_only(path, st.st_size)):
        sens.remove("private_key")
        sens.append("certificate")
    mode = st.st_mode & 0o7777
    w = writers.get(path)
    return FileRecord(
        path=path, directory=os.path.dirname(path), name=os.path.basename(path), size=st.st_size,
        owner=owner_name(st.st_uid), group=group_name(st.st_gid), perms=f"{mode:04o}", age_days=age, band=band,
        modified=iso(st.st_mtime), accessed=iso(st.st_atime), changed=iso(st.st_ctime), created=created_str(path),
        last_active=iso(last), category=category, what=what, modified_by=w[1] if w else "unknown",
        sensitive=sorted(sens), risk=risk_level(mode, st.st_size, category, sens, bool(hits), is_vendor(path)))


# --------------------------------------------------------------------------- #
# REPORT MODEL (everything the TUI / chat / files need, computed once)
# --------------------------------------------------------------------------- #
RULE_TEXT = {
    "private_key": "looks like a private key file", "private_key_block": "contains a private key",
    "aws_access_key": "contains an AWS access key", "github_token": "contains a GitHub token",
    "slack_token": "contains a Slack token", "google_api_key": "contains a Google API key",
    "jwt_token": "contains a login (JWT) token", "password_assignment": "has an active password=... line",
    "api_secret_assignment": "contains an API key / secret value", "secrets": "is a secrets / credentials file",
    "password": "name suggests a password (not confirmed inside)", "token": "name suggests a token (not confirmed inside)",
    "confidential": "name suggests confidential data (not confirmed)", "certificate": "is a certificate (usually fine)",
    "cloud_credentials": "is a cloud credentials file", "kubernetes_config": "is a Kubernetes config (may hold tokens)",
    "docker_credentials": "is a Docker credentials file", "ssh_material": "is SSH key material",
}


def why_sensitive(r: FileRecord) -> str:
    parts: List[str] = []
    for t in sorted(r.sensitive, key=lambda t: (t not in CONTENT_NAMES, t)):
        txt = RULE_TEXT.get(t, t)
        if txt not in parts:
            parts.append(txt)
    mode = int(r.perms, 8)
    access = "EVERY user can read it" if mode & 4 else "its group can read it" if mode & 0o40 else "only its owner can read it"
    return f"{'; '.join(parts[:2])} - {access} (perms {r.perms})"


def coverage(meta: dict, stats: ScanStats, n_records: int):
    skipped = set(stats.skipped_dirs)
    sys_skipped = sorted(d for d in skipped if d in SYSTEM_PATHS)
    user_skipped = sorted(d for d in skipped if d not in SYSTEM_PATHS and d not in DEFAULT_EXCLUDES and d != meta.get("output_dir"))
    items: List[Tuple[str, str]] = [("ok", "Hidden files (names starting with a dot) are included")]
    problems: List[str] = []
    if meta["is_root"]:
        items.append(("ok", "Ran as root - every folder could be read"))
    else:
        problems.append("not run as root")
        items.append(("warn", "NOT root - folders owned by other users were hidden by Linux"))
    if stats.permission_errors:
        problems.append(f"{stats.permission_errors:,} unreadable")
        items.append(("warn", f"{stats.permission_errors:,} folders/files could not be read"))
    if sys_skipped:
        problems.append("system folders skipped")
        items.append(("warn", "System folders skipped on purpose: " + ", ".join(sys_skipped[:6]) + "  (add --include-system-paths)"))
    if stats.other_fs:
        problems.append("other disks not scanned")
        items.append(("warn", "Other disks/mounts not scanned: " + ", ".join(stats.other_fs[:4]) + "  (add --cross-filesystems)"))
    if user_skipped:
        problems.append("folders excluded")
        items.append(("warn", "Folders you excluded: " + ", ".join(user_skipped[:6])))
    if stats.truncated:
        problems.append("record limit hit")
        items.append(("warn", "Stopped early at the record limit (raise --max-records)"))
    items.append(("info", f"Not listed because used less than {meta['min_age']} day(s) ago: {max(0, stats.files_seen - n_records):,} files"))
    items.append(("info", f"Symbolic links skipped: {stats.symlinks:,} (they only point to other files)"))
    items.append(("info", "Audit trail: " + meta["audit_note"]))
    return items, problems


def build_model(meta: dict, recs: List[FileRecord], stats: ScanStats) -> dict:
    by_band: Dict[int, List[FileRecord]] = defaultdict(list)
    for r in recs:
        by_band[r.band].append(r)
    sens = sorted((r for r in recs if r.sensitive), key=lambda r: (RISK_ORDER[r.risk], -r.size))
    n = {k: sum(1 for r in sens if r.risk == k) for k in RISK_ORDER}
    items, problems = coverage(meta, stats, len(recs))
    if n["CRITICAL"]:
        verdict = ("ACTION NEEDED", "crit", f"{n['CRITICAL']} critical sensitive file(s) readable by other users")
    elif n["HIGH"]:
        verdict = ("REVIEW", "warn", f"{n['HIGH']} high-risk sensitive file(s) to check")
    elif n["MEDIUM"]:
        verdict = ("REVIEW", "warn", f"{n['MEDIUM']} possible sensitive file(s) (found by name, not confirmed)")
    else:
        verdict = ("OK", "ok", "no sensitive files found")
    kinds: Dict[str, List] = defaultdict(lambda: [0, 0, ""])
    for r in recs:
        kinds[r.category][0] += 1
        kinds[r.category][1] += r.size
        kinds[r.category][2] = r.what
    return {"meta": meta, "recs": recs, "stats": stats, "by_band": by_band, "sens": sens, "n": n,
            "total": sum(r.size for r in recs), "verdict": verdict, "cov": items, "problems": problems,
            "kinds": sorted(kinds.items(), key=lambda x: -x[1][1])}


def group_dirs(files: List[FileRecord]) -> List[Tuple[str, List[FileRecord]]]:
    g: Dict[str, List[FileRecord]] = defaultdict(list)
    for f in files:
        g[f.directory].append(f)
    return sorted(g.items(), key=lambda x: -sum(f.size for f in x[1]))


def age_rows(M: dict) -> List[dict]:
    rows = []
    for b in BANDS:
        fs = M["by_band"].get(b[0])
        if fs:
            rows.append({"band": b, "files": len(fs), "size": sum(f.size for f in fs)})
    return rows


def timeline_rows(recs: List[FileRecord]) -> List[Tuple[str, int, str]]:
    ts = []
    for r in recs:
        try:
            ts.append((datetime.strptime(r.last_active, "%Y-%m-%d %H:%M:%S"), r))
        except ValueError:
            pass
    if not ts:
        return []
    weekly = (max(t for t, _ in ts) - min(t for t, _ in ts)).days <= 84
    g: Dict[str, List[int]] = defaultdict(lambda: [0, 0])
    for t, r in ts:
        k = (t - timedelta(days=t.weekday())).strftime("%Y-%m-%d") if weekly else t.strftime("%Y-%m")
        g[k][0] += 1
        g[k][1] += r.size
    rows = []
    for k in sorted(g)[-12:]:
        label = "week of " + datetime.strptime(k, "%Y-%m-%d").strftime("%b %d") if weekly else k
        rows.append((label, g[k][0], f"{fc(g[k][0])} {human(g[k][1]):>9}"))
    return rows


def folder_rows(recs: List[FileRecord], n: int = 8) -> List[Tuple[str, int, str]]:
    return [(d, sum(f.size for f in fs), f"{fc(len(fs))} {human(sum(f.size for f in fs)):>9}")
            for d, fs in group_dirs(recs)[:n]]


def type_rows(M: dict) -> List[Tuple[str, int, str]]:
    return [(c, sz, f"{fc(n)} {human(sz):>9}") for c, (n, sz, _) in M["kinds"][:8]]


def next_steps(M: dict) -> List[str]:
    steps = []
    if M["n"]["CRITICAL"] or M["n"]["HIGH"]:
        steps.append("Fix CRITICAL and HIGH files first: chmod 600 keys / password files, or move the secrets to a secrets manager.")
    old = [r for r in M["recs"] if r.age_days >= 30 and r.size >= 10 * 1048576]
    if old:
        big = max(old, key=lambda r: r.size)
        steps.append(f"Review the biggest old files - they free the most space (largest: {big.path}, {human(big.size)}).")
    if M["problems"]:
        steps.append(f"For a complete scan run: sudo ./{os.path.basename(sys.argv[0])} --full")
    if M["meta"]["audit_count"] == 0:
        steps.append("Enable auditd (run with --audit-setup) so the MODIFIED BY column can show who edited each file.")
    steps.append("Open the Excel / HTML report to filter, sort and share the complete file list.")
    return steps


# --------------------------------------------------------------------------- #
# TERMINAL UI  (colour, aligned columns, fits the terminal width)
# --------------------------------------------------------------------------- #
class Sty:
    """Tiny ANSI helper. Disabled -> returns plain text, so the same renderer also writes the .txt report."""
    def __init__(self, on: bool):
        self.on = on

    def __call__(self, text: str, fg: Optional[int] = None, bold: bool = False, dim: bool = False, bg: Optional[int] = None) -> str:
        if not self.on:
            return text
        codes = (["1"] if bold else []) + (["2"] if dim else []) + ([f"38;5;{fg}"] if fg is not None else []) + \
                ([f"48;5;{bg}"] if bg is not None else [])
        return f"\033[{';'.join(codes)}m{text}\033[0m" if codes else text


def C(text, **kw):
    return (str(text), kw)


def cell(S: Sty, spec, width: int, align: str = "l") -> str:
    text, kw = spec if isinstance(spec, tuple) else (str(spec), {})
    text = tail(text, width) if kw.get("tail") else head(text, width)
    text = text.ljust(width) if align == "l" else text.rjust(width)
    return S(text, fg=kw.get("fg"), bold=kw.get("bold", False), dim=kw.get("dim", False))


def table(S: Sty, cols: List[Tuple[str, int, str]], rows: List[list], indent: int = 2) -> List[str]:
    pad = " " * indent
    out = [pad + " ".join(S(h.ljust(w) if a == "l" else h.rjust(w), fg=245, bold=True) for h, w, a in cols),
           pad + S(" ".join("─" * w for _, w, _ in cols), fg=238)]
    for row in rows:
        out.append(pad + " ".join(cell(S, v, w, a) for v, (_, w, a) in zip(row, cols)))
    return out


def pill(S: Sty, risk: str) -> str:
    return S(f" {risk:^8} ", fg=16, bg=RISK_256[risk], bold=True) if S.on else f"[{risk}]".center(10)


def bar(S: Sty, frac: float, width: int, fg: int) -> str:
    if frac <= 0:
        return S("░" * width, fg=237)
    eighths = max(1, round(frac * width * 8))
    full, rem = divmod(eighths, 8)
    s = "█" * full + ("▏▎▍▌▋▊▉"[rem - 1] if rem else "")
    return S(s, fg=fg) + S("░" * (width - len(s)), fg=237)


def file_columns(W: int) -> List[Tuple[str, str, int, str]]:
    """Which columns fit: (key, header, width, align). The last (file) column takes the rest."""
    cols = [("mod", "LAST MODIFIED", 16, "l"), ("act", "LAST ACTIVITY", 16, "l"), ("by", "MODIFIED BY", 18, "l"),
            ("owner", "OWNER", 8, "l"), ("perm", "PERM", 4, "l"), ("size", "SIZE", 9, "r"),
            ("age", "UNUSED", 17, "l"), ("type", "TYPE", 13, "l")]
    drop = {"type"} if W < 165 else set()
    if W < 145:
        drop |= {"age", "perm"}
    if W < 120:
        drop |= {"by", "owner"}
    if W < 100:
        drop |= {"mod"}
    return [c for c in cols if c[0] not in drop]


def file_row(r: FileRecord, keys: List[str], show_path: bool = True) -> list:
    known = r.modified_by != "unknown"
    vals = {"mod": C(r.modified[:16], fg=183), "act": C(r.last_active[:16], fg=153),
            "by": C(r.modified_by, fg=117 if known else 240, dim=not known),
            "owner": C(r.owner, fg=250), "perm": C(r.perms, fg=245), "size": C(human(r.size), fg=255, bold=True),
            "age": C(human_duration(r.age_days), fg=245), "type": C(r.category, fg=140),
            "file": C(r.path if show_path else r.name, tail=True, fg=RISK_256[r.risk] if r.sensitive else 252,
                      bold=bool(r.sensitive))}
    return [vals[k] for k in keys]


def render_tui(M: dict, S: Sty, W: int, per_band: Optional[int], attn_n: Optional[int] = None) -> str:
    meta, recs, L = M["meta"], M["recs"], []
    add = L.append
    inner = W - 2
    word, level, detail = M["verdict"]
    lvl_fg = {"crit": 196, "warn": 214, "ok": 78}[level]

    def boxline(left: str, right: str = "") -> None:
        add(S("║", fg=39) + " " + left + " " * max(1, inner - 2 - vlen(left) - vlen(right)) + right + " " + S("║", fg=39))

    def section(num: int, title: str, sub: str = "") -> None:
        add("")
        add(S(f" {num} ", fg=16, bg=39, bold=True) + " " + S(title, fg=255, bold=True) + ("   " + S(sub, fg=244) if sub else ""))
        add(S("─" * W, fg=238))

    add(S("╔" + "═" * inner + "╗", fg=39))
    boxline(S("LINUX FILE CLEANUP REPORT", fg=51, bold=True) + S(f"  v{VERSION}", fg=244),
            S("report only · nothing was deleted, moved or changed", fg=244))
    boxline(S(meta["server"], fg=255, bold=True) + S(f"  ·  {meta['cloud']}  ·  {meta['generated_at']} UTC  ·  {meta['run_as']}", fg=250),
            S(f"scanned {meta['files_seen']:,} files in {meta['duration_s']}s", fg=244))
    add(S("╚" + "═" * inner + "╝", fg=39))
    add(" " + S(f" {word} ", fg=16, bg=lvl_fg, bold=True) + "  " + S(detail, fg=lvl_fg, bold=True))
    add("")

    # KPI cards
    n = M["n"]
    scan_ok = not M["problems"]
    cards = [("UNUSED FILES", f"{len(recs):,}", f"older than {meta['min_age']} day(s)", 51),
             ("TOTAL SIZE", human(M["total"]), "can be reviewed", 183),
             ("SENSITIVE", f"{len(M['sens']):,}", f"{n['HIGH']} high · {n['MEDIUM']} medium", 214),
             ("CRITICAL", f"{n['CRITICAL']:,}", "readable by everyone", 196 if n["CRITICAL"] else 78),
             ("SCAN", "COMPLETE" if scan_ok else "PARTIAL", "all readable disks" if scan_ok else "see section 7", 78 if scan_ok else 214)]
    cw = (W - (len(cards) - 1)) // len(cards)
    ci = cw - 2
    ctr = lambda t, fg, bold=False: " " * ((ci - len(t)) // 2) + S(t, fg=fg, bold=bold) + " " * (ci - len(t) - (ci - len(t)) // 2)  # noqa: E731
    for row in range(5):
        parts = []
        for lab, val, sub, fg in cards:
            if row == 0:
                parts.append(S("┌" + "─" * ci + "┐", fg=238))
            elif row == 4:
                parts.append(S("└" + "─" * ci + "┘", fg=238))
            else:
                body = (ctr(lab, 245), ctr(val, fg, True), ctr(sub, 240))[row - 1]
                parts.append(S("│", fg=238) + body + S("│", fg=238))
        add(" ".join(parts))
    if M["problems"]:
        add(S("  Why partial: " + "; ".join(M["problems"]) + "   (use --full as root for a complete scan)", fg=214))

    # 1 attention
    section(1, "NEEDS ATTENTION FIRST", "sensitive files: keys, passwords, tokens, credentials")
    if not M["sens"]:
        add("  " + S("● No sensitive files found.", fg=78))
    else:
        shown = M["sens"] if not attn_n else M["sens"][:attn_n]
        wmod, wby, wown = 16, 20, 8
        pw = W - 2 - (10 + wmod + wby + wown + 4 * 1 + 5 + 1)
        add("  " + " ".join(S(h, fg=245, bold=True) for h in
                            ("RISK".ljust(10), "LAST MODIFIED".ljust(wmod), "MODIFIED BY".ljust(wby), "OWNER".ljust(wown), "PERM ", "FILE")))
        add("  " + S("─" * (W - 2), fg=238))
        for r in shown:
            known = r.modified_by != "unknown"
            add("  " + " ".join([pill(S, r.risk), S(r.modified[:16].ljust(wmod), fg=183),
                                 S(head(r.modified_by, wby).ljust(wby), fg=117 if known else 240),
                                 S(head(r.owner, wown).ljust(wown), fg=250), S(r.perms.ljust(5), fg=245),
                                 S(tail(r.path, max(20, pw)), fg=RISK_256[r.risk], bold=True)]))
            add("  " + " " * 10 + " " + S("↳ " + head(why_sensitive(r), W - 16), fg=244))
        if len(shown) < len(M["sens"]):
            add(S(f"  … and {len(M['sens']) - len(shown):,} more sensitive files - they are all in the saved reports.", fg=244))
        add(S("  Tip: keys and password files should be chmod 600. This tool only reports - it never changes permissions.", fg=240))

    # 2 where is the space
    def chart(title: str, rows: List[Tuple[str, float, str, int]]) -> None:
        if not rows:
            return
        add("")
        add("  " + S(title, fg=111, bold=True))
        vmax = max([v for _, v, _, _ in rows] + [1])
        lw = min(34, max(len(r[0]) for r in rows))
        bw = max(12, min(36, W - lw - 40))
        for label, val, right, fg in rows:
            add("  " + S(tail(label, lw).ljust(lw), fg=252) + " " + bar(S, val / vmax, bw, fg) + "  " + S(right, fg=250))

    section(2, "WHERE IS THE SPACE?")
    total = max(1, M["total"])
    chart("2a  How long have files been unused?   (bar = size)",
          [(b["band"][1], b["size"], f"{fc(b['files'])} {human(b['size']):>9} {b['size'] * 100 // total:>3}%", b["band"][3])
           for b in age_rows(M)])
    srows = []
    for b in BANDS:
        fs = M["by_band"].get(b[0])
        if fs:
            srows.append([C(b[1], fg=b[3], bold=True), C(f"{len(fs):,}"), C(human(sum(f.size for f in fs)), bold=True),
                          C(f"{sum(f.size for f in fs) * 100 // total}%"),
                          C(min(f.last_active for f in fs)[:16], fg=153), C(max(f.last_active for f in fs)[:16], fg=153)])
    if srows:
        add("")
        L.extend(table(S, [("AGE GROUP", 12, "l"), ("FILES", 9, "r"), ("SIZE", 10, "r"), ("SHARE", 6, "r"),
                           ("OLDEST ACTIVITY", 16, "l"), ("NEWEST ACTIVITY", 16, "l")], srows))
    tl = timeline_rows(recs)
    if tl:
        chart("2b  When were files last active?   (bar = number of files)", [(a, b, c, 75) for a, b, c in tl])
    fr = folder_rows(recs)
    if fr:
        chart("2c  Biggest folders of unused files   (bar = size)", [(a, b, c, 141) for a, b, c in fr])
    ty = type_rows(M)
    if ty:
        chart("2d  What kinds of files?   (bar = size)", [(a, b, c, 176) for a, b, c in ty])

    # 3 biggest files
    section(3, "BIGGEST UNUSED FILES", "free these first")
    cols = file_columns(W)
    keys = [c[0] for c in cols] + ["file"]
    fixed = sum(c[2] for c in cols) + len(cols)
    tcols = [(c[1], c[2], c[3]) for c in cols] + [("FILE", max(20, W - 2 - fixed), "l")]
    add("")
    L.extend(table(S, tcols, [file_row(r, keys) for r in sorted(recs, key=lambda x: -x.size)[:10]]))

    # 4 files by age
    section(4, "FILES BY AGE", "oldest first · largest files of each group" + ("" if per_band is None else f" · top {per_band}"))
    for b in BANDS:
        fs = M["by_band"].get(b[0])
        if not fs:
            continue
        add("")
        add("  " + S("■ ", fg=b[3]) + S(f"UNUSED {b[1].upper()}", fg=b[3], bold=True) +
            S(f"   {nfiles(len(fs))} · {human(sum(f.size for f in fs))} · {b[2]}", fg=244))
        top = ", ".join(f"{tail(d, 46)} ({len(x):,}, {human(sum(f.size for f in x))})" for d, x in group_dirs(fs)[:2])
        add("  " + S("  main folders: ", fg=240) + S(head(top, W - 20), fg=245))
        ordered = sorted(fs, key=lambda x: -x.size)
        sel = ordered if per_band is None else ordered[:per_band]
        L.extend(table(S, tcols, [file_row(r, keys) for r in sel]))
        if len(sel) < len(fs):
            add(S(f"    … and {len(fs) - len(sel):,} more files in this group - see the Excel / HTML report.", fg=244))

    # 5 file types
    section(5, "WHAT KINDS OF FILES ARE THESE?")
    for cat, (cnt, sz, desc) in M["kinds"]:
        add("  " + S(cat.ljust(16), fg=176, bold=True) + S(f"{cnt:>8,} files {human(sz):>10}", fg=250) + "  " + S(head(desc, W - 44), fg=244))

    # 6 modified-by
    known = sum(1 for r in recs if r.modified_by != "unknown")
    section(6, "WHO MODIFIED THE FILES?")
    add("  " + S(f"{known:,} of {len(recs):,} files have a known editor.", fg=117 if known else 214, bold=True))
    add(S("  Linux never stores who edited a file - only the OWNER and times. The editor comes from auditd.", fg=244))
    add(S(f"  Enable it:  sudo ./{os.path.basename(sys.argv[0])} --audit-setup", fg=244))

    # 7 coverage
    section(7, "HOW COMPLETE IS THIS SCAN?")
    for lv, text in M["cov"]:
        sym, fg = {"ok": ("●", 78), "warn": ("▲", 214), "info": ("·", 244)}[lv]
        add("  " + S(sym, fg=fg) + " " + S(head(text, W - 6), fg=250))
    add("  " + S("RESULT: ", fg=255, bold=True) + (S("COMPLETE", fg=78, bold=True) if not M["problems"] else S("PARTIAL", fg=214, bold=True)))

    # 8 next steps
    section(8, "WHAT TO DO NEXT")
    for i, step in enumerate(next_steps(M), 1):
        add("  " + S(f"{i}.", fg=39, bold=True) + " " + head(step, W - 6))
    add("")
    return "\n".join(L)


def render_footer(M: dict, S: Sty, W: int, saved: Dict[str, str], results: Dict[str, str]) -> str:
    L = [S("═" * W, fg=39), S(" RUN COMPLETE", fg=51, bold=True)]
    if saved:
        L.append(S(f" REPORT FILES   {os.path.dirname(next(iter(saved.values())))}   (owner-only permissions)", fg=250))
        for fmt, p in saved.items():
            L.append("   " + S(fmt.upper().ljust(6), fg=111, bold=True) + S(human(os.path.getsize(p)).rjust(9), fg=250) + "  " + S(os.path.basename(p), fg=244))
    L.append(S(" CHAT", fg=250))
    if not results:
        L.append(S("   nothing sent (fill in the webhook URLs near the top of this script)", fg=244))
    for ch, res in results.items():
        bad = res.startswith("FAILED")
        warn = res.startswith("skipped")
        L.append("   " + S(ch.ljust(14), fg=255, bold=True) + S(res, fg=196 if bad else 214 if warn else 78))
    L.append(S("═" * W, fg=39))
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# FILE EXPORTS: CSV, JSON, HTML, XLSX
# --------------------------------------------------------------------------- #
def open_secure(path: str, mode: str = "w"):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    return os.fdopen(fd, mode) if "b" in mode else os.fdopen(fd, mode, encoding="utf-8", newline="")


HEADERS = ["Age group", "Risk", "Directory", "File name", "Size (bytes)", "Size", "Last modified", "Modified by", "Owner",
           "Group", "Permissions", "Created", "Last accessed", "Last changed", "Last active", "Unused (days)", "Unused for",
           "Type", "What it is", "Sensitive matches", "Full path"]


def file_values(r: FileRecord) -> list:
    return [BAND[r.band][1], r.risk if r.sensitive else "", r.directory, r.name, r.size, human(r.size), r.modified,
            r.modified_by, r.owner, r.group, r.perms, r.created or "n/a", r.accessed, r.changed, r.last_active,
            r.age_days, human_duration(r.age_days), r.category, r.what, ", ".join(r.sensitive), r.path]


def sorted_records(M: dict) -> List[FileRecord]:
    order = {b[0]: i for i, b in enumerate(BANDS)}
    return sorted(M["recs"], key=lambda r: (order[r.band], -r.size))


def export_csv(path: str, M: dict) -> None:
    with open_secure(path) as fh:
        fh.write("\ufeff")
        w = csv.writer(fh)
        w.writerow(HEADERS)
        for r in sorted_records(M):
            w.writerow([("'" + v) if isinstance(v, str) and v[:1] in "=+-@" and v else v for v in file_values(r)])


def export_json(path: str, M: dict) -> None:
    with open_secure(path) as fh:
        json.dump({"meta": M["meta"], "files": [asdict(r) for r in M["recs"]]}, fh, indent=1)


HTML_CSS = """:root{--bg:#f4f6fa;--card:#fff;--ink:#1d2433;--mute:#667085;--line:#e3e8ef;--head:#1f4e79;--c:#fde2e2;--cf:#b42318;--h:#ffe9d2;--hf:#b54708;--m:#fff6d6;--mf:#8a6a00;--l:#e6f4ea;--lf:#2e7d32}
@media(prefers-color-scheme:dark){:root{--bg:#0f141b;--card:#18202b;--ink:#e6eaf2;--mute:#97a3b6;--line:#2b3646;--c:#4a2020;--cf:#ffb4ab;--h:#4a3217;--hf:#ffc78f;--m:#463d14;--mf:#ffe08a;--l:#173a22;--lf:#9ad9a8}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,"Segoe UI",Roboto,Arial,sans-serif}
.w{max-width:1280px;margin:0 auto;padding:22px 14px 60px}.band{background:linear-gradient(135deg,#1f4e79,#2a77b5);color:#fff;border-radius:14px;padding:20px 24px}
.band h1{margin:0 0 4px;font-size:22px}.band p{margin:0;opacity:.85}.g{display:grid;gap:12px;margin:16px 0;grid-template-columns:repeat(auto-fit,minmax(170px,1fr))}
.k{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}.k b{display:block;color:var(--mute);font-size:11.5px;text-transform:uppercase;letter-spacing:.05em}
.k span{font-size:24px;font-weight:700}h2{font-size:17px;margin:28px 0 10px}table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line)}
th,td{padding:7px 11px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}th{background:var(--head);color:#fff;font-size:12px;cursor:pointer;position:sticky;top:0}
.n{text-align:right;white-space:nowrap}.p{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;word-break:break-all}
.b{display:inline-block;padding:1px 9px;border-radius:99px;font-size:11.5px;font-weight:700}.CRITICAL{background:var(--c);color:var(--cf)}.HIGH{background:var(--h);color:var(--hf)}
.MEDIUM{background:var(--m);color:var(--mf)}.LOW{background:var(--l);color:var(--lf)}.bar{height:9px;border-radius:5px;min-width:2px}
details{margin:10px 0}summary{cursor:pointer;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px;font-weight:600}
.s{display:flex;gap:10px;margin:8px 0}.s input,.s select{padding:9px 12px;border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--ink)}.s input{flex:1}
.note{color:var(--mute);font-size:12.5px}.mute{color:var(--mute)}@media print{details{display:block}.s{display:none}}"""
BAND_HEX = {196: "#e74c3c", 202: "#e67e22", 208: "#f08c2e", 220: "#f1c40f", 190: "#c7d32a", 154: "#8fd14f", 82: "#2ecc71", 45: "#3498db"}


def export_html(path: str, M: dict) -> None:
    meta, e = M["meta"], htmllib.escape
    h = [f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
         f"<title>File Cleanup Report - {e(meta['server'])}</title><style>{HTML_CSS}</style></head><body><div class=w>",
         f"<div class=band><h1>📋 Linux File Cleanup Report</h1><p>Report only - nothing was deleted · {e(meta['server'])} · {e(meta['cloud'])} · "
         f"{e(meta['generated_at'])} UTC · {e(meta['run_as'])}</p></div><div class=g>"]
    for k, v in (("Status", M["verdict"][0]), ("Unused files", f"{len(M['recs']):,}"), ("Total size", human(M["total"])),
                 ("Sensitive", f"{len(M['sens']):,}"), ("🔴 Critical", M["n"]["CRITICAL"]), ("🟠 High", M["n"]["HIGH"]),
                 ("🟡 Medium", M["n"]["MEDIUM"])):
        h.append(f"<div class=k><b>{k}</b><span>{v}</span></div>")
    h.append(f"</div><p class=note>{e(M['verdict'][2])}. Editors come from auditd: {e(meta['audit_note'])}.</p>")
    h.append("<h2>How long have files been unused?</h2><table><tr><th>Age group</th><th class=n>Files</th><th class=n>Size</th><th>Oldest activity</th><th>Newest activity</th><th style='width:30%'>Share of size</th></tr>")
    vmax = max([r["size"] for r in age_rows(M)] + [1])
    for r in age_rows(M):
        b = r["band"]
        fs = M["by_band"][b[0]]
        h.append(f"<tr><td><b>{e(b[1])}</b> <span class=mute>({e(b[2])})</span></td><td class=n>{r['files']:,}</td><td class=n>{human(r['size'])}</td>"
                 f"<td>{e(min(f.last_active for f in fs)[:16])}</td><td>{e(max(f.last_active for f in fs)[:16])}</td>"
                 f"<td><div class=bar style='width:{max(1, r['size'] * 100 // vmax)}%;background:{BAND_HEX[b[3]]}'></div></td></tr>")
    h.append("</table><h2>🔴 Needs attention first</h2>")
    if not M["sens"]:
        h.append("<p>✅ No sensitive files found.</p>")
    else:
        h.append("<table><tr><th>Risk</th><th>File</th><th>Why</th><th>Last modified</th><th>Last activity</th><th>Modified by</th><th>Owner</th></tr>")
        for r in M["sens"]:
            h.append(f"<tr><td><span class='b {r.risk}'>{r.risk}</span></td><td class=p>{e(r.path)}</td><td>{e(why_sensitive(r))}</td>"
                     f"<td>{e(r.modified[:16])}</td><td>{e(r.last_active[:16])}</td><td>{e(r.modified_by)}</td><td>{e(r.owner)}</td></tr>")
        h.append("</table>")
    h.append("<h2>Every file</h2><div class=s><input id=q placeholder='Search path, owner, editor...' oninput=f()>"
             "<select id=r onchange=f()><option value=''>All risks</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option></select></div>")
    for b in BANDS:
        fs = M["by_band"].get(b[0])
        if not fs:
            continue
        h.append(f"<details{' open' if b[0] >= 90 else ''}><summary>■ Unused {e(b[1])} - {nfiles(len(fs))}, {human(sum(f.size for f in fs))}</summary>"
                 "<table class=t><tr><th>File</th><th>Last modified</th><th>Last activity</th><th>Modified by</th><th>Owner</th><th>Perms</th><th class=n>Size</th>"
                 "<th>Created</th><th class=n>Unused</th><th>Type</th><th>Risk</th></tr>")
        for r in sorted(fs, key=lambda x: -x.size):
            risk = f"<span class='b {r.risk}'>{r.risk}</span>" if r.sensitive else ""
            h.append(f"<tr class=f data-r='{r.risk if r.sensitive else ''}'><td class=p>{e(r.path)}</td><td>{e(r.modified[:16])}</td><td>{e(r.last_active[:16])}</td><td>{e(r.modified_by)}</td>"
                     f"<td>{e(r.owner)}</td><td>{r.perms}</td><td class=n>{human(r.size)}</td><td>{e(r.created[:10] or 'n/a')}</td>"
                     f"<td class=n>{e(human_duration(r.age_days))}</td><td>{e(r.category)}</td><td>{risk}</td></tr>")
        h.append("</table></details>")
    sym = {"ok": "✅", "warn": "⚠️", "info": "•"}
    h.append("<h2>Scan coverage</h2><ul>" + "".join(f"<li>{sym[lv]} {e(t)}</li>" for lv, t in M["cov"]) + "</ul>")
    h.append("<script>function f(){var q=document.getElementById('q').value.toLowerCase(),r=document.getElementById('r').value;"
             "document.querySelectorAll('tr.f').forEach(function(x){x.style.display=(x.textContent.toLowerCase().indexOf(q)<0||(r&&x.dataset.r!==r))?'none':''})}"
             "document.querySelectorAll('table.t').forEach(function(t){t.querySelectorAll('th').forEach(function(th,i){th.onclick=function(){"
             "var rows=[].slice.call(t.querySelectorAll('tr.f')),d=th.dataset.d=th.dataset.d=='1'?-1:1;rows.sort(function(a,b){return d*a.children[i].textContent.localeCompare(b.children[i].textContent,undefined,{numeric:true})});"
             "rows.forEach(function(x){t.appendChild(x)})}})})</script></div></body></html>")
    with open_secure(path) as fh:
        fh.write("".join(h))


def _col(n: int) -> str:
    s = ""
    while n:
        n, rem = divmod(n - 1, 26)
        s = chr(65 + rem) + s
    return s


_XML_BAD = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")
XS_HEAD, XS_CRIT, XS_HIGH, XS_MED, XS_LOW, XS_TITLE, XS_BOLD, XS_INT = 1, 2, 3, 4, 5, 6, 7, 8
XS_RISK = {"CRITICAL": XS_CRIT, "HIGH": XS_HIGH, "MEDIUM": XS_MED, "LOW": XS_LOW}
XLSX_STYLES = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
               '<fonts count="4"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>'
               '<font><b/><sz val="16"/><color rgb="FF1F4E79"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
               '<fills count="7"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill>'
               + "".join(f'<fill><patternFill patternType="solid"><fgColor rgb="{c}"/><bgColor indexed="64"/></patternFill></fill>'
                         for c in ("FF1F4E79", "FFFFC7CE", "FFFFE0B2", "FFFFF2CC", "FFE2EFDA")) +
               '</fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
               '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="9">'
               '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
               '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>'
               + "".join(f'<xf numFmtId="0" fontId="3" fillId="{i}" borderId="0" xfId="0" applyFont="1" applyFill="1"/>' for i in (3, 4, 5, 6)) +
               '<xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1"/>'
               '<xf numFmtId="0" fontId="3" fillId="0" borderId="0" xfId="0" applyFont="1"/>'
               '<xf numFmtId="3" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/></cellXfs>'
               '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>')


def _xl_cell(ref: str, value, style: int) -> str:
    if value is None or value == "":
        return f'<c r="{ref}" s="{style}"/>' if style else ""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f'<c r="{ref}" s="{style}"><v>{value}</v></c>'
    return f'<c r="{ref}" s="{style}" t="inlineStr"><is><t xml:space="preserve">{htmllib.escape(_XML_BAD.sub("", str(value)), quote=False)}</t></is></c>'


def _xl_sheet(zf, name: str, rows, widths: List[int], filt: bool) -> None:
    with zf.open(name, "w") as out:
        w = lambda s: out.write(s.encode("utf-8"))      # noqa: E731
        w('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">')
        if filt:
            w('<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>')
        w("<cols>" + "".join(f'<col min="{i}" max="{i}" width="{x}" customWidth="1"/>' for i, x in enumerate(widths, 1)) + "</cols><sheetData>")
        n = 0
        for n, row in enumerate(rows, 1):
            w(f'<row r="{n}">' + "".join(_xl_cell(f"{_col(c)}{n}", v, s) for c, (v, s) in enumerate(row, 1)) + "</row>")
        w("</sheetData>")
        if filt and n > 1:
            w(f'<autoFilter ref="A1:{_col(len(widths))}{n}"/>')
        w("</worksheet>")


def export_xlsx(path: str, M: dict) -> None:
    meta = M["meta"]
    Hd = lambda *names: [(x, XS_HEAD) for x in names]      # noqa: E731

    def summary():
        yield [("Linux File Cleanup Report", XS_TITLE)]
        yield [("Report only - nothing was deleted, moved or changed", 0)]
        yield []
        for k, v in (("Server", meta["server"]), ("Cloud", meta["cloud"]), ("Run at (UTC)", meta["generated_at"]), ("Run as", meta["run_as"]),
                     ("Status", f"{M['verdict'][0]} - {M['verdict'][2]}"), ("Unused files", len(M["recs"])), ("Total size", human(M["total"])),
                     ("Sensitive files", len(M["sens"])), ("Critical", M["n"]["CRITICAL"]), ("High", M["n"]["HIGH"]), ("Medium", M["n"]["MEDIUM"]),
                     ("Audit trail", meta["audit_note"])):
            yield [(k, XS_BOLD), (v, XS_INT if isinstance(v, int) else 0)]
        yield []
        yield Hd("Age group", "Files", "Size", "Meaning", "Oldest activity", "Newest activity")
        for r in age_rows(M):
            fs = M["by_band"][r["band"][0]]
            yield [(r["band"][1], XS_BOLD), (r["files"], XS_INT), (human(r["size"]), 0), (r["band"][2], 0),
                   (min(f.last_active for f in fs), 0), (max(f.last_active for f in fs), 0)]
        yield []
        yield Hd("Coverage", "Detail")
        for lv, t in M["cov"]:
            yield [({"ok": "OK", "warn": "WARNING", "info": "Note"}[lv], 0), (t, 0)]

    def attention():
        yield Hd("Risk", "File", "Why", "Last modified", "Last activity", "Modified by", "Owner", "Perms", "Size")
        for r in M["sens"]:
            yield [(r.risk, XS_RISK[r.risk]), (r.path, 0), (why_sensitive(r), 0), (r.modified, 0), (r.last_active, 0),
                   (r.modified_by, 0), (r.owner, 0), (r.perms, 0), (human(r.size), 0)]

    def all_files():
        yield Hd(*HEADERS)
        for r in sorted_records(M):
            v = file_values(r)
            row = [(x, 0) for x in v]
            row[4], row[15] = (v[4], XS_INT), (v[15], XS_INT)
            if r.sensitive:
                row[1] = (v[1], XS_RISK[r.risk])
            yield row

    def folders():
        yield Hd("Directory", "Files", "Size (bytes)", "Size", "Oldest unused (days)")
        for d, fs in group_dirs(M["recs"]):
            tot = sum(f.size for f in fs)
            yield [(d, 0), (len(fs), XS_INT), (tot, XS_INT), (human(tot), 0), (max(f.age_days for f in fs), XS_INT)]

    sheets = [("Summary", summary(), [26, 60, 14, 40, 19, 19], False),
              ("Needs Attention", attention(), [11, 60, 60, 19, 19, 24, 10, 8, 11], True),
              ("All Files", all_files(), [14, 10, 36, 28, 13, 10, 19, 24, 10, 10, 8, 19, 19, 19, 19, 10, 14, 14, 40, 24, 60], True),
              ("By Folder", folders(), [60, 9, 16, 11, 18], True)]
    ct = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
          '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>']
    wbs, rels = [], []
    with open_secure(path, "wb") as fh, zipfile.ZipFile(fh, "w", zipfile.ZIP_DEFLATED) as zf:
        for i, (name, rows, widths, filt) in enumerate(sheets, 1):
            _xl_sheet(zf, f"xl/worksheets/sheet{i}.xml", rows, widths, filt)
            ct.append(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>')
            wbs.append(f'<sheet name="{name}" sheetId="{i}" r:id="rId{i}"/>')
            rels.append(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>')
        rels.append(f'<Relationship Id="rId{len(sheets) + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>')
        zf.writestr("[Content_Types].xml", "".join(ct) + "</Types>")
        zf.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        zf.writestr("xl/workbook.xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>' + "".join(wbs) + "</sheets></workbook>")
        zf.writestr("xl/_rels/workbook.xml.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                    + "".join(rels) + "</Relationships>")
        zf.writestr("xl/styles.xml", XLSX_STYLES)


# --------------------------------------------------------------------------- #
# DOCUMENT REPORTS: PDF + WORD (.docx) - standard library only, same story as the TUI / HTML / Excel
# --------------------------------------------------------------------------- #
DOC_OPTS = {"files": 0}              # files listed per age group in PDF / Word (0 = ALL). Sensitive files are always all listed.
D_INK, D_MUTE, D_BLUE, D_LINE, D_ZEBRA = "#1D2433", "#667085", "#1F4E79", "#E3E8EF", "#F6F8FB"
D_RISK = {"CRITICAL": ("#FDE2E2", "#B42318"), "HIGH": ("#FFE9D2", "#B54708"),
          "MEDIUM": ("#FFF6D6", "#8A6A00"), "LOW": ("#E6F4EA", "#2E7D32")}
D_LEVEL = {"crit": "#B42318", "warn": "#B54708", "ok": "#2E7D32"}
D_ASCII = {"…": "...", "·": "|", "—": "-", "–": "-", "↳": ">", "■": "#"}


def Cx(text, **kw) -> dict:
    """Table cell with style: fill, color, bold, mono."""
    return {"t": str(text), **kw}


def _dcell(c) -> dict:
    return c if isinstance(c, dict) else {"t": str(c)}


def _dclean(s) -> str:
    s = str(s).replace("\n", " ").replace("\t", " ")
    for k, v in D_ASCII.items():
        s = s.replace(k, v)
    return re.sub(r"[\x00-\x1f]", "?", s)


def _wrap_mono(s: str, cap: int) -> List[str]:
    """Wrap fixed-width text; prefer breaking after / space - _ so paths stay readable."""
    cap, out, s = max(4, cap), [], _dclean(s)
    while len(s) > cap:
        cut = cap
        for i in range(cap, int(cap * 0.55), -1):
            if s[i - 1] in "/ -_,;":
                cut = i
                break
        out.append(s[:cut].rstrip())
        s = s[cut:].lstrip(" ")
    out.append(s)
    return out


def _hw(s: str, size: float, bold: bool = False) -> float:
    """Approximate Helvetica text width in points."""
    w = 0.0
    for ch in s:
        w += 0.28 if ch in "ijl.,:;'|!tfI " else 0.83 if ch in "mwMW" else 0.68 if ch.isupper() else 0.556 if ch.isdigit() else 0.52
    return w * size * (1.07 if bold else 1.0)


def _wrap_words(s: str, size: float, maxw: float, bold: bool = False) -> List[str]:
    lines, cur = [], ""
    for word in _dclean(s).split(" "):
        trial = (cur + " " + word).strip()
        if cur and _hw(trial, size, bold) > maxw:
            lines.append(cur)
            cur = word
        else:
            cur = trial
    return lines + [cur]


class _Pdf:
    """Tiny PDF writer: A4 landscape, Helvetica + Courier, rectangles, text, auto page breaks, repeating table headers."""
    W, H, MX, MY = 842.0, 595.0, 36.0, 40.0

    def __init__(self):
        self.pages: List[List[str]] = []
        self.cur: List[str] = []
        self.y = 0.0
        self.new_page()

    def new_page(self) -> None:
        self.cur = []
        self.pages.append(self.cur)
        self.y = self.H - self.MY

    @staticmethod
    def _rgb(h: str) -> str:
        h = h.lstrip("#")
        return " ".join(f"{int(h[i:i + 2], 16) / 255:.3f}" for i in (0, 2, 4))

    @staticmethod
    def _esc(s: str) -> str:
        s = _dclean(s).encode("cp1252", "replace").decode("latin-1")
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    def text(self, x, y, s, font="F1", size=9.0, color=D_INK) -> None:
        self.cur.append(f"BT /{font} {size} Tf {self._rgb(color)} rg {x:.1f} {y:.1f} Td ({self._esc(s)}) Tj ET")

    def rect(self, x, y, w, h, fill=None, stroke=None) -> None:
        pre = (f"{self._rgb(fill)} rg " if fill else "") + (f"{self._rgb(stroke)} RG 0.5 w " if stroke else "")
        self.cur.append(f"{pre}{x:.1f} {y:.1f} {w:.1f} {h:.1f} re {'B' if fill and stroke else 'f' if fill else 'S'}")

    def ensure(self, h: float) -> None:
        if self.y - h < self.MY + 14:
            self.new_page()

    # ---- blocks ----
    def title(self, title: str, sub: str) -> None:
        w = self.W - 2 * self.MX
        self.rect(self.MX, self.y - 52, w, 52, fill=D_BLUE)
        self.text(self.MX + 14, self.y - 24, title, "F2", 19, "#FFFFFF")
        self.text(self.MX + 14, self.y - 42, sub, "F1", 8.5, "#DCE8F5")
        self.y -= 64

    def verdict(self, level: str, text: str) -> None:
        self.ensure(30)
        w = self.W - 2 * self.MX
        self.rect(self.MX, self.y - 24, w, 24, fill=D_LEVEL[level])
        self.text(self.MX + 12, self.y - 16, text, "F2", 10.5, "#FFFFFF")
        self.y -= 34

    def kpis(self, cards) -> None:
        self.ensure(64)
        gap, n = 8.0, len(cards)
        cw = (self.W - 2 * self.MX - gap * (n - 1)) / n
        for i, (lab, val, sub, col) in enumerate(cards):
            x = self.MX + i * (cw + gap)
            self.rect(x, self.y - 54, cw, 54, fill="#F4F6FA", stroke=D_LINE)
            self.text(x + cw / 2 - _hw(lab, 7, True) / 2, self.y - 14, lab, "F2", 7, D_MUTE)
            self.text(x + cw / 2 - _hw(val, 17, True) / 2, self.y - 35, val, "F2", 17, col)
            self.text(x + cw / 2 - _hw(sub, 7) / 2, self.y - 48, sub, "F1", 7, D_MUTE)
        self.y -= 66

    def h1(self, text: str) -> None:
        self.ensure(110)
        self.y -= 12
        self.text(self.MX, self.y - 12, text, "F2", 13, D_BLUE)
        self.rect(self.MX, self.y - 18, self.W - 2 * self.MX, 1.2, fill=D_BLUE)
        self.y -= 28

    def h2(self, text: str, color: str = D_INK) -> None:
        self.ensure(84)
        self.y -= 4
        self.rect(self.MX, self.y - 10, 7, 7, fill=color)
        self.text(self.MX + 12, self.y - 9, text, "F2", 9.5, D_INK)
        self.y -= 18

    def para(self, text: str, mute: bool = False, size: float = 8.5) -> None:
        for ln in _wrap_words(text, size, self.W - 2 * self.MX - 4):
            self.ensure(size + 4)
            self.text(self.MX, self.y - size, ln, "F1", size, D_MUTE if mute else D_INK)
            self.y -= size + 3
        self.y -= 3

    def bars(self, rows) -> None:
        vmax = max([r[1] for r in rows] + [1e-9])
        lw, bw = 150.0, 260.0
        for label, val, right, col in rows:
            self.ensure(15)
            self.text(self.MX + 4, self.y - 9, _dclean(label)[:int(lw / 4.1)] if _hw(_dclean(label), 8) > lw else label, "F1", 8)
            x = self.MX + lw + 8
            self.rect(x, self.y - 10, bw, 9, fill="#EEF1F6")
            self.rect(x, self.y - 10, max(1.5, bw * val / vmax) if val > 0 else 0, 9, fill=col)
            self.text(x + bw + 10, self.y - 9, right, "F3", 7.5)
            self.y -= 14
        self.y -= 6

    def table(self, cols, rows, size: float = 7.0) -> None:
        cw, pad, lead = size * 0.6, 3.0, size * 1.25
        usable = self.W - 2 * self.MX
        fixed = sum(c[1] * cw + 2 * pad for c in cols if c[1] > 0)
        weights = sum(-c[1] for c in cols if c[1] < 0) or 1
        rest = max(60.0, usable - fixed)
        widths = [c[1] * cw + 2 * pad if c[1] > 0 else rest * (-c[1]) / weights for c in cols]
        if sum(widths) > usable:
            widths = [w * usable / sum(widths) for w in widths]

        def header() -> None:
            self.ensure(40)
            x = self.MX
            self.rect(x, self.y - 15, sum(widths), 15, fill=D_BLUE)
            for (h, _, al, _), w in zip(cols, widths):
                tx = x + pad if al == "l" else x + w - pad - _hw(h, 7, True)
                self.text(tx, self.y - 10.5, h, "F2", 7, "#FFFFFF")
                x += w
            self.y -= 15

        header()
        for ri, row in enumerate(rows):
            cells, lines = [_dcell(c) for c in row], []
            for c, w in zip(cells, widths):
                lines.append(_wrap_mono(c["t"], int((w - 2 * pad) / cw)))
            h = max(len(x) for x in lines) * lead + 4
            if self.y - h < self.MY + 14:
                self.new_page()
                header()
            x = self.MX
            self.rect(x, self.y - h, sum(widths), h, fill=D_ZEBRA if ri % 2 else "#FFFFFF")
            for c, ls, w, (_, _, al, _) in zip(cells, lines, widths, cols):
                if c.get("fill"):
                    self.rect(x, self.y - h, w, h, fill=c["fill"])
                font = "F4" if c.get("bold") else "F3"
                for li, ln in enumerate(ls):
                    tx = x + pad if al == "l" else x + w - pad - len(ln) * cw
                    self.text(tx, self.y - 2 - size - li * lead + 1, ln, font, size, c.get("color") or D_INK)
                x += w
            self.rect(self.MX, self.y - h, sum(widths), 0.4, fill=D_LINE)
            self.y -= h
        self.y -= 8

    def save(self, path: str, footer: str) -> None:
        n, out, offs = len(self.pages), bytearray(b"%PDF-1.4\n"), {}

        def add(num: int, data: bytes) -> None:
            offs[num] = len(out)
            out.extend(f"{num} 0 obj\n".encode() + data + b"\nendobj\n")

        add(1, b"<< /Type /Catalog /Pages 2 0 R >>")
        add(2, f"<< /Type /Pages /Kids [{' '.join(f'{7 + 2 * i} 0 R' for i in range(n))}] /Count {n} >>".encode())
        for i, name in enumerate(("Helvetica", "Helvetica-Bold", "Courier", "Courier-Bold")):
            add(3 + i, f"<< /Type /Font /Subtype /Type1 /BaseFont /{name} /Encoding /WinAnsiEncoding >>".encode())
        for i, pg in enumerate(self.pages):
            self.cur = list(pg)
            self.text(self.MX, 22, footer, "F1", 7, D_MUTE)
            label = f"Page {i + 1} of {n}"
            self.text(self.W - self.MX - _hw(label, 7), 22, label, "F1", 7, D_MUTE)
            stream = "\n".join(self.cur).encode("latin-1", "replace")
            add(7 + 2 * i, (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.W:.0f} {self.H:.0f}] /Resources << /Font << /F1 3 0 R /F2 4 0 R "
                            f"/F3 5 0 R /F4 6 0 R >> >> /Contents {8 + 2 * i} 0 R >>").encode())
            add(8 + 2 * i, f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream")
        total, xref = 7 + 2 * n, len(out)
        out.extend(f"xref\n0 {total}\n0000000000 65535 f \n".encode())
        for num in range(1, total):
            out.extend(f"{offs[num]:010d} 00000 n \n".encode())
        out.extend(f"trailer\n<< /Size {total} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
        with open_secure(path, "wb") as fh:
            fh.write(out)


# ---- WORD --------------------------------------------------------------------------------------------------------- #
def _wx(t) -> str:
    return htmllib.escape(_XML_BAD.sub("", str(t).replace("\n", " ")), quote=False)


def _wrun(t, bold=False, color=None, size=None, mono=False) -> str:
    rpr = ('<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/>' if mono else "") + ("<w:b/>" if bold else "") + \
          (f'<w:color w:val="{color.lstrip("#")}"/>' if color else "") + (f'<w:sz w:val="{int(size * 2)}"/>' if size else "")
    return f'<w:r><w:rPr>{rpr}</w:rPr><w:t xml:space="preserve">{_wx(t)}</w:t></w:r>'


def _wpara(runs: str, style: Optional[str] = None, fill: Optional[str] = None, before: int = 40, after: int = 40, jc: str = "", keep: bool = False) -> str:
    ppr = ""
    if style:
        ppr += '<w:pStyle w:val="%s"/>' % style
    if keep:
        ppr += "<w:keepNext/>"
    if fill:
        ppr += '<w:shd w:val="clear" w:color="auto" w:fill="%s"/>' % fill.lstrip("#")
    ppr += '<w:spacing w:before="%d" w:after="%d"/>' % (before, after)
    if jc:
        ppr += '<w:jc w:val="%s"/>' % jc
    return "<w:p><w:pPr>%s</w:pPr>%s</w:p>" % (ppr, runs)


def _wraw(w: int, body: str, fill: Optional[str] = None) -> str:
    shd = '<w:shd w:val="clear" w:color="auto" w:fill="%s"/>' % fill.lstrip("#") if fill else ""
    return '<w:tc><w:tcPr><w:tcW w:w="%d" w:type="dxa"/>%s<w:vAlign w:val="center"/></w:tcPr>%s</w:tc>' % (w, shd, body)


def _wcell(w: int, text, align="l", fill=None, color=None, bold=False, mono=False, size=8.0) -> str:
    jc = "right" if align == "r" else ("center" if align == "c" else "")
    return _wraw(w, _wpara(_wrun(text, bold, color, size, mono), before=20, after=20, jc=jc), fill)


_WSIDES = ("top", "left", "bottom", "right", "insideH", "insideV")
_WBORD = "".join('<w:%s w:val="single" w:sz="4" w:space="0" w:color="E3E8EF"/>' % t for t in _WSIDES)
_WNOBORD = "".join('<w:%s w:val="nil"/>' % t for t in _WSIDES)


def _wtable(widths: List[int], rows_xml: str, borders: str = _WBORD) -> str:
    grid = "".join('<w:gridCol w:w="%d"/>' % w for w in widths)
    return ('<w:tbl><w:tblPr><w:tblW w:w="%d" w:type="dxa"/><w:tblBorders>%s</w:tblBorders><w:tblLayout w:type="fixed"/>'
            '<w:tblCellMar><w:left w:w="70" w:type="dxa"/><w:right w:w="70" w:type="dxa"/></w:tblCellMar></w:tblPr>'
            '<w:tblGrid>%s</w:tblGrid>%s</w:tbl>' % (sum(widths), borders, grid, rows_xml)) + _wpara("", before=0, after=60)


def _wdata_table(cols, rows, total: int = 15398) -> str:
    fixed = sum(c[1] * 95 + 160 for c in cols if c[1] > 0)
    weights = sum(-c[1] for c in cols if c[1] < 0) or 1
    rest = max(1500, total - fixed)
    widths = [c[1] * 95 + 160 if c[1] > 0 else int(rest * (-c[1]) / weights) for c in cols]
    xml = '<w:tr><w:trPr><w:cantSplit/><w:tblHeader/></w:trPr>' + "".join(
        _wcell(w, c[0], c[2], D_BLUE, "#FFFFFF", True, False, 8) for c, w in zip(cols, widths)) + "</w:tr>"
    for ri, row in enumerate(rows):
        xml += "<w:tr><w:trPr><w:cantSplit/></w:trPr>"
        for c, w, col in zip(row, widths, cols):
            c = _dcell(c)
            xml += _wcell(w, c["t"], col[2], c.get("fill") or (D_ZEBRA if ri % 2 else None), c.get("color"), c.get("bold", False),
                          c.get("mono", col[3]), 8)
        xml += "</w:tr>"
    return _wtable(widths, xml)


def _wblocks(blocks) -> str:
    X = []
    for b in blocks:
        k = b[0]
        if k == "title":
            X.append(_wpara(_wrun(b[1], True, "#FFFFFF", 22), fill=D_BLUE, before=0, after=0))
            X.append(_wpara(_wrun(b[2], False, "#DCE8F5", 9), fill=D_BLUE, before=0, after=160))
        elif k == "verdict":
            X.append(_wpara(_wrun(" " + b[2], True, "#FFFFFF", 12), fill=D_LEVEL[b[1]], before=60, after=100))
        elif k == "kpis":
            w = 15398 // len(b[1])
            cells = "".join(_wraw(w, _wpara(_wrun(c[0], True, D_MUTE, 7), before=40, after=0, jc="center")
                                  + _wpara(_wrun(c[1], True, c[3], 17), before=0, after=0, jc="center")
                                  + _wpara(_wrun(c[2], False, D_MUTE, 7.5), before=0, after=40, jc="center"), "#F4F6FA") for c in b[1])
            white = "".join('<w:%s w:val="single" w:sz="24" w:space="0" w:color="FFFFFF"/>' % t for t in ("top", "left", "bottom", "right", "insideH", "insideV"))
            X.append(_wtable([w] * len(b[1]), "<w:tr>%s</w:tr>" % cells, white))
        elif k == "h1":
            X.append(_wpara(_wrun(b[1]), style="Heading1", keep=True))
        elif k == "h2":
            X.append(_wpara(_wrun("■ ", True, b[2] or D_INK, 10) + _wrun(b[1], True, D_INK, 10.5), style="Heading2", keep=True))
        elif k == "p":
            X.append(_wpara(_wrun(b[1], False, D_MUTE if b[2] else D_INK, 9.5)))
        elif k == "bars":
            vmax = max([r[1] for r in b[1]] + [1e-9])
            rows = ""
            for label, val, right, col in b[1]:
                n = 0 if val <= 0 else max(1, round(val / vmax * 34))
                bar = _wrun("\u2588" * n, False, col, 8, True) + _wrun("\u2591" * (34 - n), False, "#D5DBE5", 8, True)
                rows += ("<w:tr>" + _wcell(2900, label, "l", size=8.5) + _wraw(3800, _wpara(bar, before=20, after=20))
                         + _wcell(5200, _dclean(right), "l", mono=True, size=8) + "</w:tr>")
            X.append(_wtable([2900, 3800, 5200], rows, _WNOBORD))
        elif k == "table":
            X.append(_wdata_table(b[1], b[2]))
    return "".join(X)


def export_docx(path: str, M: dict) -> None:
    blocks = build_doc_blocks(M)
    ns = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
    doc = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document {ns}><w:body>{_wblocks(blocks)}'
           '<w:sectPr><w:footerReference w:type="default" r:id="rId2"/><w:pgSz w:w="16838" w:h="11906" w:orient="landscape"/>'
           '<w:pgMar w:top="720" w:right="720" w:bottom="720" w:left="720" w:header="360" w:footer="360" w:gutter="0"/></w:sectPr></w:body></w:document>')
    styles = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles {ns}><w:docDefaults><w:rPrDefault><w:rPr>'
              '<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/><w:sz w:val="20"/><w:color w:val="1D2433"/></w:rPr></w:rPrDefault></w:docDefaults>'
              '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>'
              '<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>'
              '<w:pPr><w:keepNext/><w:pBdr><w:bottom w:val="single" w:sz="8" w:space="2" w:color="1F4E79"/></w:pBdr><w:spacing w:before="320" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr>'
              '<w:rPr><w:b/><w:color w:val="1F4E79"/><w:sz w:val="30"/></w:rPr></w:style>'
              '<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>'
              '<w:pPr><w:keepNext/><w:spacing w:before="200" w:after="60"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:b/><w:sz w:val="22"/></w:rPr></w:style></w:styles>')
    footer = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:ftr {ns}><w:p><w:pPr><w:jc w:val="center"/></w:pPr>'
              + _wrun(f"Linux File Cleanup Report - {M['meta']['server']}   |   Page ", False, D_MUTE, 8)
              + '<w:fldSimple w:instr=" PAGE "><w:r><w:t>1</w:t></w:r></w:fldSimple>' + _wrun(" of ", False, D_MUTE, 8)
              + '<w:fldSimple w:instr=" NUMPAGES "><w:r><w:t>1</w:t></w:r></w:fldSimple></w:p></w:ftr>')
    rel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    with open_secure(path, "wb") as fh, zipfile.ZipFile(fh, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml",
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
                    '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
                    '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
                    '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/></Types>')
        zf.writestr("_rels/.rels", f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                    f'<Relationship Id="rId1" Type="{rel}/officeDocument" Target="word/document.xml"/></Relationships>')
        zf.writestr("word/_rels/document.xml.rels", f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                    f'<Relationship Id="rId1" Type="{rel}/styles" Target="styles.xml"/><Relationship Id="rId2" Type="{rel}/footer" Target="footer1.xml"/></Relationships>')
        zf.writestr("word/document.xml", doc)
        zf.writestr("word/styles.xml", styles)
        zf.writestr("word/footer1.xml", footer)


# ---- ONE CONTENT MODEL FOR BOTH ------------------------------------------------------------------------------------ #
def _doc_file_cols():
    return [("Last modified", 16, "l", False), ("Last activity", 16, "l", False), ("Modified by", 16, "l", False),
            ("Owner", 8, "l", False), ("Perms", 5, "l", False), ("Size", 9, "r", False), ("Unused for", 17, "l", False),
            ("Type", 14, "l", False), ("File (full path)", -1, "l", True)]


def _doc_file_row(r: FileRecord) -> list:
    bg, fg = D_RISK[r.risk]
    return [r.modified[:16], r.last_active[:16], Cx(r.modified_by, color=None if r.modified_by != "unknown" else D_MUTE), r.owner,
            r.perms, human(r.size), human_duration(r.age_days), r.category,
            Cx(r.path, bold=bool(r.sensitive), color=fg if r.sensitive else None)]


def build_doc_blocks(M: dict) -> list:
    meta, word, n, recs = M["meta"], M["verdict"], M["n"], M["recs"]
    B: list = [("title", "Linux File Cleanup Report",
                f"{meta['server']}  |  {meta['cloud']}  |  {meta['generated_at']} UTC  |  {meta['run_as']}"),
               ("p", "REPORT ONLY - nothing was deleted, moved or changed on this server.", True),
               ("verdict", word[1], f"{word[0]}  -  {word[2]}")]
    ok = not M["problems"]
    B.append(("kpis", [("UNUSED FILES", f"{len(recs):,}", f"older than {meta['min_age']} day(s)", D_BLUE),
                       ("TOTAL SIZE", human(M["total"]), "can be reviewed", D_BLUE),
                       ("SENSITIVE", f"{len(M['sens']):,}", f"{n['HIGH']} high | {n['MEDIUM']} medium", D_RISK["HIGH"][1]),
                       ("CRITICAL", f"{n['CRITICAL']:,}", "readable by everyone", D_RISK["CRITICAL" if n["CRITICAL"] else "LOW"][1]),
                       ("SCAN", "COMPLETE" if ok else "PARTIAL", "all readable disks" if ok else "see section 7", D_RISK["LOW" if ok else "HIGH"][1])]))
    B += [("h1", "Summary"),
          ("table", [("Item", 18, "l", False), ("Detail", -1, "l", False)],
           [[Cx("Server", bold=True), meta["server"]], [Cx("Cloud", bold=True), meta["cloud"]],
            [Cx("Report time (UTC)", bold=True), meta["generated_at"]], [Cx("Run as", bold=True), meta["run_as"]],
            [Cx("Folders scanned", bold=True), ", ".join(meta["roots"])],
            [Cx("Files checked", bold=True), f"{meta['files_seen']:,} files in {meta['dirs_seen']:,} folders ({meta['duration_s']} s)"],
            [Cx("Unused threshold", bold=True), f"files not touched for at least {meta['min_age']} day(s)"],
            [Cx("Who modified?", bold=True), meta["audit_note"]]]),
          ("h2", "How to read the risk levels", None),
          ("table", [("Risk", 10, "l", False), ("Meaning", -1, "l", False)],
           [[Cx("CRITICAL", bold=True, fill=D_RISK["CRITICAL"][0], color=D_RISK["CRITICAL"][1]), "Sensitive file (key, password, token) that EVERY user can read - or a private key readable by its group. Fix first."],
            [Cx("HIGH", bold=True, fill=D_RISK["HIGH"][0], color=D_RISK["HIGH"][1]), "Confirmed sensitive file, readable only by owner/group. Check it is protected (chmod 600) or move it to a secrets manager."],
            [Cx("MEDIUM", bold=True, fill=D_RISK["MEDIUM"][0], color=D_RISK["MEDIUM"][1]), "Name looks sensitive but content not confirmed, a certificate, a world-writable file, a crash dump or a huge file."],
            [Cx("LOW", bold=True, fill=D_RISK["LOW"][0], color=D_RISK["LOW"][1]), "Ordinary unused file - no sensitive pattern found."]])]
    # 1 attention
    B.append(("h1", "1 · Needs attention first - sensitive files"))
    if not M["sens"]:
        B.append(("p", "No sensitive files found.", False))
    else:
        rows = []
        for r in M["sens"]:
            bg, fg = D_RISK[r.risk]
            rows.append([Cx(r.risk, bold=True, fill=bg, color=fg), Cx(r.path, bold=True, color=fg), why_sensitive(r), r.modified[:16], r.last_active[:16],
                         Cx(r.modified_by, color=None if r.modified_by != "unknown" else D_MUTE), r.owner, r.perms, human(r.size)])
        B.append(("table", [("Risk", 9, "l", False), ("File (full path)", -3, "l", True), ("Why it was flagged", -2, "l", False), ("Last modified", 16, "l", False),
                            ("Last activity", 16, "l", False), ("Modified by", 16, "l", False), ("Owner", 8, "l", False), ("Perms", 5, "l", False),
                            ("Size", 9, "r", False)], rows))
        B.append(("p", "Tip: keys and password files should be chmod 600. This tool only reports - it never changes permissions. Secret VALUES are never stored in this report.", True))
    # 2 space
    B.append(("h1", "2 · Where is the space?"))
    total = max(1, M["total"])
    B.append(("h2", "2a  How long have files been unused?  (bar = size)", None))
    B.append(("bars", [(b["band"][1], b["size"], f"{b['files']:>6,} files {human(b['size']):>9} {b['size'] * 100 // total:>3}%", BAND_HEX[b["band"][3]]) for b in age_rows(M)]))
    arows = []
    for b in BANDS:
        fs = M["by_band"].get(b[0])
        if fs:
            sz = sum(f.size for f in fs)
            arows.append([Cx(b[1], bold=True, color=BAND_HEX[b[3]]), f"{len(fs):,}", human(sz), f"{sz * 100 // total}%",
                          min(f.last_active for f in fs)[:16], max(f.last_active for f in fs)[:16]])
    B.append(("table", [("Age group", 14, "l", False), ("Files", 9, "r", False), ("Size", 10, "r", False), ("Share", 6, "r", False),
                        ("Oldest activity", 16, "l", False), ("Newest activity", 16, "l", False)], arows))
    tl = timeline_rows(recs)
    if tl:
        B.append(("h2", "2b  When were files last active?  (bar = number of files)", None))
        B.append(("bars", [(a, v, c.strip(), "#2A77B5") for a, v, c in tl]))
    fr = folder_rows(recs, 10)
    if fr:
        B.append(("h2", "2c  Biggest folders of unused files  (bar = size)", None))
        B.append(("bars", [(tail(a, 30), v, c.strip(), "#7B61C4") for a, v, c in fr]))
    ty = type_rows(M)
    if ty:
        B.append(("h2", "2d  What kinds of files?  (bar = size)", None))
        B.append(("bars", [(a, v, c.strip(), "#C25BA7") for a, v, c in ty]))
    # 3 biggest
    B += [("h1", "3 · Biggest unused files - free these first"),
          ("table", _doc_file_cols(), [_doc_file_row(r) for r in sorted(recs, key=lambda x: -x.size)[:15]])]
    # 4 by age
    cap = DOC_OPTS["files"] or None
    B.append(("h1", "4 · Files by age (oldest first)"))
    for b in BANDS:
        fs = M["by_band"].get(b[0])
        if not fs:
            continue
        B.append(("h2", f"Unused {b[1]}  -  {nfiles(len(fs))}  |  {human(sum(f.size for f in fs))}  |  {b[2]}", BAND_HEX[b[3]]))
        top = ", ".join(f"{d} ({len(x):,} files, {human(sum(f.size for f in x))})" for d, x in group_dirs(fs)[:3])
        B.append(("p", "Main folders: " + top, True))
        ordered = sorted(fs, key=lambda x: -x.size)
        sel = ordered if not cap else ordered[:cap]
        B.append(("table", _doc_file_cols(), [_doc_file_row(r) for r in sel]))
        if len(sel) < len(fs):
            B.append(("p", f"... and {len(fs) - len(sel):,} more files in this group - the Excel / CSV report lists every file (or run with --doc-files 0).", True))
    # 5 kinds
    B += [("h1", "5 · What kinds of files are these?"),
          ("table", [("Type", 16, "l", False), ("Files", 8, "r", False), ("Size", 10, "r", False), ("What it is", -1, "l", False)],
           [[Cx(c, bold=True), f"{cnt:,}", human(sz), d] for c, (cnt, sz, d) in M["kinds"]])]
    # 6 who
    known = sum(1 for r in recs if r.modified_by != "unknown")
    B += [("h1", "6 · Who modified the files?"),
          ("p", f"{known:,} of {len(recs):,} files have a known editor.", False),
          ("p", "Linux never stores who edited a file - only the OWNER and the timestamps. The editor name comes from auditd. "
                f"To enable it run:  sudo ./{os.path.basename(sys.argv[0])} --audit-setup", True)]
    # 7 coverage
    st = {"ok": ("OK", D_RISK["LOW"]), "warn": ("WARNING", D_RISK["HIGH"]), "info": ("Note", ("#F4F6FA", D_MUTE))}
    B += [("h1", "7 · How complete is this scan?"),
          ("table", [("Status", 10, "l", False), ("Detail", -1, "l", False)],
           [[Cx(st[lv][0], bold=True, fill=st[lv][1][0], color=st[lv][1][1]), t] for lv, t in M["cov"]]),
          ("p", "RESULT: " + ("COMPLETE" if ok else "PARTIAL - " + "; ".join(M["problems"])), False)]
    # 8 next
    B += [("h1", "8 · What to do next"),
          ("table", [("#", 3, "r", False), ("Action", -1, "l", False)], [[str(i), s] for i, s in enumerate(next_steps(M), 1)]),
          ("p", "Report only: this tool never deletes, moves or changes files.", True)]
    return B


def export_pdf(path: str, M: dict) -> None:
    pdf = _Pdf()
    for b in build_doc_blocks(M):
        k = b[0]
        if k == "title":
            pdf.title(b[1], b[2])
        elif k == "verdict":
            pdf.verdict(b[1], b[2])
        elif k == "kpis":
            pdf.kpis(b[1])
        elif k == "h1":
            pdf.h1(b[1])
        elif k == "h2":
            pdf.h2(b[1], b[2] or D_INK)
        elif k == "p":
            pdf.para(b[1], b[2])
        elif k == "bars":
            pdf.bars(b[1])
        elif k == "table":
            pdf.table(b[1], b[2])
    pdf.save(path, f"Linux File Cleanup Report - {M['meta']['server']} - {M['meta']['generated_at']} UTC - report only")


ALL_FORMATS = ("html", "xlsx", "pdf", "docx", "csv", "json", "txt")


def save_reports(out_dir: str, M: dict, formats: List[str], txt: str) -> Dict[str, str]:
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    base = os.path.join(out_dir, f"file_discovery_{M['meta']['server']}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}")
    makers = {"html": export_html, "xlsx": export_xlsx, "pdf": export_pdf, "docx": export_docx, "csv": export_csv, "json": export_json}
    saved: Dict[str, str] = {}
    for fmt in formats:
        p = f"{base}.{fmt}"
        try:
            if fmt == "txt":
                with open_secure(p) as fh:
                    fh.write(txt + "\n")
            else:
                makers[fmt](p, M)
            saved[fmt] = p
        except Exception as exc:                        # one failing format never blocks the others
            log.warning("Could not create the %s report: %s: %s", fmt.upper(), type(exc).__name__, exc)
            try:
                os.remove(p)
            except OSError:
                pass
    give_back_to_sudo_user([out_dir] + list(saved.values()))
    return saved


# --------------------------------------------------------------------------- #
# CHAT MESSAGES - same story as the TUI, in each service's native rich format
# --------------------------------------------------------------------------- #
def _chunks(lines: List[str], limit: int) -> List[str]:
    out, cur = [], ""
    for ln in lines:
        ln = ln[:limit - 5]
        if cur and len(cur) + len(ln) + 1 > limit:
            out.append(cur)
            cur = ""
        cur += ("\n" if cur else "") + ln
    if cur:
        out.append(cur)
    return out


def chat_file_lines(M: dict, band: int, per_band: Optional[int], ansi: bool, name_w: int = 30) -> Tuple[List[str], int]:
    """Lines for one age group: header, folder header, then 'SIZE  LAST-ACTIVE  BY  NAME'. Returns (lines, files_not_shown)."""
    fs, lines, shown = M["by_band"][band], [], 0
    col = (lambda t, c: f"\u001b[{c}m{t}\u001b[0m") if ansi else (lambda t, c: t)      # noqa: E731
    lines.append(col("   SIZE      LAST ACTIVE  BY           FILE", 36))
    for d, dfs in group_dirs(fs):
        if per_band is not None and shown >= per_band:
            break
        lines.append(col(f"▸ {tail(d, 54)}", 34) + col(f"  ({len(dfs):,} · {human(sum(f.size for f in dfs))})", 30))
        for r in sorted(dfs, key=lambda x: -x.size):
            if per_band is not None and shown >= per_band:
                break
            who = r.modified_by if r.modified_by != "unknown" else r.owner
            mark = RISK_EMOJI[r.risk] + " " if (r.sensitive and not ansi) else ""
            name = head(r.name, name_w)
            if r.sensitive and ansi:
                name = col(name, RISK_ANSI[r.risk])
            lines.append(f"  {mark}{human(r.size):>9} {r.last_active[5:16]} {head(who, 12):<12} {name}")
            shown += 1
    return lines, len(fs) - shown


def _attn_lines(M: dict, n: Optional[int], ansi: bool) -> List[str]:
    out = []
    for r in (M["sens"] if not n else M["sens"][:n]):
        if ansi:
            c = RISK_ANSI[r.risk]
            out += [f"\u001b[1;{c}m{r.risk:<8}\u001b[0m {tail(r.path, 70)}", f"\u001b[30m  ↳ {head(why_sensitive(r), 90)}\u001b[0m",
                    f"  modified {r.modified[:16]} · active {r.last_active[:16]} · by {head(r.modified_by, 24)} · owner {r.owner} · {r.perms}"]
        else:
            out += [f"{RISK_EMOJI[r.risk]} *{r.risk}* `{tail(r.path, 70)}`",
                    f"      _{head(why_sensitive(r), 110)}_",
                    f"      modified {r.modified[:16]} · active {r.last_active[:16]} · by *{head(r.modified_by, 28)}* · owner {r.owner} · {r.perms}"]
    return out


def _emoji_bar(frac: float, band_emoji: str, width: int = 10) -> str:
    n = 0 if frac <= 0 else max(1, round(frac * width))
    return band_emoji * n + "⬜" * (width - n)


def discord_messages(M: dict, o: dict) -> List[dict]:
    bt = lambda x: str(x).replace("`", "'")             # noqa: E731
    meta, word = M["meta"], M["verdict"]
    color = {"crit": 0xE74C3C, "warn": 0xE67E22, "ok": 0x2ECC71}[word[1]]
    icon = {"crit": "🔴", "warn": "🟠", "ok": "🟢"}[word[1]]
    n = M["n"]
    emb: List[dict] = [{
        "title": f"📋 Linux File Cleanup Report - {meta['server']}"[:250], "color": color,
        "description": f"{meta['cloud']} · {meta['generated_at']} UTC · {meta['run_as']}\n**Report only - nothing was deleted, moved or changed**\n\n"
                       f"{icon} **{word[0]} - {bt(word[2])}**",
        "fields": [{"name": "Unused files", "value": f"{len(M['recs']):,}\n{human(M['total'])}", "inline": True},
                   {"name": "Sensitive", "value": f"{len(M['sens']):,}\n🔴 {n['CRITICAL']} · 🟠 {n['HIGH']} · 🟡 {n['MEDIUM']}", "inline": True},
                   {"name": "Scan", "value": "✅ COMPLETE" if not M["problems"] else "⚠️ PARTIAL", "inline": True},
                   {"name": "Why partial" if M["problems"] else "Coverage", "value": bt("; ".join(M["problems"]) or "every readable file was checked")[:1000], "inline": False},
                   {"name": "Who edited files?", "value": bt(meta["audit_note"])[:1000], "inline": False}],
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "footer": {"text": "linux_file_discovery · report only"}}]
    # 1 attention
    if not M["sens"]:
        emb.append({"title": "1 · Needs attention", "description": "🟢 No sensitive files found.", "color": 0x2ECC71})
    elif o["hide_paths"]:
        emb.append({"title": "1 · Needs attention", "description": f"{len(M['sens']):,} sensitive files (names hidden - see the attached report).", "color": 0xE74C3C})
    else:
        top = len(M["sens"]) if o["full"] else o["attention"]
        lines = _attn_lines(M, top, True)
        for i, ch in enumerate(_chunks([bt(x) for x in lines], 3800)):
            emb.append({"title": (f"1 · Needs attention first (top {min(top, len(M['sens']))} of {len(M['sens'])})" if i == 0 else "1 · Needs attention (cont.)"),
                        "description": f"```ansi\n{ch}\n```", "color": 0xE74C3C})

    # 2 graphs
    def acol(t, c):
        return f"\u001b[{c}m{t}\u001b[0m"

    def bar_lines(rows):                                  # rows: (label, value, right, ansi code)
        vmax = max([v for _, v, _, _ in rows] + [1])
        out = []
        for label, v, right, c in rows:
            k = 0 if v <= 0 else max(1, round(v / vmax * 14))
            out.append(f"{head(label, 12):<12} {acol('█' * k, c)}{acol('░' * (14 - k), 30)} {right}")
        return out

    ar = [(r["band"][1], r["size"], f"{r['files']:>5,}f {human(r['size']):>8}", r["band"][4]) for r in age_rows(M)]
    graph = "**2a · How long unused?** (bar = size)\n```ansi\n" + "\n".join(bar_lines(ar)) + "\n```"
    tl = timeline_rows(M["recs"])
    if tl:
        graph += "\n**2b · When last active?** (bar = files)\n```ansi\n" + "\n".join(bar_lines([(a, b, c.strip().replace("  ", " "), 34) for a, b, c in tl])) + "\n```"
    fr = folder_rows(M["recs"], 6)
    if fr:
        graph += "\n**2c · Biggest folders** (bar = size)\n```ansi\n" + "\n".join(bar_lines([(tail(a, 12), b, c.strip().replace("  ", " "), 35) for a, b, c in fr])) + "\n```"
    emb.append({"title": "📊 2 · Where is the space?", "description": graph[:4000], "color": 0x3498DB})
    # 3 age groups
    per = None if o["full"] else o["files"]
    for b in BANDS:
        if b[0] not in M["by_band"]:
            continue
        fs = M["by_band"][b[0]]
        lines, rest = chat_file_lines(M, b[0], per, True, 28)
        if rest:
            lines.append(f"… and {rest:,} more files - see the attached Excel / HTML report")
        for i, ch in enumerate(_chunks([bt(x) for x in lines], 3800)):
            emb.append({"title": (f"{b[5]} 3 · Unused {b[1]} - {nfiles(len(fs))} · {human(sum(f.size for f in fs))}" if i == 0 else f"{b[1]} (cont.)")[:250],
                        "description": f"```ansi\n{ch}\n```", "color": b[6]})
    emb.append({"description": "✅ **Report complete - no deletion performed.**\n" + bt(next_steps(M)[0]), "color": 0x2ECC71})
    msgs, cur, size = [], [], 0
    for e in emb:                                         # Discord: <= 10 embeds and ~6000 characters per message
        es = len(e.get("title", "")) + len(e.get("description", "")) + sum(len(f["name"]) + len(f["value"]) for f in e.get("fields", []))
        if cur and (len(cur) >= 10 or size + es > 5500):
            msgs.append(cur)
            cur, size = [], 0
        cur.append(e)
        size += es
    if cur:
        msgs.append(cur)
    return [{"username": "File Cleanup Report", "embeds": m} for m in msgs]


def slack_messages(M: dict, o: dict) -> List[dict]:
    sx = lambda t: str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")      # noqa: E731
    sec = lambda t: {"type": "section", "text": {"type": "mrkdwn", "text": t[:2990]}}            # noqa: E731
    ctx = lambda t: {"type": "context", "elements": [{"type": "mrkdwn", "text": t[:2990]}]}      # noqa: E731
    meta, word, n = M["meta"], M["verdict"], M["n"]
    icon = {"crit": "🔴", "warn": "🟠", "ok": "🟢"}[word[1]]
    B: List[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": f"📋 Linux File Cleanup Report - {meta['server']}"[:150], "emoji": True}},
        ctx(f"{sx(meta['cloud'])} · {meta['generated_at']} UTC · {sx(meta['run_as'])} · *report only - nothing was deleted*"),
        sec(f"{icon} *{word[0]} - {sx(word[2])}*"),
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Unused files*\n{len(M['recs']):,} · {human(M['total'])}"},
            {"type": "mrkdwn", "text": f"*Sensitive*\n{len(M['sens']):,}  🔴 {n['CRITICAL']}  🟠 {n['HIGH']}  🟡 {n['MEDIUM']}"},
            {"type": "mrkdwn", "text": "*Scan*\n" + ("✅ COMPLETE" if not M["problems"] else "⚠️ PARTIAL - " + sx("; ".join(M["problems"])))},
            {"type": "mrkdwn", "text": f"*Who edited?*\n{sx(head(meta['audit_note'], 120))}"}]}]
    B.append({"type": "divider"})
    if not M["sens"]:
        B.append(sec("🟢 *1 · Needs attention* - no sensitive files found."))
    elif o["hide_paths"]:
        B.append(sec(f"🔴 *1 · Needs attention* - {len(M['sens']):,} sensitive files (names hidden, see the attached report)."))
    else:
        top = len(M["sens"]) if o["full"] else o["attention"]
        body = _chunks([sx(x) for x in _attn_lines(M, top, False)], 2700)
        for i, ch in enumerate(body):
            B.append(sec((f"🔴 *1 · Needs attention first* (top {min(top, len(M['sens']))} of {len(M['sens'])})\n" if i == 0 else "") + ch))
    B.append({"type": "divider"})
    total = max(1, M["total"])
    rows = age_rows(M)
    vmax = max([r["size"] for r in rows] + [1])
    chart = [f"{_emoji_bar(r['size'] / vmax, r['band'][5])}  *{r['band'][1]}* — {r['files']:,} files · {human(r['size'])} · {r['size'] * 100 // total}%" for r in rows]
    B.append(sec("*2a · How long have files been unused?* (bar = size)\n" + "\n".join(chart)))
    tl = timeline_rows(M["recs"])
    if tl:
        tmax = max(v for _, v, _ in tl) or 1
        B.append(sec("*2b · When were files last active?* (bar = files)\n" + "\n".join(
            f"{_emoji_bar(v / tmax, '🟦')}  *{lab}* — {right.strip()}" for lab, v, right in tl)))
    fr = folder_rows(M["recs"], 6)
    if fr:
        fmax = max(v for _, v, _ in fr) or 1
        B.append(sec("*2c · Biggest folders* (bar = size)\n" + "\n".join(
            f"{_emoji_bar(v / fmax, '🟪')}  `{sx(tail(lab, 40))}` — {right.strip()}" for lab, v, right in fr)))
    per = None if o["full"] else o["files"]
    for b in BANDS:
        if b[0] not in M["by_band"]:
            continue
        fs = M["by_band"][b[0]]
        lines, rest = chat_file_lines(M, b[0], per, False, 30)
        if rest:
            lines.append(f"... and {rest:,} more files - see the attached Excel / HTML report")
        B.append({"type": "divider"})
        B.append(sec(f"{b[5]} *3 · Unused {b[1]}* — {nfiles(len(fs))} · {human(sum(f.size for f in fs))} · _{b[2]}_"))
        for ch in _chunks([sx(x) for x in lines], 2700):
            B.append(sec(f"```{ch}```"))
    B.append(ctx("✅ Report complete - no deletion performed. Next step: " + sx(next_steps(M)[0])))
    msgs, cur, size = [], [], 0
    for blk in B:                                         # Slack: <= 50 blocks per message
        bl = len(json.dumps(blk))
        if cur and (len(cur) >= 45 or size + bl > 30000):
            msgs.append(cur)
            cur, size = [], 0
        cur.append(blk)
        size += bl
    if cur:
        msgs.append(cur)
    out = []
    for i, blocks in enumerate(msgs, 1):
        if i > 1:
            blocks = [ctx(f"Linux File Cleanup Report - part {i}/{len(msgs)}")] + blocks
        out.append({"text": f"Linux File Cleanup Report - {word[0]}", "blocks": blocks})
    return out


def teams_card(body: List[dict]) -> dict:
    """One Microsoft Teams message = one Adaptive Card (works with Teams 'Workflows' webhooks)."""
    return {"type": "message", "attachments": [{
        "contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None,
        "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                    "version": "1.4", "msteams": {"width": "Full"}, "body": body}}]}


def teams_messages(M: dict, o: dict) -> List[dict]:
    tx = lambda t: str(t).replace("*", "\\*")                                                    # noqa: E731
    tb = lambda text, **kw: {"type": "TextBlock", "text": text, "wrap": True, **kw}              # noqa: E731
    mono = lambda lines: [tb(tx(ln) or " ", fontType="Monospace", size="Small", spacing="None", wrap=False) for ln in lines]  # noqa: E731
    head2 = lambda t: tb(t, weight="Bolder", size="Medium", separator=True, spacing="Medium")    # noqa: E731
    meta, word, n = M["meta"], M["verdict"], M["n"]
    icon = {"crit": "🔴", "warn": "🟠", "ok": "🟢"}[word[1]]
    style = {"crit": "attention", "warn": "warning", "ok": "good"}[word[1]]
    B: List[dict] = [
        tb(f"📋 Linux File Cleanup Report - {tx(meta['server'])}", size="Large", weight="Bolder"),
        tb(f"{meta['cloud']} · {meta['generated_at']} UTC · {tx(meta['run_as'])} · report only - nothing was deleted",
           isSubtle=True, spacing="None"),
        {"type": "Container", "style": style, "items": [tb(f"{icon} **{word[0]}** - {tx(word[2])}", weight="Bolder")]},
        {"type": "FactSet", "facts": [
            {"title": "Unused files", "value": f"{len(M['recs']):,} · {human(M['total'])}"},
            {"title": "Sensitive", "value": f"{len(M['sens']):,}   🔴 {n['CRITICAL']}  🟠 {n['HIGH']}  🟡 {n['MEDIUM']}"},
            {"title": "Scan", "value": "✅ COMPLETE" if not M["problems"] else "⚠️ PARTIAL - " + tx("; ".join(M["problems"]))},
            {"title": "Who edited?", "value": tx(head(meta["audit_note"], 140))}]}]
    # 1 attention
    if not M["sens"]:
        B += [head2("🟢 1 · Needs attention"), tb("No sensitive files found.")]
    elif o["hide_paths"]:
        B += [head2("🔴 1 · Needs attention"), tb(f"{len(M['sens']):,} sensitive files (names hidden - see the attached report).")]
    else:
        top = len(M["sens"]) if o["full"] else o["attention"]
        B.append(head2(f"🔴 1 · Needs attention first (top {min(top, len(M['sens']))} of {len(M['sens'])})"))
        for r in (M["sens"] if not top else M["sens"][:top]):
            B.append(tb(f"{RISK_EMOJI[r.risk]} **{r.risk}**  {tx(tail(r.path, 90))}", spacing="Small"))
            B.append(tb(f"↳ {tx(head(why_sensitive(r), 120))}", isSubtle=True, size="Small", spacing="None"))
            B.append(tb(f"modified {r.modified[:16]} · active {r.last_active[:16]} · by {tx(head(r.modified_by, 28))} · owner {r.owner} · {r.perms}",
                        isSubtle=True, size="Small", spacing="None"))
    # 2 graphs
    total = max(1, M["total"])
    rows = age_rows(M)
    vmax = max([r["size"] for r in rows] + [1])
    B += [head2("📊 2a · How long have files been unused?  (bar = size)")]
    B += mono([f"{_emoji_bar(r['size'] / vmax, r['band'][5])} {r['band'][1]:<12} {r['files']:>6,} files {human(r['size']):>9} {r['size'] * 100 // total:>3}%"
               for r in rows])
    tl = timeline_rows(M["recs"])
    if tl:
        tmax = max(v for _, v, _ in tl) or 1
        B += [head2("2b · When were files last active?  (bar = files)")]
        B += mono([f"{_emoji_bar(v / tmax, '🟦')} {lab:<14} {right.strip()}" for lab, v, right in tl])
    fr = folder_rows(M["recs"], 6)
    if fr:
        fmax = max(v for _, v, _ in fr) or 1
        B += [head2("2c · Biggest folders  (bar = size)")]
        B += mono([f"{_emoji_bar(v / fmax, '🟪')} {tail(lab, 34):<34} {right.strip()}" for lab, v, right in fr])
    # 3 every age group
    per = None if o["full"] else o["files"]
    for b in BANDS:
        if b[0] not in M["by_band"]:
            continue
        fs = M["by_band"][b[0]]
        lines, rest = chat_file_lines(M, b[0], per, False, 30)
        if rest:
            lines.append(f"... and {rest:,} more files - see the attached Excel / HTML report")
        B.append(head2(f"{b[5]} 3 · Unused {b[1]} — {nfiles(len(fs))} · {human(sum(f.size for f in fs))} · {b[2]}"))
        B += mono(lines)
    B.append(tb("✅ Report complete - no deletion performed. Next step: " + tx(next_steps(M)[0]), isSubtle=True, separator=True))
    msgs, cur, size = [], [], 0
    for blk in B:                                         # Teams: keep each card well under ~28 KB
        bl = len(json.dumps(blk))
        if cur and size + bl > 24000:
            msgs.append(cur)
            cur, size = [], 0
        cur.append(blk)
        size += bl
    if cur:
        msgs.append(cur)
    out = []
    for i, blocks in enumerate(msgs, 1):
        if i > 1:
            blocks = [tb(f"Linux File Cleanup Report - part {i}/{len(msgs)}", isSubtle=True)] + blocks
        out.append(teams_card(blocks))
    return out


BUILDERS = {"slack": slack_messages, "teams": teams_messages, "discord": discord_messages}
WEBHOOK_VARS = {"slack": "SLACK_WEBHOOK_URL", "teams": "TEAMS_WEBHOOK_URL", "discord": "DISCORD_WEBHOOK_URL"}
URL_RE = {"slack": re.compile(r"^https://hooks\.slack\.com/services/\S+$"),
          "teams": re.compile(r"^https://[\w.-]+\.(?:webhook\.office\.com|logic\.azure\.com|api\.powerplatform\.com|office\.com)(?::\d+)?/\S+$"),
          "discord": re.compile(r"^https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api(?:/v\d+)?/webhooks/\d+/[\w-]+(?:\?.*)?$")}


def get_webhook(ch: str) -> Tuple[str, Optional[str]]:
    var = WEBHOOK_VARS[ch]
    url = cfg(var)
    if not url or "XXXX" in url or url.endswith("..."):
        return "", f"skipped - {var} is not set"
    if not URL_RE[ch].match(url):
        return "", f"FAILED - {var} does not look like a valid {ch.title()} webhook URL"
    return url, None


def explain_http(ch: str, code: int, body: str) -> str:
    b = (body or "").lower()
    if code == 403 and ("1010" in b or "cloudflare" in b):
        return "HTTP 403 (1010): blocked by the firewall in front of the webhook"
    if code in (401, 403, 404):
        return f"HTTP {code}: webhook revoked, deleted or wrong - create a NEW {ch.title()} webhook"
    if code == 400:
        return "HTTP 400: message rejected (too long or wrong format) " + (body or "")[:120].replace("\n", " ")
    if code == 413:
        return "HTTP 413: file too large for this service"
    if code == 429:
        return "HTTP 429: rate limited"
    return f"HTTP {code}"


def post_json(url: str, payload: dict, ch: str, retries: int = 3) -> Tuple[bool, str]:
    """POST JSON; the URL is never logged. Retries only 429 / 5xx / network errors."""
    body, last = json.dumps(payload).encode(), "unknown error"
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=20):               # nosec - user supplied
                return True, ""
        except urllib.error.HTTPError as exc:
            try:
                text = exc.read().decode("utf-8", "replace")[:300]
            except Exception:
                text = ""
            last = explain_http(ch, exc.code, text)
            if exc.code == 429:
                try:
                    wait = min(30.0, float(exc.headers.get("Retry-After", 5)))
                except (TypeError, ValueError):
                    wait = 5.0
                time.sleep(wait)
                continue
            if exc.code < 500:
                return False, last
        except Exception as exc:
            last = f"network error ({type(exc).__name__})"
        if attempt < retries:
            time.sleep(2 ** attempt)
    return False, last


def notify(channels: List[str], M: dict, opts: dict) -> Dict[str, str]:
    results: Dict[str, str] = {}
    for ch in channels:
        if ch not in BUILDERS:
            results[ch] = "skipped - unknown channel (use slack, teams, discord)"
            continue
        url, problem = get_webhook(ch)
        if problem:
            results[ch] = problem
            continue
        msgs = BUILDERS[ch](M, opts)
        cap = opts["max_messages"]
        dropped = 0
        if cap and len(msgs) > cap:
            dropped = len(msgs) - cap
            msgs = msgs[:cap]
        sent = 0
        for i, payload in enumerate(msgs, 1):
            ok, why = post_json(url, payload, ch)
            if not ok:
                results[ch] = f"FAILED - {why}" + (f" ({sent}/{len(msgs)} messages sent)" if sent else "")
                break
            sent += 1
            if i < len(msgs):
                time.sleep(1.2)                                # stay under ~1 message/second
        else:
            results[ch] = f"sent ({sent} message{'s' if sent != 1 else ''}" + (f", {dropped} more skipped by --chat-max-messages" if dropped else "") + ")"
    return results


# --------------------------------------------------------------------------- #
# ATTACHMENTS (full PDF / Word / Excel / HTML / CSV in the chat itself)
# --------------------------------------------------------------------------- #
def _multipart(fields: Dict[str, str], field_name: str, filename: str, data: bytes):
    boundary = "----lfd" + os.urandom(8).hex()
    parts = [f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode() for k, v in fields.items()]
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
                 f'Content-Type: application/octet-stream\r\n\r\n'.encode() + data + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def shrink_for_upload(path: str, limit: int) -> Optional[str]:
    """Return the file itself when it fits, else a .zip of it when that fits, else None."""
    if os.path.getsize(path) <= limit:
        return path
    zpath = path + ".zip"
    try:
        with open_secure(zpath, "wb") as fh, zipfile.ZipFile(fh, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            zf.write(path, os.path.basename(path))
        if os.path.getsize(zpath) <= limit:
            return zpath
    except Exception:
        pass
    return None


def upload_discord(url: str, path: str, note: str) -> str:
    send = shrink_for_upload(path, DISCORD_UPLOAD_LIMIT)
    if not send:
        return f"skipped ({human(os.path.getsize(path))}, over Discord's limit even zipped - open it from the server)"
    with open(send, "rb") as fh:
        data = fh.read()
    body, ctype = _multipart({"payload_json": json.dumps({"content": note, "username": "File Cleanup Report"})}, "files[0]", os.path.basename(send), data)
    try:
        req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": ctype, "User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=120):                  # nosec
            return "sent" if send == path else "sent (zipped)"
    except urllib.error.HTTPError as exc:
        return f"FAILED - {explain_http('discord', exc.code, '')}"
    except Exception as exc:
        return f"FAILED - {type(exc).__name__}"


SLACK_HINTS = {
    "not_in_channel": "the app is not in the channel - type /invite @YourApp there",
    "channel_not_found": "SLACK_CHANNEL_ID must be the ID (C0123...), not the name; for a private channel invite the app first",
    "missing_scope": "add the files:write scope to the app, then reinstall it to the workspace",
    "invalid_auth": "SLACK_BOT_TOKEN is wrong or revoked",
    "not_authed": "SLACK_BOT_TOKEN is missing",
    "token_revoked": "SLACK_BOT_TOKEN was revoked - create a new one",
    "account_inactive": "the Slack app / token was deactivated",
}


def _slack_call(token: str, method: str, data: bytes, ctype: str, timeout: int = 30) -> dict:
    req = urllib.request.Request(f"{SLACK_API}/{method}", data=data, method="POST",
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": ctype, "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:          # nosec - fixed slack.com URL
        return json.loads(resp.read().decode())


def upload_slack_many(token: str, channel: str, paths: List[str], note: str) -> str:
    """Upload every report as ONE Slack post. Needs a bot token with files:write and the app invited to the channel."""
    files = []
    try:
        for path in paths:
            name = os.path.basename(path)
            with open(path, "rb") as fh:
                data = fh.read()
            s1 = _slack_call(token, "files.getUploadURLExternal",
                             urllib.parse.urlencode({"filename": name, "length": len(data)}).encode(),
                             "application/x-www-form-urlencoded")
            if not s1.get("ok"):
                err = s1.get("error", "?")
                return f"FAILED - {err}: {SLACK_HINTS.get(err, '')}"
            up = urllib.request.Request(s1["upload_url"], data=data, method="POST",
                                        headers={"Content-Type": "application/octet-stream", "User-Agent": USER_AGENT})
            with urllib.request.urlopen(up, timeout=300):               # nosec - URL returned by Slack
                pass
            files.append({"id": s1["file_id"], "title": name})
        s3 = _slack_call(token, "files.completeUploadExternal",
                         json.dumps({"files": files, "channel_id": channel, "initial_comment": note}).encode(),
                         "application/json; charset=utf-8", 60)
        if s3.get("ok"):
            return f"sent ({len(files)} files)"
        err = s3.get("error", "?")
        return f"FAILED - {err}: {SLACK_HINTS.get(err, '')}"
    except urllib.error.HTTPError as exc:
        return f"FAILED - HTTP {exc.code} while uploading {len(files) + 1}/{len(paths)}"
    except Exception as exc:
        return f"FAILED - {type(exc).__name__}: {exc}"


def send_attachments(channels: List[str], kinds: List[str], saved: Dict[str, str], note: str) -> Dict[str, str]:
    res: Dict[str, str] = {}
    files = [saved[k] for k in kinds if k in saved]
    for ch in channels:
        if ch == "discord":
            url, problem = get_webhook("discord")
            if not url:
                continue
            out = [f"{os.path.basename(f).rsplit('.', 1)[-1]}: {upload_discord(url, f, note)}" for f in files]
            res["discord files"] = ", ".join(out) or "nothing to attach"
        elif ch == "teams":
            res["teams files"] = "skipped - Teams webhooks cannot carry files; open the Excel / HTML report from the server"
        elif ch == "slack":
            tok, chan = cfg("SLACK_BOT_TOKEN"), cfg("SLACK_CHANNEL_ID")
            if not (tok and chan):
                missing = " and ".join(n for n, v in (("SLACK_BOT_TOKEN", tok), ("SLACK_CHANNEL_ID", chan)) if not v)
                res["slack files"] = f"skipped - {missing} not set (webhooks cannot carry files; see the top of this script)"
            elif not files:
                res["slack files"] = "nothing to attach"
            else:
                res["slack files"] = upload_slack_many(tok, chan, files, note)
    return res


def check_slack_bot() -> str:
    """auth.test: is the bot token valid? (cannot prove the app was invited to the channel - the upload reports that)."""
    tok, chan = cfg("SLACK_BOT_TOKEN"), cfg("SLACK_CHANNEL_ID")
    if not tok:
        return "SLACK_BOT_TOKEN not set - Slack will get the message but NOT the PDF/Word/Excel/HTML/CSV files"
    if not chan:
        return "SLACK_CHANNEL_ID not set - files cannot be attached (use the channel ID like C0123ABCDEF)"
    if not re.match(r"^[CGD][A-Z0-9]{6,}$", chan):
        return f"SLACK_CHANNEL_ID '{chan}' does not look like an ID - it must be like C0123ABCDEF, not the channel name"
    try:
        r = _slack_call(tok, "auth.test", b"", "application/x-www-form-urlencoded", 15)
    except Exception as exc:
        return f"FAILED - could not reach Slack ({type(exc).__name__})"
    if not r.get("ok"):
        err = r.get("error", "?")
        return f"FAILED - {err}: {SLACK_HINTS.get(err, '')}"
    return (f"token OK (bot '{r.get('user')}' in '{r.get('team')}'). Make sure you ran /invite @{r.get('user')} "
            f"in the channel and the app has the files:write scope")


def run_test_notify(channels: List[str]) -> int:
    print("\nWEBHOOK CHECK")
    code = 0
    for ch in channels:
        url, problem = get_webhook(ch)
        if problem:
            print(f"  {ch:<8} {problem}")
            code = 1
            continue
        payload = ({"text": "✅ Linux File Cleanup - TEST: this Slack webhook works."} if ch == "slack" else
                   teams_card([{"type": "TextBlock", "text": "✅ Linux File Cleanup - TEST: this Teams webhook works.", "weight": "Bolder", "wrap": True}]) if ch == "teams" else
                   {"username": "File Cleanup Report", "embeds": [{"title": "✅ Linux File Cleanup - TEST", "description": "This Discord webhook works.", "color": 0x2ECC71}]})
        ok, why = post_json(url, payload, ch)
        print(f"  {ch:<8} {'sent' if ok else 'FAILED - ' + why}")
        code |= 0 if ok else 1
    if "slack" in channels:
        msg = check_slack_bot()
        print(f"  {'slack files':<12} {msg}")
        if msg.startswith(("FAILED", "SLACK_")):
            code |= 1
    return code


def configured_channels() -> List[str]:
    return [ch for ch in WEBHOOK_VARS if get_webhook(ch)[0]]


# --------------------------------------------------------------------------- #
# SYSTEM HELPERS
# --------------------------------------------------------------------------- #
def give_back_to_sudo_user(paths: List[str]) -> None:
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and gid:
        for p in paths:
            try:
                os.chown(p, int(uid), int(gid))
            except OSError:
                pass


def maybe_elevate(args) -> None:
    """Not root but passwordless sudo works (default on EC2 Ubuntu)? Restart under sudo so no folder is hidden."""
    if os.geteuid() == 0 or args.no_elevate:
        return
    try:
        ok = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        ok = False
    if not ok:
        log.warning("Passwordless sudo not available - continuing as '%s' (some folders will be hidden).", owner_name(os.geteuid()))
        return
    log.info("Not root - restarting with sudo so every folder can be read (use --no-elevate to stay '%s').", owner_name(os.geteuid()))
    os.execvp("sudo", ["sudo", "-n", "-E", sys.executable, os.path.abspath(sys.argv[0])] + sys.argv[1:] + ["--no-elevate"])


def acquire_lock(out_dir: str):
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    lock_path = os.path.join(out_dir, ".lock")
    try:
        fh = open(lock_path, "w")
    except OSError:
        return object()
    give_back_to_sudo_user([out_dir, lock_path])
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return None
    return fh


# --------------------------------------------------------------------------- #
# MAIN
# --------------------------------------------------------------------------- #
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Linux file discovery & reporting (report only, never deletes)")
    p.add_argument("--roots", nargs="+", default=DEFAULT_ROOTS, help=f"folders to scan (default: {' '.join(DEFAULT_ROOTS)})")
    p.add_argument("--exclude", nargs="*", default=[], help="extra paths to skip")
    p.add_argument("--min-age", type=int, default=1, help="only list files unused for at least N days (default 1)")
    p.add_argument("--age-basis", choices=list(AGE_BASIS), default="all", help="timestamps that define 'unused' (default all = mtime+atime+ctime)")
    p.add_argument("--cross-filesystems", action="store_true", help="also scan other mounted disks")
    p.add_argument("--include-system-paths", action="store_true", help="also scan /usr /bin /lib* /boot ... (skipped by default)")
    p.add_argument("--no-content-scan", action="store_true", help="detect sensitive files by NAME only (faster)")
    p.add_argument("--full", action="store_true", help="nothing hidden: system paths + other disks")
    p.add_argument("--no-elevate", action="store_true", help="do not auto-restart with sudo")
    p.add_argument("--max-records", type=int, default=1_000_000)
    p.add_argument("--output-dir", default="./file_discovery_reports")
    p.add_argument("--formats", default="all", help="html,xlsx,pdf,docx,csv,json,txt or all (default all)")
    p.add_argument("--doc-files", type=int, default=0, help="files listed per age group in the PDF / Word report (default 0 = ALL files)")
    p.add_argument("--server-name", default=socket.gethostname())
    p.add_argument("--cloud", choices=["AWS", "Azure", "GCP", "On-Prem"], help="skip auto-detection")
    # terminal
    p.add_argument("--top", type=int, default=12, help="files per age group in the terminal (default 12, 0 = all)")
    p.add_argument("--width", type=int, default=0, help="force the terminal layout width (default: auto)")
    p.add_argument("--no-color", action="store_true")
    # chat
    p.add_argument("--notify", default="auto", help="slack,teams,discord | auto (every channel with a webhook) | none")
    p.add_argument("--chat-files", type=int, default=15, help="files listed per age group in chat (default 15)")
    p.add_argument("--chat-attention", type=int, default=15, help="sensitive files listed in chat (default 15)")
    p.add_argument("--chat-full", action="store_true", help="put EVERY file and EVERY sensitive file in chat (many messages)")
    p.add_argument("--chat-max-messages", type=int, default=40, help="safety cap per channel (default 40, 0 = no cap)")
    p.add_argument("--attach", default="pdf,xlsx,docx,html,csv", help="report files to upload to the chats (default pdf,xlsx,docx,html,csv; '' = none)")
    p.add_argument("--hide-sensitive-paths", action="store_true", help="never list sensitive file paths in chat")
    p.add_argument("--test-notify", action="store_true", help="send one tiny test message per webhook, check the Slack bot token, and exit")
    # who modified
    p.add_argument("--audit-log", default=AUDIT_LOG)
    p.add_argument("--audit-key", default=AUDIT_KEY, help=f"auditd rule key to read (default {AUDIT_KEY})")
    p.add_argument("--audit-setup", action="store_true", help="print how to enable 'modified by' tracking and exit")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    load_env_files()
    if args.audit_setup:
        print(AUDIT_SETUP)
        return 0
    channels = [] if args.notify.strip().lower() == "none" else (
        configured_channels() if args.notify.strip().lower() == "auto" else [c.strip().lower() for c in args.notify.split(",") if c.strip()])
    if args.test_notify:
        return run_test_notify(channels or list(WEBHOOK_VARS))
    if args.full:
        args.include_system_paths = args.cross_filesystems = True
    maybe_elevate(args)
    try:
        os.nice(10)
    except OSError:
        pass
    lock = acquire_lock(args.output_dir)
    if lock is None:
        log.error("Another run is already in progress - exiting.")
        return 3

    started = time.time()
    cloud = args.cloud or detect_cloud()
    log.info("Environment: %s | server: %s", cloud, args.server_name)
    writers, audit_note = load_audit_writers(args.audit_log, args.audit_key)
    roots = list(dict.fromkeys(os.path.realpath(r) for r in args.roots if os.path.isdir(r)))
    if not roots:
        log.error("No valid scan roots found.")
        return 2
    extra = set() if args.include_system_paths else SYSTEM_PATHS
    excludes = {os.path.realpath(x) for x in (DEFAULT_EXCLUDES | set(args.exclude) | extra)}
    excludes.add(os.path.realpath(args.output_dir))

    stats, seen, recs, now = ScanStats(), set(), [], time.time()
    tty = sys.stderr.isatty()
    last_tick = 0.0
    for root in roots:
        log.info("Scanning %s ...", root)
        for path, st in walk_files(root, excludes, not args.cross_filesystems, seen, stats):
            if tty and time.monotonic() - last_tick > 0.4:
                last_tick = time.monotonic()
                sys.stderr.write(f"\r  Scanning {root[-24:]:<24} {stats.files_seen:>10,} checked | {len(recs):>8,} unused ")
            rec = build_record(path, st, now, not args.no_content_scan, args.age_basis, args.min_age, writers)
            if rec:
                recs.append(rec)
                if len(recs) >= args.max_records:
                    stats.truncated = True
                    break
        if stats.truncated:
            break
    if tty:
        sys.stderr.write("\r" + " " * 90 + "\r")

    meta = {"server": args.server_name, "cloud": cloud, "roots": roots, "min_age": args.min_age,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"), "duration_s": round(time.time() - started, 1),
            "files_seen": stats.files_seen, "dirs_seen": stats.dirs_seen, "delete_performed": False,
            "output_dir": os.path.realpath(args.output_dir), "is_root": os.geteuid() == 0, "audit_note": audit_note,
            "audit_count": len(writers),
            "run_as": "root (full access)" if os.geteuid() == 0 else f"{owner_name(os.geteuid())} (NOT root - protected folders hidden)"}
    M = build_model(meta, recs, stats)
    DOC_OPTS["files"] = args.doc_files

    cols = args.width or shutil.get_terminal_size((130, 40)).columns
    W = max(80, min(cols, 190))
    use_color = sys.stdout.isatty() and not os.environ.get("NO_COLOR") and not args.no_color
    print(render_tui(M, Sty(use_color), W, None if args.top == 0 else args.top, None if args.top == 0 else max(args.top, 15)))
    txt = render_tui(M, Sty(False), 150, None)

    saved = save_reports(args.output_dir, M, [f for f in ALL_FORMATS if args.formats == "all" or f in args.formats.split(",")], txt)
    results: Dict[str, str] = {}
    if channels:
        opts = {"full": args.chat_full, "files": args.chat_files, "attention": args.chat_attention,
                "hide_paths": args.hide_sensitive_paths, "max_messages": 0 if args.chat_full and args.chat_max_messages == 40 else args.chat_max_messages}
        results = notify(channels, M, opts)
        kinds = [k.strip().lower() for k in args.attach.split(",") if k.strip()]
        if kinds:
            results.update(send_attachments(channels, kinds, saved, f"{meta['server']} - Linux File Cleanup Report (report only)"))
    print(render_footer(M, Sty(use_color), W, saved, results))
    return 4 if any(v.startswith("FAILED") for v in results.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
