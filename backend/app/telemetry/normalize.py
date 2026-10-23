"""Module-independent normalization of event features.

Raw sensor payloads are untrusted.  Normalization turns them into a small,
bounded vocabulary that the correlation engine can compare fairly:

* SSH commands become ``category:tool`` action tokens.
* HTTP paths become templates with identifiers removed.
* User agents become a sorted set of product tokens.

The output is deterministic: the same input always produces the same tokens.
That property is required for reproducible experiments.
"""

from __future__ import annotations

import hashlib
import re
import shlex
from typing import Any, Iterable

from ..schemas.event import EventIn

MAX_TOKENS = 400

# Command -> behavioural category.  Ordered by specificity; first match wins.
CATEGORY_RULES: tuple[tuple[str, frozenset[str]], ...] = (
    ("mining", frozenset({"xmrig", "minerd", "cpuminer", "stratum", "nicehash"})),
    ("persistence", frozenset({"crontab", "systemctl", "service", "rc-update", "update-rc.d", "schtasks", "launchctl"})),
    ("credential", frozenset({"ssh-keygen", "ssh-copy-id", "passwd", "chpasswd", "hydra", "medusa", "mimikatz", "john", "hashcat"})),
    ("lateral", frozenset({"nmap", "masscan", "nc", "ncat", "netcat", "socat", "psexec", "smbclient", "redis-cli", "mysql"})),
    ("download", frozenset({"curl", "wget", "tftp", "ftp", "scp", "rsync", "git"})),
    ("privilege", frozenset({"sudo", "su", "pkexec", "setcap", "chmod", "chown"})),
    ("cleanup", frozenset({"shred", "wipe", "unset", "history"})),
    ("recon", frozenset({
        "whoami", "id", "uname", "hostname", "ifconfig", "ip", "netstat", "ss", "ps",
        "top", "free", "df", "ls", "cat", "find", "grep", "awk", "sed", "head", "tail",
        "lscpu", "lsblk", "mount", "env", "printenv", "systeminfo", "tasklist",
        "nslookup", "dig", "ping", "traceroute", "dpkg", "rpm", "apt", "yum",
    })),
    ("execution", frozenset({"bash", "sh", "python", "python3", "perl", "php", "node", "ruby"})),
    ("destruction", frozenset({"rm", "dd", "mkfs", "shutdown", "reboot", "kill"})),
)

_SHELL_META_RE = re.compile(r"[;&|`$<>]")
_HASH_LIKE_RE = re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE)
_TMP_PATH_RE = re.compile(r"/(tmp|var/tmp|dev/shm)/[^\s]+")
_UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)
_HEX_RE = re.compile(r"\b[0-9a-f]{8,}\b", re.IGNORECASE)
_INT_RE = re.compile(r"\b\d+\b")
_USERINFO_RE = re.compile(r"[^@\s]+@[^:\s]+")


def categorize_command(command: str) -> str:
    lowered = command.lower()
    first = _base_commands(lowered)
    for category, names in CATEGORY_RULES:
        if first & names:
            return category
    for category, names in CATEGORY_RULES:
        if any(name in lowered for name in names):
            return category
    return "other"


def _base_commands(lowered: str) -> set[str]:
    """Extract command names, skipping wrappers and assignments."""
    tokens = re.split(r"[\s;&|><]+", lowered)
    names: set[str] = set()
    skip_next = False
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        if not token:
            continue
        if token in {"sudo", "env", "nohup", "timeout", "setsid", "busybox"}:
            continue
        if token.startswith("-") or "=" in token:
            if token in {"-c", "-m", "-u"}:
                skip_next = False
            continue
        names.add(token.rsplit("/", 1)[-1])
        break
    return names


def command_action(command: str) -> str:
    category = categorize_command(command)
    names = _base_commands(command.lower())
    tool = sorted(names)[0] if names else "unknown"
    tool = re.sub(r"[^a-z0-9_.-]", "", tool)[:32] or "unknown"
    return f"{category}:{tool}"


def normalize_command(command: str) -> tuple[str, str]:
    """Return (category, action token) for an attacker-supplied command."""
    cleaned = command.strip().replace("\x00", "")[:2000]
    return categorize_command(cleaned), command_action(cleaned)


def _split_command(command: str) -> list[str]:
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        parts = command.split()
    return [part for part in parts if part][:64]


def command_shape(command: str) -> str:
    """A path-and-argument-normalized shape used for explanation, not scoring."""
    parts = _split_command(command)
    shaped = []
    for part in parts:
        if part.startswith("/") or part.startswith("./"):
            part = "/" + part.rsplit("/", 1)[-1]
        part = _HASH_LIKE_RE.sub("{hash}", part)
        part = _INT_RE.sub("{n}", part)
        shaped.append(part[:64])
    return " ".join(shaped)[:300]


def normalize_path_template(path: str) -> str:
    """Collapse identifiers in a URL path so different scans share a template."""
    raw = (path or "/").split("?", 1)[0].split("#", 1)[0]
    raw = raw.lower()[:500] or "/"
    raw = _TMP_PATH_RE.sub("/{tmp}", raw)
    raw = _UUID_RE.sub("{uuid}", raw)
    raw = _HEX_RE.sub("{hex}", raw)
    raw = _INT_RE.sub("{n}", raw)
    raw = re.sub(r"/+", "/", raw)
    segments = [segment for segment in raw.split("/") if segment][:8]
    return "/" + "/".join(segments) if segments else "/"


def normalize_user_agents(agents: Iterable[str]) -> list[str]:
    tokens: set[str] = set()
    for agent in agents:
        if not agent:
            continue
        for product in re.findall(r"[A-Za-z][A-Za-z0-9_.-]{1,24}", agent[:400]):
            lowered = product.lower()
            if lowered in {"mozilla", "compatible", "http", "https"}:
                continue
            tokens.add(lowered)
    return sorted(tokens)[:24]


def normalize_usernames(usernames: Iterable[str]) -> list[str]:
    result: set[str] = set()
    for name in usernames:
        cleaned = (name or "").strip().lower()[:64]
        if not cleaned:
            continue
        cleaned = _USERINFO_RE.sub("{user}", cleaned)
        result.add(re.sub(r"[^a-z0-9_.@-]", "", cleaned) or "unknown")
    return sorted(result)[:50]


def feature_digest(features: dict[str, Any]) -> str:
    import json

    encoded = json.dumps(features, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def normalize_event(event: EventIn) -> dict[str, Any]:
    """Derive canonical features for an event, preserving the original values."""
    features = dict(event.features or {})
    module = event.source_module
    normalized: dict[str, Any] = {
        "module": module,
        "event_type": event.event_type,
    }

    if module == "honeypot" and event.event_type.startswith("honeypot.ssh"):
        success = bool(features.get("success", event.event_type.endswith("login_success")))
        username = str(features.get("username", ""))
        command = str(features.get("command", ""))
        category, action = normalize_command(command) if command else ("auth", "auth:login")
        normalized.update(
            {
                "action": action,
                "category": category,
                "command_shape": command_shape(command) if command else "",
                "username": username.lower()[:64],
                "success": success,
                "client": str(features.get("client_version", ""))[:120],
                "auth_attempt": event.event_type.endswith(("login", "login_failed", "login_success")),
            }
        )
        if command:
            normalized["command_length"] = len(command)

    elif module == "honeypot" and event.event_type == "honeypot.http.credential_attempt":
        normalized.update(
            {
                "action": "http:credential_attempt",
                "category": "credential",
                "username": str(features.get("username", "")).lower()[:64],
                "success": False,
                "auth_attempt": True,
                "password_sha256_prefix": str(features.get("password_sha256_prefix", ""))[:16],
                "password_length": _safe_int(features.get("password_length")) or 0,
            }
        )

    elif module == "honeypot" and event.event_type.startswith("honeypot.http"):
        method = str(features.get("method", "GET")).upper()[:8]
        path = str(features.get("path", "/"))
        template = normalize_path_template(path)
        status = _safe_int(features.get("status"))
        normalized.update(
            {
                "method": method,
                "path_template": template,
                "status": status,
                "action": f"http:{method.lower()}:{template}",
                "category": "http_probe",
                "user_agent": str(features.get("user_agent", ""))[:300],
                "body_size": _safe_int(features.get("body_size")) or 0,
            }
        )
        for flag in (
            "probe",
            "sensitive_probe",
            "login_attempt",
            "throttled",
            "profile",
            "investigation_id",
        ):
            if flag in features:
                normalized[flag] = features[flag]

    elif module == "websec":
        normalized.update(
            {
                "action": f"websec:{features.get('check_id', 'unknown')}"[:120],
                "category": "web_finding",
                "check_id": str(features.get("check_id", "unknown"))[:64],
                "confidence_label": str(features.get("confidence", "medium"))[:16],
            }
        )

    elif module == "cryptointel":
        normalized.update(
            {
                "action": f"crypto:{features.get('indicator', 'observation')}"[:120],
                "category": "asset_risk",
                "asset_symbol": str(features.get("asset_symbol", ""))[:32].upper(),
            }
        )

    elif module == "app":
        normalized.update(
            {
                "action": f"app:{features.get('action', event.event_type)}"[:120],
                "category": "application",
                "username": str(features.get("username", "")).lower()[:64],
                "outcome": str(features.get("outcome", ""))[:32],
            }
        )

    normalized["raw_indicators"] = list(event.provenance.indicators)
    return normalized


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def canonical_json(value: Any) -> str:
    import json

    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
