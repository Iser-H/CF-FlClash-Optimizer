# -*- coding: utf-8 -*-
"""Local Clash-client discovery (FlClash / Clash Verge Rev / Mihomo Party).

Every supported GUI keeps its profiles on disk:

* FlClash            %APPDATA%\\com.follow\\clash\\profiles\\<id>.yaml
* Clash Verge Rev    %APPDATA%\\io.github.clash-verge-rev.clash-verge-rev\\profiles\\*.yaml
* Mihomo Party       %APPDATA%\\mihomo-party\\profiles\\*.yaml

The module only *reads* those directories: it never starts, stops or rewrites a
client. Discovery is best-effort so the GUI can still fall back to the manual
"pick any local YAML" path on a machine where nothing is installed yet.
"""

import glob
import os
import re
import sqlite3
from typing import Dict, List, Optional

# key -> human label / process name / default external controller
CLIENTS: Dict[str, dict] = {
    "flclash": {
        "label": "FlClash",
        "process": "FlClash.exe",
        "api": "127.0.0.1:9090",
    },
    "verge": {
        "label": "Clash Verge Rev",
        "process": "clash-verge.exe",
        "api": "127.0.0.1:9097",
    },
    "mihomo": {
        "label": "Mihomo Party",
        "process": "Mihomo Party.exe",
        "api": "127.0.0.1:9090",
    },
    "manual": {
        "label": "手动选择 YAML",
        "process": "",
        "api": "127.0.0.1:9090",
    },
}

CLIENT_LABELS = {key: meta["label"] for key, meta in CLIENTS.items()}


def _appdata() -> str:
    return os.environ.get("APPDATA") or os.path.join(
        os.path.expanduser("~"), "AppData", "Roaming")


def _localappdata() -> str:
    return os.environ.get("LOCALAPPDATA") or os.path.join(
        os.path.expanduser("~"), "AppData", "Local")


def candidate_dirs(flclash_dir: str = "") -> Dict[str, List[str]]:
    """Likely config directories per client, most specific first."""
    roaming, local = _appdata(), _localappdata()
    return {
        "flclash": [p for p in (
            flclash_dir,
            os.path.join(roaming, "com.follow", "clash"),
        ) if p],
        "verge": [
            os.path.join(roaming, "io.github.clash-verge-rev.clash-verge-rev"),
            os.path.join(local, "io.github.clash-verge-rev.clash-verge-rev"),
            os.path.join(roaming, "clash-verge-rev"),
        ],
        "mihomo": [
            os.path.join(roaming, "mihomo-party"),
            os.path.join(roaming, "Mihomo Party"),
            os.path.join(local, "mihomo-party"),
        ],
    }


def _read_head(path: str, limit: int = 262144) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""


def looks_like_profile(path: str) -> bool:
    """A usable mihomo/clash profile must define a proxies list."""
    text = _read_head(path)
    if not text:
        return False
    return bool(re.search(r"^\s*proxies\s*:", text, re.MULTILINE))


def _labels_from_sqlite(directory: str) -> Dict[str, str]:
    """FlClash keeps display labels in database.sqlite -> {id: label}."""
    db = os.path.join(directory, "database.sqlite")
    labels: Dict[str, str] = {}
    if not os.path.exists(db):
        return labels
    try:
        uri = "file:{}?mode=ro".format(db.replace(chr(92), "/"))
        con = sqlite3.connect(uri, uri=True, timeout=2)
        for pid, label in con.execute("select id,label from profiles"):
            labels[str(pid)] = str(label or "")
        con.close()
    except Exception:
        return {}
    return labels


def _profile_entries(directory: str) -> List[dict]:
    """All YAML profiles inside <dir>/profiles (fallback: <dir> itself)."""
    if not directory or not os.path.isdir(directory):
        return []
    labels = _labels_from_sqlite(directory)
    rows: List[dict] = []
    seen = set()
    for base in (os.path.join(directory, "profiles"), directory):
        if not os.path.isdir(base):
            continue
        for pattern in ("*.yaml", "*.yml"):
            for path in glob.glob(os.path.join(base, pattern)):
                if not os.path.isfile(path):
                    continue
                real = os.path.normcase(os.path.abspath(path))
                if real in seen:
                    continue
                seen.add(real)
                if not looks_like_profile(path):
                    continue
                stem = os.path.splitext(os.path.basename(path))[0]
                label = labels.get(stem) or stem
                try:
                    mtime = os.path.getmtime(path)
                except OSError:
                    mtime = 0.0
                rows.append({"label": label, "path": os.path.abspath(path),
                             "mtime": mtime, "dir": os.path.abspath(directory)})
        if rows:
            break
    rows.sort(key=lambda r: r["mtime"], reverse=True)
    return rows


def detect_api(directory: str) -> dict:
    """Read external-controller / secret from a client's generated config."""
    api, secret = "", ""
    for name in ("config.yaml", "verge.yaml", "clash.yaml", "mihomo.yaml"):
        path = os.path.join(directory or "", name)
        if not os.path.isfile(path):
            continue
        text = _read_head(path, 65536)
        m = re.search(r'^\s*external-controller\s*:\s*["\']?([^\s"\']+)',
                      text, re.MULTILINE)
        if m and not api:
            api = m.group(1).strip()
        m = re.search(r'^\s*secret\s*:\s*["\']?([^\s"\']*)', text, re.MULTILINE)
        if m and not secret:
            secret = m.group(1).strip()
    return {"api": api, "secret": secret}


def discover(flclash_dir: str = "") -> List[dict]:
    """Return one row per detected client with its profiles.

    Row: {"key", "label", "dir", "api", "secret", "profiles": [...]}
    Clients whose directory exists but yields no YAML are still reported with
    an empty profile list, so the GUI can say "installed, no profile found".
    """
    found: List[dict] = []
    for key, dirs in candidate_dirs(flclash_dir).items():
        for directory in dirs:
            if not os.path.isdir(directory):
                continue
            profiles = _profile_entries(directory)
            api = detect_api(directory)
            found.append({
                "key": key,
                "label": CLIENTS[key]["label"],
                "dir": os.path.abspath(directory),
                "api": api.get("api") or CLIENTS[key]["api"],
                "secret": api.get("secret", ""),
                "profiles": profiles,
            })
            if profiles:
                break  # first directory with real profiles wins
    return found


def first_profile(flclash_dir: str = "") -> Optional[dict]:
    for client in discover(flclash_dir):
        if client["profiles"]:
            row = dict(client["profiles"][0])
            row["key"] = client["key"]
            row["api"] = client["api"]
            row["secret"] = client["secret"]
            return row
    return None


def normalize_api(url: str) -> str:
    """'http://127.0.0.1:9090/' -> '127.0.0.1:9090' (ClashAPI wants host:port)."""
    text = (url or "").strip()
    text = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", text)
    return text.rstrip("/")


def restart_hint(client_key: str) -> str:
    return CLIENTS.get(client_key, {}).get("process", "")
