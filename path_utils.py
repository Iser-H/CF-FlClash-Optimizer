# -*- coding: utf-8 -*-
"""Path utilities - works both in dev and PyInstaller frozen mode."""

import hashlib
import json
import os
import shutil
import sqlite3
import sys
import time
from typing import Optional


def get_app_root() -> str:
    """Return the application root directory."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def get_app_dir() -> str:
    """Alias of get_app_root(): the directory holding the exe (or the sources).

    The autostart entry is created by explorer.exe, whose working directory is
    %SystemRoot%\\System32; every relative path (config.json, bin\\cfst.exe,
    exports\\) must be resolved against this directory instead.
    """
    return get_app_root()


def ensure_app_cwd() -> str:
    """Force the process working directory to the application directory.

    Returns the application directory. Never raises: a locked/inaccessible
    directory keeps the previous working directory so the app still starts.
    """
    root = get_app_root()
    try:
        if os.path.isdir(root):
            os.chdir(root)
    except OSError:
        pass
    return root


def get_desktop_dir() -> str:
    """Get the true user Desktop directory from Windows registry."""
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
        path, _ = winreg.QueryValueEx(key, "Desktop")
        path = os.path.expandvars(path)
        if os.path.exists(path):
            return path
    except Exception:
        pass
    fallback = os.path.join(os.path.expanduser("~"), "Desktop")
    if not os.path.exists(fallback) and os.path.exists(r"E:\desktop"):
        return r"E:\desktop"
    return fallback


APP_ROOT = get_app_root()
APP_NAME = "CF-FlClash-Optimizer"
DATA_DIR_ENV = "CFFO_DATA_DIR"           # test/portable override (absolute path)
MIGRATION_MARKER = ".data-migration-v13.json"

# Folders that may hold a previous portable install next to the program folder.
# `release_v1.2` is listed before `dist` on purpose: it holds the newest known
# good user config, the older dist folder is only a fallback.
LEGACY_DIR_NAMES = ("release_v1.2", "dist", "release_v1.1",
                    "CF-FlClash-Optimizer-v1.2", "CF-FlClash-Optimizer")


def _is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def _is_writable_dir(path: str) -> bool:
    try:
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, f".cffo-write-test-{os.getpid()}")
        with open(probe, "w", encoding="utf-8") as handle:
            handle.write("ok")
        os.unlink(probe)
        return True
    except OSError:
        return False


def get_data_root() -> str:
    """Fixed per-user data directory.

    The shipped EXE always keeps user data in ``%APPDATA%\\CF-FlClash-Optimizer``
    so moving / replacing the EXE never loses the configuration again.  Running
    from sources with a local ``config.json`` keeps the portable layout (that is
    what the test-suite expects), and ``CFFO_DATA_DIR`` overrides both.
    """
    override = str(os.environ.get(DATA_DIR_ENV) or "").strip()
    if override:
        return os.path.abspath(override)
    appdata = str(os.environ.get("APPDATA") or "").strip() or os.path.expanduser("~")
    fixed = os.path.join(appdata, APP_NAME)
    if not _is_frozen() and os.path.isfile(os.path.join(APP_ROOT, "config.json")):
        return APP_ROOT
    if _is_writable_dir(fixed):
        return fixed
    return APP_ROOT


DATA_ROOT = get_data_root()
BIN_DIR = os.path.join(DATA_ROOT, "bin")
BACKUPS_DIR = os.path.join(DATA_ROOT, "backups")
EXPORTS_DIR = os.path.join(DATA_ROOT, "exports")
CONFIG_FILE = os.path.join(DATA_ROOT, "config.json")
IP_TXT = os.path.join(BIN_DIR, "ip.txt")


def _frozen_exe_dir() -> str:
    """Directory of the running EXE (PyInstaller onefile: not ``_MEIPASS``)."""
    exe = str(getattr(sys, "executable", "") or "")
    if not exe:
        return APP_ROOT
    try:
        return os.path.dirname(os.path.abspath(exe))
    except OSError:
        return APP_ROOT


def cfst_lookup_paths(frozen: Optional[bool] = None, exe_dir: Optional[str] = None,
                      data_bin: Optional[str] = None) -> list:
    """Ordered ``cfst.exe`` candidates.

    In a frozen onefile build the binary shipped next to the EXE
    (``<exe dir>\\bin\\cfst.exe``) wins: the unpacked ``sys._MEIPASS`` folder is a
    throw-away temp directory and must never be the primary source for an
    external helper.  The writable data folder is the fallback (and the first
    choice when running from sources).
    """
    is_frozen = _is_frozen() if frozen is None else bool(frozen)
    base = os.path.abspath(exe_dir or (_frozen_exe_dir() if is_frozen else APP_ROOT))
    user_bin = os.path.abspath(data_bin or BIN_DIR)
    ordered = (
        [os.path.join(base, "bin", "cfst.exe"), os.path.join(user_bin, "cfst.exe")]
        if is_frozen else
        [os.path.join(user_bin, "cfst.exe"), os.path.join(base, "bin", "cfst.exe")]
    )
    paths, seen = [], set()
    for path in ordered:
        key = os.path.normcase(path)
        if key in seen:
            continue
        seen.add(key)
        paths.append(path)
    return paths


def cfst_candidates() -> list:
    """Backwards-compatible alias of :func:`cfst_lookup_paths`."""
    return cfst_lookup_paths()


def resolve_cfst_exe(frozen: Optional[bool] = None, exe_dir: Optional[str] = None,
                     data_bin: Optional[str] = None) -> str:
    """Absolute path of the speed-test core (first existing candidate)."""
    paths = cfst_lookup_paths(frozen=frozen, exe_dir=exe_dir, data_bin=data_bin)
    for path in paths:
        try:
            if os.path.isfile(path) and os.path.getsize(path) > 0:
                return path
        except OSError:
            continue
    return paths[0]


def cfst_diagnostics(frozen: Optional[bool] = None, exe_dir: Optional[str] = None,
                     data_bin: Optional[str] = None) -> dict:
    """What the program will use, where it looked, and whether it is there."""
    paths = cfst_lookup_paths(frozen=frozen, exe_dir=exe_dir, data_bin=data_bin)
    chosen = resolve_cfst_exe(frozen=frozen, exe_dir=exe_dir, data_bin=data_bin)
    candidates = []
    for path in paths:
        exists = os.path.isfile(path)
        try:
            size = os.path.getsize(path) if exists else 0
        except OSError:
            size = 0
        candidates.append({"path": path, "exists": exists, "size": size})
    exists = os.path.isfile(chosen)
    try:
        size = os.path.getsize(chosen) if exists else 0
    except OSError:
        size = 0
    return {"frozen": _is_frozen() if frozen is None else bool(frozen),
            "chosen": chosen, "exists": exists, "size": size,
            "candidates": candidates}


CFST_EXE = resolve_cfst_exe()


def ip_list_lookup(frozen: Optional[bool] = None, exe_dir: Optional[str] = None,
                   data_bin: Optional[str] = None) -> list:
    """Ordered ``ip.txt`` candidates (shipped package first when frozen)."""
    is_frozen = _is_frozen() if frozen is None else bool(frozen)
    base = os.path.abspath(exe_dir or (_frozen_exe_dir() if is_frozen else APP_ROOT))
    user_bin = os.path.abspath(data_bin or BIN_DIR)
    ordered = (
        [os.path.join(base, "bin", "ip.txt"), os.path.join(user_bin, "ip.txt")]
        if is_frozen else
        [os.path.join(user_bin, "ip.txt"), os.path.join(base, "bin", "ip.txt")]
    )
    result, seen = [], set()
    for path in ordered:
        key = os.path.normcase(path)
        if key in seen:
            continue
        seen.add(key)
        result.append(path)
    return result


_BUILTIN_CF_IPV4_CIDRS = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
)


def write_builtin_ip_list(path: str) -> bool:
    """Write the built-in official Cloudflare IPv4 CIDR list (fallback)."""
    lines: list = []
    try:
        import cidr_pool
        lines = [str(item) for item in
                 (getattr(cidr_pool, "OFFICIAL_CF_IPV4_CIDRS", []) or [])]
    except Exception:
        lines = []
    if not lines:
        lines = list(_BUILTIN_CF_IPV4_CIDRS)
    text = "# Cloudflare IPv4 CIDR list (built-in fallback)\n" + "\n".join(lines) + "\n"
    try:
        from storage_utils import atomic_write_text
        atomic_write_text(path, text)
        return True
    except Exception:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
            return True
        except OSError:
            return False


def resolve_ip_list_file(create: bool = True, frozen: Optional[bool] = None,
                         exe_dir: Optional[str] = None,
                         data_bin: Optional[str] = None) -> dict:
    """Locate ``ip.txt`` for cfst, generating a built-in fallback when missing.

    Returns ``{"path", "source", "exists", "generated"}`` where source is one of
    ``package`` / ``data`` / ``generated`` / ``missing``.
    """
    paths = ip_list_lookup(frozen=frozen, exe_dir=exe_dir, data_bin=data_bin)
    is_frozen = _is_frozen() if frozen is None else bool(frozen)
    base = os.path.abspath(exe_dir or (_frozen_exe_dir() if is_frozen else APP_ROOT))
    package_path = os.path.join(base, "bin", "ip.txt")
    for path in paths:
        try:
            if os.path.isfile(path) and os.path.getsize(path) > 0:
                source = "package" if os.path.normcase(path) == os.path.normcase(package_path) else "data"
                return {"path": path, "source": source, "exists": True, "generated": False}
        except OSError:
            continue
    target = paths[0] if is_frozen else paths[0]
    # Fallback is always written to the writable data bin, never into the package.
    target = os.path.join(os.path.abspath(data_bin or BIN_DIR), "ip.txt")
    made = write_builtin_ip_list(target) if create else False
    return {"path": target, "source": "generated" if made else "missing",
            "exists": os.path.isfile(target), "generated": made}

# Desktop export directory
DESKTOP_DIR = get_desktop_dir()
DESKTOP_EXPORT_DIR = os.path.join(DESKTOP_DIR, "CF导出配置")

# Ensure directories exist
for d in [BIN_DIR, BACKUPS_DIR, EXPORTS_DIR]:
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass


def clash_config_dir_for(profile_path: str) -> str:
    """Directory that contains FlClash's ``profiles/`` + ``database.sqlite``.

    The GUI stores ``dirname(profile.yaml)`` which is the ``profiles`` subfolder;
    profile lookup by name needs the parent folder, so normalise it here.
    """
    path = str(profile_path or "").strip()
    if not path:
        return ""
    folder = os.path.dirname(os.path.abspath(path))
    if os.path.basename(folder).lower() == "profiles":
        parent = os.path.dirname(folder)
        if os.path.isdir(os.path.join(parent, "profiles")):
            return parent
    return folder


def legacy_data_roots() -> list:
    """Candidate previous installs, newest known-good first.

    Covers both layouts seen in the wild: the old folders *inside* the project
    directory (``<project>\\release_v1.2``) and *beside* the program folder
    (``<parent>\\release_v1.2`` when the EXE sits in its own version folder).
    """
    parent = os.path.dirname(APP_ROOT.rstrip("\\/")) or APP_ROOT
    roots = []
    for name in LEGACY_DIR_NAMES:
        roots.append(os.path.join(APP_ROOT, name))
    for name in LEGACY_DIR_NAMES:
        roots.append(os.path.join(parent, name))
    roots.append(APP_ROOT)
    seen = set()
    result = []
    for root in roots:
        if not root:
            continue
        key = os.path.normcase(os.path.abspath(root))
        if key in seen:
            continue
        seen.add(key)
        result.append(os.path.abspath(root))
    return result


def read_config_file(path: str):
    """Parsed config dict, or None when the file is missing/broken/empty."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) and data else None
    except Exception:
        return None


def _copy_missing(src: str, dst: str, copied: dict) -> int:
    """Copy a file or a directory tree without ever overwriting existing files."""
    count = 0
    if os.path.isfile(src):
        if os.path.exists(dst):
            return 0
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            return 1
        except OSError:
            return 0
    if not os.path.isdir(src):
        return 0
    for base, _dirs, files in os.walk(src):
        rel = os.path.relpath(base, src)
        for name in files:
            source = os.path.join(base, name)
            target = os.path.join(dst, rel, name) if rel != "." else os.path.join(dst, name)
            if os.path.exists(target):
                continue
            try:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                shutil.copy2(source, target)
                count += 1
            except OSError:
                continue
    return count


def ensure_user_data(migrate: bool = True, data_root: Optional[str] = None,
                     legacy_roots: Optional[list] = None) -> dict:
    """Create the data folders and (once) migrate a previous install.

    Guarantees:
    * an existing valid ``CONFIG_FILE`` is never overwritten;
    * the source config is copied into ``backups/migration-<ts>/`` first;
    * everything else is copied, never moved; no source file is deleted;
    * returns a report the GUI can log (paths only, never secret values).

    ``data_root`` / ``legacy_roots`` exist so the migration can be tested on
    throw-away folders without touching the real user profile.
    """
    root = os.path.abspath(data_root or DATA_ROOT)
    bin_dir = os.path.join(root, "bin")
    backups_dir = os.path.join(root, "backups")
    exports_dir = os.path.join(root, "exports")
    config_file = os.path.join(root, "config.json")
    report = {"data_root": root, "status": "existing", "config_source": "",
              "backup_dir": "", "copied": {}, "warnings": []}
    for folder in (root, bin_dir, backups_dir, exports_dir):
        try:
            os.makedirs(folder, exist_ok=True)
        except OSError as exc:
            report["warnings"].append(f"创建目录失败 {folder}: {exc}")

    if os.path.isfile(config_file) and read_config_file(config_file):
        return report
    if not migrate:
        report["status"] = "fresh"
        return report

    source_root = ""
    source_path = ""
    source_data = None
    for candidate_root in (legacy_roots if legacy_roots is not None else legacy_data_roots()):
        candidate_root = os.path.abspath(str(candidate_root))
        if os.path.normcase(candidate_root) == os.path.normcase(root):
            continue
        candidate = os.path.join(candidate_root, "config.json")
        data = read_config_file(candidate)
        if data:
            source_root, source_path, source_data = candidate_root, candidate, data
            break
    if source_data is None:
        report["status"] = "fresh"
        return report

    stamp = time.strftime("%Y%m%d_%H%M%S")
    backup_dir = os.path.join(backups_dir, f"migration-{stamp}")
    try:
        os.makedirs(backup_dir, exist_ok=True)
        shutil.copy2(source_path, os.path.join(backup_dir, "config.json"))
        report["backup_dir"] = backup_dir
    except OSError as exc:
        report["warnings"].append(f"备份迁移来源失败: {exc}")

    # Keep the profile lookup folder consistent with the real FlClash layout.
    try:
        fixed_dir = clash_config_dir_for(str(source_data.get("flclash_profile_path") or ""))
        if fixed_dir:
            source_data["flclash_config_dir"] = fixed_dir
    except Exception:
        pass

    try:
        from storage_utils import atomic_write_text
        atomic_write_text(
            config_file,
            json.dumps(source_data, ensure_ascii=False, indent=2) + "\n")
    except Exception as exc:
        report["warnings"].append(f"写入新配置失败，继续使用旧目录: {exc}")
        report["status"] = "failed"
        return report

    copied = {}
    for name, target in (("backups", backups_dir), ("exports", exports_dir),
                         ("bin", bin_dir)):
        n = _copy_missing(os.path.join(source_root, name), target, copied)
        if n:
            copied[name] = n
    cidr_src = os.path.join(source_root, "cidr_score_history.json")
    if os.path.isfile(cidr_src):
        n = _copy_missing(cidr_src, os.path.join(root, "cidr_score_history.json"), copied)
        if n:
            copied["cidr_score_history.json"] = n
    report.update(status="migrated", config_source=source_path, copied=copied)

    try:
        from storage_utils import atomic_write_text
        marker = dict(report)
        marker["migrated_at"] = stamp
        atomic_write_text(os.path.join(root, MIGRATION_MARKER),
                          json.dumps(marker, ensure_ascii=False, indent=2) + "\n")
    except Exception:
        pass
    return report


def _normalise_profile_dirs(cfg: dict) -> dict:
    """Keep ``flclash_config_dir`` at the folder holding profiles/ + database.sqlite.

    Older builds stored ``dirname(profile.yaml)`` (the ``profiles`` subfolder),
    which made profile lookup by display name silently fail.
    """
    try:
        profile = str(cfg.get("flclash_profile_path") or "").strip()
        if not profile:
            return cfg
        current = str(cfg.get("flclash_config_dir") or "").strip()
        profile_dir = os.path.dirname(os.path.abspath(profile))
        if not current or os.path.normcase(os.path.abspath(current)) == os.path.normcase(profile_dir):
            cfg["flclash_config_dir"] = clash_config_dir_for(profile)
    except Exception:
        pass
    return cfg


def load_config() -> dict:
    """Load config.json, creating defaults if missing."""
    defaults = {
        # Left empty on purpose: a fresh checkout discovers the local client
        # (FlClash / Clash Verge Rev / Mihomo Party) at first start instead of
        # shipping somebody else's absolute path.
        "client_type": "auto",
        "flclash_profile_path": "",
        "flclash_config_dir": "",
        "mixed_port": 7890,
        "external_controller": "127.0.0.1:9090",
        "secret": "",
        "cf_node_names": [
            "\u7f8e\u56fd \u6d1b\u6749\u77f6-CF\u4f18\u90091",
            "\u7f8e\u56fd \u6d1b\u6749\u77f6-CF\u4f18\u90092",
            "\u7f8e\u56fd \u6d1b\u6749\u77f6-CF\u4f18\u90093",
        ],
        "cf_node_name_prefix": "\U0001f1fa\U0001f1f8 \u6d1b\u6749\u77f6-CF\u4f18\u9009",
        "cfst_threads": 200,
        "cfst_tl": 400,
        "cfst_sl": 5.0,
        "cfst_dn": 10,
        "cfst_url": "",
        "lan_server_port": 8686,
        # LAN sharing is opt-in for a fresh install. An existing config.json
        # that explicitly stores True keeps working, but now always requires
        # the token below.
        "lan_server_enabled": False,
        "lan_bind_host": "auto",
        "lan_auth_token": "",
        "lan_firewall_remote": "LocalSubnet",
        "lan_port_fallback": 10,
        "airport_profile_name": "",
        "airport_profile_path": "",
        "airport_exclude_paths": [],
        "airport_managed_nodes": [],
        "airport_exclude_keywords": ["\u6d41\u91cf", "\u5230\u671f", "\u91cd\u7f6e", "\u5b98\u7f51", "\u5269\u4f59", "\u5957\u9910"],
        "airport_us_keywords": ["united states", "\u7f8e\u56fd", "\u7f8e\u897f", "los angeles", "\u6d1b\u6749\u77f6"],
        "airport_max_nodes": 80,
        "chain_landing_node_name": "",
        # v1.2+ option, persisted so a fresh install already shows it.
        "direct_landing_node_name": "\U0001f1fa\U0001f1f8 \u6d1b\u6749\u77f6-VPS-\u76f4\u8fde(AI)",
        # v1.3.1: optional manual dialer-proxy entry for the AI chain node.
        # "" = automatic (airport front group), else an airport node / group name.
        "chain_entry_node": "",
        "auto_airport_group_name": "\u26a1 \u673a\u573a\u81ea\u52a8\u4f18\u9009",
        "excluded_node_names": ["CF-\u4fdd\u5e95"],
        "obsolete_group_names": ["\u81ea\u52a8\uff08\u76f4\u8fde\u4f18\u5148\uff09", "\U0001f1fa\U0001f1f8 \u6d1b\u6749\u77f6-CF\u4f18\u9009"],
        "auto_guard_enabled": False,
        "auto_guard_interval_min": 30,
        "auto_guard_max_loss": 5.0,
        "cidr_score_file": "cidr_score_history.json",
        "cidr_sample_size": 2000,
        "cidr_exploit_ratio": 0.7,
        "cidr_top_subnets": 40,
        # Startup / tray behaviour (persisted by the GUI).
        "auto_start_enabled": False,
        "close_to_tray": True,
        "start_minimized": False,
    }
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            for k, v in defaults.items():
                data.setdefault(k, v)
            _normalise_profile_dirs(data)
            return data
        except Exception:
            pass
    save_config(defaults)
    return defaults


def save_config(cfg: dict):
    """Save config.json atomically (UTF-8, no BOM)."""
    from storage_utils import atomic_write_text
    atomic_write_text(CONFIG_FILE, json.dumps(cfg, ensure_ascii=False, indent=2) + "\n")


# ---------------------------------------------------------------------------
# Windows autostart (HKCU\Software\Microsoft\Windows\CurrentVersion\Run)
#
# HKCU is per-user writable, so the entry can be created/removed without any
# administrator rights and without touching machine-wide policy. The value is
# the command line explorer.exe launches at logon.
# ---------------------------------------------------------------------------
AUTO_START_KEY_NAME = "CF-FlClash-Optimizer"
AUTO_START_REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"

_MAIN_SCRIPT = "main_gui.py"


def _python_gui_exe() -> str:
    """pythonw.exe (no console window) when present, else python.exe."""
    exe = os.path.abspath(sys.executable or "python")
    if getattr(sys, "frozen", False):
        return exe
    candidate = os.path.join(os.path.dirname(exe), "pythonw.exe")
    if os.path.exists(candidate):
        return os.path.abspath(candidate)
    return exe


def build_auto_start_command(minimized: bool = True) -> str:
    """Build the HKCU Run value for this program.

    Frozen exe : "<abs exe>" --minimized
    Source run : "<pythonw.exe>" "<abs main_gui.py>" --minimized
    """
    suffix = " --minimized" if minimized else ""
    if getattr(sys, "frozen", False):
        return f'"{os.path.abspath(sys.executable)}"{suffix}'
    script = os.path.abspath(os.path.join(get_app_dir(), _MAIN_SCRIPT))
    return f'"{_python_gui_exe()}" "{script}"{suffix}'


def _split_command(command: str) -> list:
    """Split a Run-key command line on spaces, honouring double quotes."""
    tokens, current, in_quotes = [], "", False
    for ch in (command or "").strip():
        if ch == '"':
            in_quotes = not in_quotes
            if not in_quotes and current:
                tokens.append(current)
                current = ""
            continue
        if ch == " " and not in_quotes:
            if current:
                tokens.append(current)
                current = ""
            continue
        current += ch
    if current:
        tokens.append(current)
    return tokens


def _run_signature(command: str) -> list:
    """Executable / script tokens of a Run command (flags removed)."""
    return [t for t in _split_command(command) if not t.startswith("-")]


def _norm_token(token: str) -> str:
    return os.path.normcase(os.path.normpath(token))


def get_auto_start_command() -> str:
    """Read the raw HKCU Run value ('' when absent or on non-Windows)."""
    try:
        import winreg
    except ImportError:
        return ""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTO_START_REG_PATH) as key:
            value, _type = winreg.QueryValueEx(key, AUTO_START_KEY_NAME)
            return str(value or "")
    except OSError:
        return ""


def is_auto_start_enabled() -> bool:
    """True only when the Run value points at *this* program (exe/script match)."""
    stored = _run_signature(get_auto_start_command())
    if not stored:
        return False
    expected = _run_signature(build_auto_start_command(True))
    if not expected:
        return False
    return [_norm_token(t) for t in stored[:len(expected)]] == \
           [_norm_token(t) for t in expected]


def set_auto_start(enabled: bool, minimized: bool = True) -> tuple:
    """Enable/disable the HKCU Run entry. Returns (ok, human message)."""
    try:
        import winreg
    except ImportError:
        return False, "当前平台不支持 winreg（仅 Windows）"
    try:
        with winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER, AUTO_START_REG_PATH, 0,
                winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
            if enabled:
                command = build_auto_start_command(minimized)
                winreg.SetValueEx(key, AUTO_START_KEY_NAME, 0, winreg.REG_SZ, command)
                stored, _type = winreg.QueryValueEx(key, AUTO_START_KEY_NAME)
                if str(stored or "") != command:
                    return False, "注册表写入校验失败（读回值不一致）"
                return True, f"开机自启已开启: {command}"
            try:
                winreg.DeleteValue(key, AUTO_START_KEY_NAME)
            except FileNotFoundError:
                pass  # already absent == success
            return True, "开机自启已关闭（注册表项已移除）"
    except OSError as exc:
        return False, f"注册表操作失败: {exc}"


# ---------------------------------------------------------------------------
# FlClash profile metadata resolution (display name -> YAML path)
# ---------------------------------------------------------------------------
def default_flclash_config_dir() -> str:
    return os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "com.follow", "clash")


def _read_current_profile_id(config_dir: str):
    try:
        with open(os.path.join(config_dir, "shared_preferences.json"), "r", encoding="utf-8") as f:
            sp = json.load(f)
        raw = sp.get("flutter.config", "{}")
        cfg = json.loads(raw) if isinstance(raw, str) else raw
        return int(cfg.get("currentProfileId") or 0)
    except Exception:
        return 0


def list_flclash_profiles(config_dir: str = "") -> list:
    """Return [{id,label,url,path,current,last_update_date}] from FlClash metadata."""
    config_dir = config_dir or default_flclash_config_dir()
    db_path = os.path.join(config_dir, "database.sqlite")
    profiles_dir = os.path.join(config_dir, "profiles")
    current_id = _read_current_profile_id(config_dir)
    rows = []
    if os.path.exists(db_path):
        try:
            uri = f"file:{db_path.replace(chr(92), '/')}?mode=ro"
            con = sqlite3.connect(uri, uri=True, timeout=3)
            con.row_factory = sqlite3.Row
            for row in con.execute(
                    "select id,label,url,last_update_date from profiles order by id"):
                item = dict(row)
                item["path"] = os.path.join(profiles_dir, f"{item['id']}.yaml")
                item["current"] = int(item.get("id") or 0) == current_id
                rows.append(item)
            con.close()
        except Exception:
            rows = []
    # Fallback: no DB rows -> list YAML files only (labels unknown).
    if not rows and os.path.isdir(profiles_dir):
        for name in sorted(os.listdir(profiles_dir)):
            if not name.lower().endswith(".yaml") or ".bak" in name.lower():
                continue
            stem = os.path.splitext(name)[0]
            try:
                pid = int(stem)
            except ValueError:
                pid = 0
            rows.append({"id": pid, "label": "", "url": "",
                         "path": os.path.join(profiles_dir, name),
                         "current": pid == current_id, "last_update_date": 0})
    for item in rows:
        if not os.path.exists(item.get("path", "")):
            # tolerate id-name variants such as <id>-<slug>.yaml
            if os.path.isdir(profiles_dir):
                for name in os.listdir(profiles_dir):
                    if name.lower().startswith(str(item.get("id"))) and name.lower().endswith(".yaml"):
                        item["path"] = os.path.join(profiles_dir, name)
                        break
    return rows


def resolve_flclash_profile_by_label(label: str, config_dir: str = "") -> dict:
    """Resolve a FlClash profile display name (case-insensitive) to its YAML path.

    Returns {id,label,url,path,current,last_update_date} or {} when not found.
    """
    label = (label or "").strip().lower()
    if not label:
        return {}
    for item in list_flclash_profiles(config_dir):
        if str(item.get("label", "")).strip().lower() == label and os.path.exists(item.get("path", "")):
            return item
    return {}


def _profile_first_nodes(path: str, limit: int = 10) -> list:
    try:
        from ruamel.yaml import YAML
        with open(path, "r", encoding="utf-8") as f:
            data = YAML(typ="rt").load(f)
        proxies = data.get("proxies") or []
        return [str(p.get("name", "")) for p in proxies[:limit] if isinstance(p, dict)]
    except Exception:
        return []


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    info_dir = sys.argv[2] if len(sys.argv) > 2 else ""
    print("FlClash 配置目录:", info_dir or default_flclash_config_dir())
    print("=" * 70)
    for item in list_flclash_profiles(info_dir):
        first = _profile_first_nodes(item["path"]) if os.path.exists(item["path"]) else []
        print(f"id={item['id']} label={item['label']!r} current={item['current']}")
        print(f"  path: {item['path']}")
        print(f"  nodes({len(first)}): {', '.join(first)}")
    print("=" * 70)
    resolved = resolve_flclash_profile_by_label(target, info_dir)
    if resolved:
        print(f"按名称 {target!r} 解析成功: {resolved['path']}")
        print("前10个节点:", _profile_first_nodes(resolved["path"]))
    else:
        print(f"按名称 {target!r} 未找到配置")
