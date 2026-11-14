# -*- coding: utf-8 -*-
"""Path utilities - works both in dev and PyInstaller frozen mode."""

import os
import sys
import json
import sqlite3


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
BIN_DIR = os.path.join(APP_ROOT, "bin")
BACKUPS_DIR = os.path.join(APP_ROOT, "backups")
EXPORTS_DIR = os.path.join(APP_ROOT, "exports")
CONFIG_FILE = os.path.join(APP_ROOT, "config.json")
CFST_EXE = os.path.join(BIN_DIR, "cfst.exe")
IP_TXT = os.path.join(BIN_DIR, "ip.txt")

# Desktop export directory
DESKTOP_DIR = get_desktop_dir()
DESKTOP_EXPORT_DIR = os.path.join(DESKTOP_DIR, "CF导出配置")

# Ensure directories exist
for d in [BIN_DIR, BACKUPS_DIR, EXPORTS_DIR]:
    os.makedirs(d, exist_ok=True)


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
