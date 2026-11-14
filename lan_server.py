# -*- coding: utf-8 -*-
"""Token-protected LAN HTTP subscription server.

Serves the exported FlClash / Clash-for-iOS YAML, the Happ TV subscription and
the Xray JSON to phones / TVs on the same LAN, read-only, on a daemon thread.

Security model (v1.1):
- Every subscription lives under an unguessable path: ``/s/<token>/<file>``.
  The token is generated with ``secrets.token_urlsafe(48)`` (384 bit) and is
  compared in constant time; there is no unauthenticated endpoint that serves
  configuration content, and legacy root paths are gone.
- GET / HEAD only. Responses carry no CORS wildcard and no server version.
- Paths are mapped through a fixed table; no URL component ever reaches the
  filesystem, so directory traversal is impossible by construction.
- Request paths are never logged (``log_message`` is a no-op), and error
  bodies are generic, so tokens / local paths never reach a log or response.
- Firewall rule: TCP inbound, profile=private (never Public) and
  remoteip=LocalSubnet (or the configured LAN CIDR), created for the port the
  server actually bound. Stale rules created by this program are removed.

Features kept from the previous implementation:
- ThreadingHTTPServer with daemon request threads
- Physical LAN IP detection (filters 198.18.* TUN, 169.254.* APIPA, 127.*)
- Port fallback when the configured port is taken, reported to the GUI
- On-demand regeneration when the profile is newer than the exports
- Exact Content-Length, no-cache, HEAD support
"""

import hmac
import ipaddress
import os
import re
import secrets
import socket
import subprocess
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Any, Callable, Dict, Optional

from PySide6.QtCore import QObject, Signal

from storage_utils import read_bytes_with_retry

# ── Token ────────────────────────────────────────────────────────────────
TOKEN_BYTES = 48                 # 48 random bytes -> 64 url-safe chars (384 bit)
TOKEN_MIN_LENGTH = 43            # 43 chars ≈ 256 bit minimum accepted on load
TOKEN_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")

# ── Firewall ─────────────────────────────────────────────────────────────
FIREWALL_RULE_PREFIX = "CF-FlClash-LAN-"
DEFAULT_REMOTE_SCOPE = "LocalSubnet"


def generate_token() -> str:
    """Return a fresh URL-safe 384-bit access token (never logged)."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def is_valid_token(token: Any) -> bool:
    """True for a token strong enough to protect the subscription."""
    if not isinstance(token, str):
        return False
    if len(token) < TOKEN_MIN_LENGTH or len(token) > 256:
        return False
    return all(ch in TOKEN_CHARS for ch in token)


def ensure_lan_token(cfg: dict, save: Optional[Callable[[dict], None]] = None) -> str:
    """Return the configured token, generating and persisting one if needed.

    A missing, weak or corrupted value is replaced by a fresh strong token;
    the caller's config dict is updated, and ``save`` persists it when given.
    """
    token = str(cfg.get("lan_auth_token") or "").strip()
    if is_valid_token(token):
        return token
    token = generate_token()
    cfg["lan_auth_token"] = token
    if save is not None:
        try:
            save(cfg)
        except Exception:
            pass
    return token


def mask_token(token: str = "", visible: int = 0) -> str:
    """Masked token for UI text; never returns the full secret by default."""
    token = str(token or "")
    if not token:
        return "未配置"
    if visible <= 0:
        return "•" * 8
    return "•" * max(0, len(token) - visible) + token[-visible:]


def get_real_lan_ip() -> str:
    """Detect the true physical LAN IPv4 address (excluding TUN/APIPA/loopback)."""
    # Method 1: route print 0.0.0.0
    try:
        flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        res = subprocess.run(
            ["route", "print", "0.0.0.0"], capture_output=True,
            encoding="gbk", errors="ignore", creationflags=flags, timeout=3,
        )
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                gateway, iface_ip = parts[2], parts[3]
                if (not gateway.startswith("198.18.") and gateway != "0.0.0.0"
                        and not iface_ip.startswith("198.18.")
                        and not iface_ip.startswith("127.")
                        and not iface_ip.startswith("169.254.")):
                    return iface_ip
    except Exception:
        pass

    # Method 2: PowerShell Get-NetIPAddress
    try:
        flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        cmd = [
            "powershell", "-NoProfile", "-Command",
            "Get-NetIPAddress -AddressFamily IPv4 | "
            "Where-Object { $_.IPAddress -notlike '198.18.*' -and $_.IPAddress -notlike '127.*' "
            "-and $_.IPAddress -notlike '169.254.*' } | "
            "Select-Object -ExpandProperty IPAddress",
        ]
        res = subprocess.run(cmd, capture_output=True, encoding="gbk",
                             errors="ignore", creationflags=flags, timeout=3)
        for line in res.stdout.splitlines():
            ip = line.strip()
            if ip and not ip.startswith(("198.18.", "127.", "169.254.")):
                return ip
    except Exception:
        pass

    # Method 3: socket probe
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("192.168.1.1", 80))
        ip = sock.getsockname()[0]
        sock.close()
        if not ip.startswith(("198.18.", "127.")):
            return ip
    except Exception:
        pass

    return "127.0.0.1"


# ══════════════════════════════════════════════════════════════════════
# Windows Firewall helpers
# ══════════════════════════════════════════════════════════════════════
def firewall_rule_name(port: int = 8686) -> str:
    return f"{FIREWALL_RULE_PREFIX}{int(port)}"


def _popen_flags() -> int:
    return subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0


def normalize_remote_scope(remote_ip: str = "") -> str:
    """Only LocalSubnet or a private LAN CIDR may become the rule's scope."""
    text = str(remote_ip or "").strip()
    if not text or text.lower() in ("localsubnet", "local subnet", "本地子网"):
        return DEFAULT_REMOTE_SCOPE
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return DEFAULT_REMOTE_SCOPE
    if network.prefixlen == 0 or not network.is_private:
        return DEFAULT_REMOTE_SCOPE
    return str(network)


def _run_netsh(args: list, timeout: int = 10):
    return subprocess.run(
        ["netsh", "advfirewall", "firewall"] + [str(a) for a in args],
        capture_output=True, encoding="gbk", errors="ignore",
        creationflags=_popen_flags(), timeout=timeout,
    )


def firewall_rule_exists(port: int = 8686) -> bool:
    """Return True when the port-specific inbound rule exists."""
    rule = firewall_rule_name(port)
    try:
        res = _run_netsh(["show", "rule", f"name={rule}"], timeout=8)
        return res.returncode == 0
    except Exception:
        return False


def _tighten_rule_scope(port: int, remote_scope: str) -> bool:
    """Restrict an existing rule to private networks + LocalSubnet.

    ``netsh firewall set rule ... new ...`` requires elevation; a denied call
    simply returns False and the caller reports the rule as not hardened.
    """
    try:
        res = _run_netsh([
            "set", "rule", f"name={firewall_rule_name(port)}", "new",
            "profile=private", f"remoteip={remote_scope}",
        ], timeout=8)
        return res.returncode == 0
    except Exception:
        return False


def _rule_scope(port: int) -> tuple:
    """Read (profiles, remote addresses) for our rule via PowerShell.

    Returns ("", "") when the rule cannot be read. Structured cmdlets are used
    instead of localized netsh text so the check works on any Windows locale.
    """
    name = firewall_rule_name(port)
    ps = (
        f"$n='{name}';"
        "$r=Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue | "
        "Select-Object -First 1;"
        "if($r){$a=$r|Get-NetFirewallAddressFilter;"
        "Write-Output (($r.Profile.ToString()) + '|' + (($a.RemoteAddress) -join ','))}"
    )
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, encoding="utf-8", errors="ignore",
            creationflags=_popen_flags(), timeout=8,
        )
        line = (res.stdout or "").strip().splitlines()
        if not line:
            return "", ""
        profile, _, remote = line[-1].partition("|")
        return profile.strip().lower(), remote.strip().lower()
    except Exception:
        return "", ""


def firewall_rule_is_hardened(port: int, remote_scope: str = DEFAULT_REMOTE_SCOPE) -> bool:
    """True when the rule is already private-only and scoped to the LAN."""
    profile, remote = _rule_scope(port)
    if not profile or not remote:
        return False
    scope = normalize_remote_scope(remote_scope).lower()
    remote_ok = "localsubnet" in remote or scope in remote or "local subnet" in remote
    return "private" in profile and "public" not in profile and remote_ok


def _tighten_rule_scope_uac(port: int, remote_scope: str) -> bool:
    """One hidden UAC prompt to tighten a legacy profile=any rule."""
    rule = firewall_rule_name(port)
    ps = (
        "$a=@('advfirewall','firewall','set','rule',"
        f"'name={rule}','new','profile=private','remoteip={remote_scope}');"
        "$p=Start-Process -FilePath \"$env:SystemRoot\\System32\\netsh.exe\" "
        "-ArgumentList $a -Verb RunAs -WindowStyle Hidden -PassThru -Wait;"
        "exit $p.ExitCode"
    )
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
            capture_output=True, encoding="gbk", errors="ignore",
            creationflags=_popen_flags(), timeout=60,
        )
        return res.returncode == 0
    except Exception:
        return False


def ensure_firewall_rule_detailed(port: int = 8686, allow_uac: bool = True,
                                  dry_run: bool = False,
                                  remote_ip: str = DEFAULT_REMOTE_SCOPE) -> Dict[str, Any]:
    """Check / add the inbound TCP rule for the subscription port.

    The rule is always TCP inbound, ``profile=private`` and
    ``remoteip=LocalSubnet`` (or the validated LAN CIDR). An existing rule is
    tightened; a missing one is added directly, then through one hidden
    UAC-elevated netsh when needed. Never raises.
    """
    scope = normalize_remote_scope(remote_ip)
    rule = firewall_rule_name(port)
    result: Dict[str, Any] = {
        "port": int(port), "rule": rule, "status": "unknown",
        "detail": "", "remoteip": scope, "profile": "private",
    }
    if firewall_rule_exists(port):
        if dry_run:
            result.update(status="exists", detail="规则已存在（dry-run 未修改）")
        elif firewall_rule_is_hardened(port, scope):
            result.update(status="exists", detail="规则已存在，作用域为专用网络/本地子网")
        elif _tighten_rule_scope(port, scope):
            result.update(status="exists", detail="规则已存在，已收紧为专用网络/本地子网")
        elif allow_uac and _tighten_rule_scope_uac(port, scope):
            result.update(status="exists", detail="规则已存在，已通过 UAC 收紧作用域")
        else:
            result.update(status="exists_unhardened",
                          detail="规则已存在；收紧作用域需要管理员权限")
        return result
    if dry_run:
        result.update(status="missing", detail="规则不存在（dry-run 未修改）")
        return result

    add_args = [
        "add", "rule", f"name={rule}", "dir=in", "action=allow",
        "protocol=TCP", f"localport={int(port)}", "profile=private",
        f"remoteip={scope}",
    ]
    try:
        res = _run_netsh(add_args, timeout=10)
        if res.returncode == 0 and firewall_rule_exists(port):
            result.update(status="added", detail="已直接添加规则（专用网络/本地子网）")
            return result
        direct_detail = (res.stdout or "") + (res.stderr or "")
    except Exception as exc:
        direct_detail = str(exc)

    if not allow_uac:
        result.update(status="failed", detail=f"添加失败（无提权）: {direct_detail.strip()[:300]}")
        return result

    # One hidden UAC prompt; the user only needs to click "Yes".
    ps = (
        "$a=@('advfirewall','firewall','add','rule',"
        f"'name={rule}','dir=in','action=allow','protocol=TCP','localport={int(port)}',"
        f"'profile=private','remoteip={scope}');"
        "$p=Start-Process -FilePath \"$env:SystemRoot\\System32\\netsh.exe\" "
        "-ArgumentList $a -Verb RunAs -WindowStyle Hidden -PassThru -Wait;"
        "exit $p.ExitCode"
    )
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
            capture_output=True, encoding="gbk", errors="ignore",
            creationflags=_popen_flags(), timeout=60,
        )
        if firewall_rule_exists(port):
            result.update(status="added_uac", detail="已通过 UAC 提权添加规则")
            return result
        result.update(status="failed",
                      detail=f"UAC 提权未完成（可能被取消）rc={res.returncode}")
        return result
    except Exception as exc:
        result.update(status="failed", detail=f"UAC 提权失败: {exc}")
        return result


def ensure_firewall_rule(port: int = 8686, allow_uac: bool = True) -> bool:
    """Backwards-compatible boolean wrapper around ensure_firewall_rule_detailed."""
    return ensure_firewall_rule_detailed(port, allow_uac=allow_uac).get("status") in (
        "exists", "exists_unhardened", "added", "added_uac")


def remove_firewall_rule(port: int = 8686, allow_uac: bool = False) -> bool:
    """Delete only this program's exact rule name; never a wildcard/prefix."""
    if not port:
        return False
    rule = firewall_rule_name(port)
    if not rule.startswith(FIREWALL_RULE_PREFIX):
        return False
    try:
        res = _run_netsh(["delete", "rule", f"name={rule}"], timeout=6)
        return res.returncode == 0
    except Exception:
        return False


def list_own_firewall_ports() -> list:
    """Ports whose rule names carry this program's prefix (parsed, deduped)."""
    try:
        res = _run_netsh(["show", "rule", "name=all"], timeout=15)
        text = (res.stdout or "") + (res.stderr or "")
        ports = {int(m) for m in re.findall(FIREWALL_RULE_PREFIX + r"(\d+)", text)}
        return sorted(ports)
    except Exception:
        return []


def remove_stale_firewall_rules(keep_port: Optional[int] = None,
                                allow_uac: bool = False) -> list:
    """Remove this program's rules for ports other than ``keep_port``."""
    removed = []
    for port in list_own_firewall_ports():
        if keep_port is not None and int(port) == int(keep_port):
            continue
        if remove_firewall_rule(port, allow_uac=allow_uac):
            removed.append(port)
    return removed


# ══════════════════════════════════════════════════════════════════════
# HTTP server
# ══════════════════════════════════════════════════════════════════════
class ReusableThreadingServer(ThreadingHTTPServer):
    """Threading HTTP server with daemon request threads (no port hijacking)."""
    allow_reuse_address = False
    daemon_threads = True


_GEN_LOCK = threading.Lock()

_SUB_USERINFO = "upload=0; download=0; total=1073741824000; expire=0"

# canonical name -> (export key, content type, download filename, extra headers)
_ENDPOINT_SPECS: Dict[str, tuple] = {
    "flclash.yaml": ("flclash", "text/yaml; charset=utf-8",
                     "FlClash_Optimized.yaml", {"Profile-Update-Interval": "24"}),
    "flclash": ("flclash", "text/yaml; charset=utf-8",
                "FlClash_Optimized.yaml", {"Profile-Update-Interval": "24"}),
    "ios.yaml": ("ios", "text/yaml; charset=utf-8", "CF-Optimized.yaml",
                 {"Profile-Update-Interval": "24",
                  "Subscription-Userinfo": _SUB_USERINFO}),
    "ios": ("ios", "text/yaml; charset=utf-8", "CF-Optimized.yaml",
            {"Profile-Update-Interval": "24",
             "Subscription-Userinfo": _SUB_USERINFO}),
    "clash": ("ios", "text/yaml; charset=utf-8", "CF-Optimized.yaml",
              {"Profile-Update-Interval": "24",
               "Subscription-Userinfo": _SUB_USERINFO}),
    "config": ("ios", "text/yaml; charset=utf-8", "CF-Optimized.yaml",
               {"Profile-Update-Interval": "24",
                "Subscription-Userinfo": _SUB_USERINFO}),
    "tv_happ.txt": ("happ", "text/plain; charset=utf-8", "tv_happ.txt",
                    {"Profile-Update-Interval": "24",
                     "Subscription-Userinfo": _SUB_USERINFO}),
    "happ.txt": ("happ", "text/plain; charset=utf-8", "tv_happ.txt",
                 {"Profile-Update-Interval": "24",
                  "Subscription-Userinfo": _SUB_USERINFO}),
    "happ": ("happ", "text/plain; charset=utf-8", "tv_happ.txt",
             {"Profile-Update-Interval": "24",
              "Subscription-Userinfo": _SUB_USERINFO}),
    "happ.json": ("happ_json", "application/json; charset=utf-8",
                  "happ_xray.json", {}),
    "xray.json": ("happ_json", "application/json; charset=utf-8",
                  "happ_xray.json", {}),
    "happ_xray.json": ("happ_json", "application/json; charset=utf-8",
                       "happ_xray.json", {}),
    "tv": ("tv", "text/plain; charset=utf-8", "tv_sub.txt", {}),
    "vless": ("vless", "text/plain; charset=utf-8", "TV_VLESS_Links.txt", {}),
}

_DASHBOARD_FILES = (
    ("flclash.yaml", "FlClash 桌面端"),
    ("ios.yaml", "Clash for iOS"),
    ("tv_happ.txt", "Happ 电视端订阅"),
    ("happ.json", "Happ Xray JSON"),
    ("tv", "Base64 订阅"),
    ("vless", "VLESS 明文列表"),
)


def _export_paths(exports_dir: str) -> Dict[str, str]:
    return {
        "flclash": os.path.join(exports_dir, "FlClash_Optimized.yaml"),
        "ios": os.path.join(exports_dir, "iOS_Clash_Config.yaml"),
        "happ": os.path.join(exports_dir, "tv_happ.txt"),
        "happ_json": os.path.join(exports_dir, "happ_xray.json"),
        "vless": os.path.join(exports_dir, "TV_VLESS_Links.txt"),
        "tv": os.path.join(exports_dir, "tv_sub.txt"),
    }


def refresh_exports(exports_dir: str, profile_path: str,
                    profile_factory: Optional[Callable[[], Any]] = None,
                    force: bool = False) -> Dict[str, str]:
    """Regenerate exports when missing or older than the live profile."""
    paths = _export_paths(exports_dir)
    need = force or any(not os.path.exists(p) for p in paths.values())
    if not need and profile_path and os.path.exists(profile_path):
        try:
            profile_mtime = os.path.getmtime(profile_path)
            need = any(os.path.getmtime(p) < profile_mtime for p in paths.values())
        except OSError:
            need = False
    if not need or profile_factory is None:
        return paths
    with _GEN_LOCK:
        # Re-check inside the lock: another request may have just rebuilt them.
        if not force and profile_path and os.path.exists(profile_path):
            try:
                profile_mtime = os.path.getmtime(profile_path)
                if all(os.path.exists(p) and os.path.getmtime(p) >= profile_mtime
                       for p in paths.values()):
                    return paths
            except OSError:
                pass
        try:
            pm = profile_factory()
            pm.generate_all_exports(exports_dir)
        except Exception:
            pass
    return paths


def _path_parts(raw_path: str) -> Optional[tuple]:
    """Split ``/s/<token>/<name>`` without decoding ANY URL escape."""
    raw = raw_path or ""
    if "?" in raw:
        raw = raw.split("?", 1)[0]
    if "#" in raw:
        raw = raw.split("#", 1)[0]
    if not raw.startswith("/") or "%" in raw or "\\" in raw or "\x00" in raw:
        return None
    parts = [p for p in raw.split("/") if p]
    if len(parts) < 2 or len(parts) > 3 or parts[0] != "s":
        return None
    token = parts[1]
    name = parts[2] if len(parts) == 3 else ""
    if not token or token not in (token.strip()):
        return None
    return token, name


def make_subscription_handler(exports_dir: str, profile_mgr: Any = None,
                              profile_factory: Optional[Callable[[], Any]] = None,
                              profile_path: str = "",
                              token_provider: Optional[Callable[[], str]] = None):
    """Factory creating the token-protected request handler."""

    def _factory():
        if profile_factory is not None:
            return profile_factory()
        return profile_mgr

    def _current_token() -> str:
        try:
            return str((token_provider() if token_provider is not None else "") or "")
        except Exception:
            return ""

    class SubscriptionHandler(BaseHTTPRequestHandler):
        server_version = "CF-FlClash-Optimizer"
        sys_version = ""

        def version_string(self):
            return self.server_version

        def log_message(self, fmt, *args):
            # Never log request paths: they contain the bearer token.
            pass

        def _send(self, is_head: bool, status: int, body: bytes, content_type: str,
                  filename: str = "", extra_headers: Optional[Dict[str, str]] = None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            if filename:
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Connection", "close")
            for key, value in (extra_headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if not is_head and body:
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        def _not_found(self, is_head: bool):
            self._send(is_head, 404, b"Not Found\n", "text/plain; charset=utf-8")

        def _method_not_allowed(self, is_head: bool):
            self._send(is_head, 405, b"Method Not Allowed\n",
                       "text/plain; charset=utf-8", extra_headers={"Allow": "GET, HEAD"})

        def _authorized_name(self) -> Optional[str]:
            parsed = _path_parts(self.path)
            if parsed is None:
                return None
            token, name = parsed
            expected = _current_token()
            if not is_valid_token(expected):
                return None
            try:
                if not hmac.compare_digest(token.encode("utf-8"), expected.encode("utf-8")):
                    return None
            except Exception:
                return None
            return name

        def _serve_file(self, is_head: bool, path: str, content_type: str,
                        filename: str, extra_headers: Optional[Dict[str, str]] = None):
            if not path or not os.path.isfile(path):
                self._not_found(is_head)
                return
            try:
                body = read_bytes_with_retry(path)
            except OSError:
                self._send(is_head, 503, b"Service Unavailable\n",
                           "text/plain; charset=utf-8")
                return
            self._send(is_head, 200, body, content_type, filename, extra_headers)

        def _dashboard_html(self) -> str:
            port = self.server.server_address[1]
            links = "".join(
                f"<li><a href='{name}'>{name}</a> — {label}</li>"
                for name, label in _DASHBOARD_FILES
            )
            return (
                "<!DOCTYPE html><html><head><meta charset='utf-8'>"
                "<title>CF-FlClash-Optimizer 局域网订阅服务</title>"
                "<style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:40px;"
                "background:#f5f7fa;color:#333}.card{background:#fff;padding:24px;border-radius:12px;"
                "box-shadow:0 4px 12px rgba(0,0,0,.08);max-width:680px;margin:auto}"
                "h2{color:#1a73e8;margin-top:0}li{line-height:2}a{color:#1a73e8;font-weight:bold}"
                ".badge{display:inline-block;padding:4px 10px;background:#e6f4ea;color:#137333;"
                "border-radius:12px;font-size:13px;font-weight:bold}</style></head><body>"
                "<div class='card'><h2>🌐 CF-FlClash-Optimizer 局域网配置订阅服务</h2>"
                "<p><span class='badge'>🟢 运行中</span> 端口 " + str(port) +
                " · 只读 · 🔐 Token 已认证</p><hr>"
                "<h3>📲 当前令牌下的订阅端点:</h3><ul>" + links + "</ul>"
                "<p>本页地址本身即为访问凭据，请勿分享。</p>"
                "</div></body></html>"
            )

        def _handle_request(self, is_head: bool = False):
            try:
                name = self._authorized_name()
                if name is None:
                    self._not_found(is_head)
                    return

                if name in ("", "index.html"):
                    if not self.path.split("?", 1)[0].endswith("/"):
                        self._send(is_head, 302, b"", "text/plain; charset=utf-8",
                                   extra_headers={"Location": self.path.split("?", 1)[0] + "/"})
                        return
                    self._send(is_head, 200, self._dashboard_html().encode("utf-8"),
                               "text/html; charset=utf-8")
                    return

                spec = _ENDPOINT_SPECS.get(name)
                if spec is None:
                    self._not_found(is_head)
                    return
                try:
                    paths = refresh_exports(exports_dir, profile_path, _factory)
                except Exception:
                    paths = _export_paths(exports_dir)
                export_key, content_type, filename, extra = spec
                self._serve_file(is_head, paths.get(export_key, ""), content_type,
                                 filename, extra)
            except Exception:
                try:
                    self._send(is_head, 500, b"Internal Server Error\n",
                               "text/plain; charset=utf-8")
                except Exception:
                    pass

        def do_HEAD(self):
            self._handle_request(is_head=True)

        def do_GET(self):
            self._handle_request(is_head=False)

        def do_POST(self):
            self._method_not_allowed(False)

        def do_PUT(self):
            self._method_not_allowed(False)

        def do_DELETE(self):
            self._method_not_allowed(False)

        def do_PATCH(self):
            self._method_not_allowed(False)

        def do_OPTIONS(self):
            self._method_not_allowed(False)

    return SubscriptionHandler


class LANServerWorker(QObject):
    """Daemon-thread LAN HTTP subscription server (token protected)."""
    started = Signal(str, int)   # ip, actual port
    error = Signal(str)
    warning = Signal(str)
    firewall = Signal(str)       # firewall check/add result

    def __init__(self, exports_dir: str, port: int = 8686, profile_mgr: Any = None,
                 profile_factory: Optional[Callable[[], Any]] = None,
                 profile_path: str = "", host: str = "auto",
                 port_fallback: int = 10, ensure_firewall: bool = True,
                 token_provider: Optional[Callable[[], str]] = None,
                 remote_scope: str = DEFAULT_REMOTE_SCOPE,
                 parent=None):
        super().__init__(parent)
        self.exports_dir = exports_dir
        self.port = int(port)
        self.profile_mgr = profile_mgr
        self.profile_factory = profile_factory
        self.profile_path = profile_path
        self.host = host
        self.port_fallback = max(0, int(port_fallback))
        self.ensure_firewall = bool(ensure_firewall)
        self.token_provider = token_provider
        self.remote_scope = normalize_remote_scope(remote_scope)
        self.firewall_status: Dict[str, Any] = {}
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._serving = threading.Event()
        self._lan_ip = ""
        self._bound_host = ""
        self._firewall_cleaned = False
        self.actual_port = 0

    def get_lan_ip(self) -> str:
        if not self._lan_ip or self._lan_ip == "127.0.0.1":
            self._lan_ip = get_real_lan_ip()
        return self._lan_ip

    def current_token(self) -> str:
        try:
            return str((self.token_provider() if self.token_provider is not None else "") or "")
        except Exception:
            return ""

    def _candidate_hosts(self) -> list:
        """Configured host first, then the detected LAN IP, then loopback."""
        configured = str(self.host or "").strip()
        detected = self.get_lan_ip()
        if configured in ("", "auto"):
            hosts = [detected or "127.0.0.1"]
        else:
            hosts = [configured]
        for candidate in (detected, "127.0.0.1"):
            if candidate and candidate not in hosts:
                hosts.append(candidate)
        return hosts

    def start(self):
        self._stop.clear()
        self._firewall_cleaned = False
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="LANSubscriptionServer")
        self._thread.start()

    def stop(self, timeout: float = 5.0):
        self._stop.set()
        server = self._server
        if server is not None:
            # shutdown() blocks until serve_forever() acknowledges; only call
            # it once the loop is actually running (avoids a close-during-boot
            # deadlock when the GUI is closed immediately after launch).
            if self._serving.wait(timeout=1.0):
                try:
                    server.shutdown()
                except Exception:
                    pass
            try:
                server.server_close()
            except Exception:
                pass
            self._server = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout)
        self._thread = None
        # Best effort, no UAC: remove only this program's rule for the port we
        # actually opened. A non-elevated call simply fails and leaves it.
        if (self.ensure_firewall and not self._firewall_cleaned
                and self.actual_port and self._bound_host != "127.0.0.1"):
            self._firewall_cleaned = True
            try:
                remove_firewall_rule(self.actual_port, allow_uac=False)
            except Exception:
                pass

    def _ensure_firewall(self, port: int):
        if not self.ensure_firewall:
            return
        if self._bound_host == "127.0.0.1":
            self.firewall.emit("仅绑定 127.0.0.1，无需防火墙规则")
            return
        try:
            info = ensure_firewall_rule_detailed(
                port, allow_uac=True, remote_ip=self.remote_scope)
            self.firewall_status = info
            self.firewall.emit(
                f"防火墙 {info.get('rule')}: {info.get('status')} — {info.get('detail')}")
        except Exception as exc:
            self.firewall.emit(f"防火墙规则检查异常: {exc}")
            return
        try:
            stale = remove_stale_firewall_rules(keep_port=port, allow_uac=False)
            if stale:
                self.firewall.emit(f"已清理本程序旧端口规则: {stale}")
        except Exception:
            pass

    def _run(self):
        if not is_valid_token(self.current_token()):
            self.error.emit("访问 Token 未初始化或强度不足，局域网订阅服务未启动")
            return

        def _factory():
            if self.profile_factory is not None:
                return self.profile_factory()
            return self.profile_mgr

        handler_cls = make_subscription_handler(
            self.exports_dir, self.profile_mgr, self.profile_factory,
            self.profile_path, self.token_provider)

        # The first request may arrive before anything was exported; build now.
        try:
            refresh_exports(self.exports_dir, self.profile_path, _factory)
        except Exception:
            pass

        self._lan_ip = get_real_lan_ip()
        ports = [self.port] + [self.port + i for i in range(1, self.port_fallback + 1)]
        hosts = self._candidate_hosts()
        last_error: Optional[Exception] = None

        for host_index, host in enumerate(hosts):
            if self._stop.is_set():
                return
            if host_index:
                self.warning.emit(f"监听地址不可用，改用 {host} …")
            for candidate in ports:
                if self._stop.is_set():
                    return
                try:
                    server = ReusableThreadingServer((host, candidate), handler_cls)
                except OSError as exc:
                    last_error = exc
                    if host_index == 0:
                        self.warning.emit(f"端口 {candidate} 不可用，尝试下一个端口...")
                    continue

                self._server = server
                self._bound_host = host
                self.actual_port = candidate
                if host != str(self.host or "").strip() and host_index:
                    self.warning.emit(f"已改用监听地址 {host}")
                if candidate != self.port:
                    self.warning.emit(f"端口 {self.port} 被占用，已回退到 {candidate}")

                self._ensure_firewall(candidate)

                report_ip = host
                if host == "0.0.0.0":
                    report_ip = self._lan_ip or "0.0.0.0"
                self.started.emit(report_ip, candidate)
                self._serving.set()
                try:
                    server.serve_forever(poll_interval=0.2)
                except Exception as exc:
                    if not self._stop.is_set():
                        self.error.emit(f"订阅服务运行异常: {exc}")
                return

        self._serving.clear()
        self.error.emit(
            f"局域网订阅服务启动失败（{self.port}~{ports[-1]} / "
            f"{', '.join(hosts)} 均不可用）: {last_error}")
