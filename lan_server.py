# -*- coding: utf-8 -*-
"""High-concurrency multi-threaded LAN HTTP subscription server.

Serves the exported FlClash / Clash-for-iOS YAML, the Happ TV subscription and
the Xray JSON to phones / TVs on the same LAN, read-only, on a daemon thread.

Features:
- ThreadingHTTPServer with daemon request threads
- Automatic Windows Firewall inbound rule (best effort, profile=any)
- Physical LAN IP detection (filters 198.18.* TUN, 169.254.* APIPA, 127.*)
- Port fallback: if the configured port is taken the next free one is used and
  reported to the GUI, so the service never silently dies
- On-demand regeneration: when the FlClash profile is newer than the exported
  files (e.g. the guardian just replaced IPs) the export is rebuilt before the
  response, so phones/TVs always pull the current best IPs
- GET + HEAD, exact Content-Length, no-cache, CORS headers
"""

import base64
import os
import socket
import subprocess
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Any, Callable, Dict, Optional

from PySide6.QtCore import QObject, Signal

from storage_utils import read_bytes_with_retry


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


def firewall_rule_name(port: int = 8686) -> str:
    return f"CF-FlClash-LAN-{int(port)}"


def _popen_flags() -> int:
    return subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0


def firewall_rule_exists(port: int = 8686) -> bool:
    """Return True when the port-specific inbound rule exists."""
    rule = firewall_rule_name(port)
    try:
        res = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule}"],
            capture_output=True, encoding="gbk", errors="ignore",
            creationflags=_popen_flags(), timeout=8,
        )
        return res.returncode == 0
    except Exception:
        return False


def ensure_firewall_rule_detailed(port: int = 8686, allow_uac: bool = True,
                                  dry_run: bool = False) -> Dict[str, Any]:
    """Check / add the inbound TCP rule for the subscription port.

    Flow: ``show rule`` -> direct ``add rule`` (works when the app is already
    elevated) -> one hidden UAC-elevated ``netsh`` (``Start-Process -Verb RunAs``)
    -> re-check.  Never raises.
    """
    rule = firewall_rule_name(port)
    result: Dict[str, Any] = {"port": int(port), "rule": rule, "status": "unknown", "detail": ""}
    if firewall_rule_exists(port):
        result.update(status="exists", detail="规则已存在，无需修改")
        return result
    if dry_run:
        result.update(status="missing", detail="规则不存在（dry-run 未修改）")
        return result

    add_cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule}", "dir=in", "action=allow",
        "protocol=TCP", f"localport={int(port)}", "profile=any",
    ]
    try:
        res = subprocess.run(add_cmd, capture_output=True, encoding="gbk",
                             errors="ignore", creationflags=_popen_flags(), timeout=10)
        if res.returncode == 0 and firewall_rule_exists(port):
            result.update(status="added", detail="已直接添加规则")
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
        f"'name={rule}','dir=in','action=allow','protocol=TCP','localport={int(port)}','profile=any');"
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
        "exists", "added", "added_uac")


class ReusableThreadingServer(ThreadingHTTPServer):
    """Threading HTTP server with daemon request threads (no port hijacking)."""
    allow_reuse_address = False
    daemon_threads = True


_GEN_LOCK = threading.Lock()


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


def make_subscription_handler(exports_dir: str, profile_mgr: Any = None,
                              profile_factory: Optional[Callable[[], Any]] = None,
                              profile_path: str = ""):
    """Factory creating the request handler bound to one exports directory."""

    def _factory():
        if profile_factory is not None:
            return profile_factory()
        return profile_mgr

    class SubscriptionHandler(BaseHTTPRequestHandler):
        server_version = "CF-FlClash-Optimizer/3.0"

        def log_message(self, fmt, *args):
            pass

        def _send(self, is_head: bool, status: int, body: bytes, content_type: str,
                  filename: str = "", extra_headers: Optional[Dict[str, str]] = None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            if filename:
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Connection", "close")
            for key, value in (extra_headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if not is_head and body:
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        def _handle_request(self, is_head: bool = False):
            req_path = self.path.split("?")[0].strip()
            try:
                paths = refresh_exports(exports_dir, profile_path, _factory)
            except Exception:
                paths = _export_paths(exports_dir)

            if req_path in ("/flclash.yaml", "/flclash"):
                self._serve_file(is_head, paths["flclash"], "text/yaml; charset=utf-8",
                                 "FlClash_Optimized.yaml",
                                 {"Profile-Update-Interval": "24"})
            elif req_path in ("/ios.yaml", "/ios", "/clash", "/config"):
                self._serve_file(is_head, paths["ios"], "text/yaml; charset=utf-8",
                                 "CF-Optimized.yaml",
                                 {"Profile-Update-Interval": "24",
                                  "Subscription-Userinfo":
                                      "upload=0; download=0; total=1073741824000; expire=0"})
            elif req_path in ("/tv_happ.txt", "/happ.txt", "/happ"):
                self._serve_file(is_head, paths["happ"], "text/plain; charset=utf-8",
                                 "tv_happ.txt",
                                 {"Profile-Update-Interval": "24",
                                  "Subscription-Userinfo":
                                      "upload=0; download=0; total=1073741824000; expire=0"})
            elif req_path in ("/happ.json", "/xray.json", "/happ_xray.json"):
                self._serve_file(is_head, paths["happ_json"], "application/json; charset=utf-8",
                                 "happ_xray.json")
            elif req_path == "/tv":
                self._serve_file(is_head, paths["tv"], "text/plain; charset=utf-8",
                                 "tv_sub.txt")
            elif req_path == "/vless":
                self._serve_file(is_head, paths["vless"], "text/plain; charset=utf-8",
                                 "TV_VLESS_Links.txt")
            elif req_path in ("/", "/index.html"):
                self._send(is_head, 200, self._dashboard_html().encode("utf-8"),
                           "text/html; charset=utf-8")
            else:
                self._send(is_head, 404,
                           f"404 Not Found: endpoint {req_path} not found.\n".encode("utf-8"),
                           "text/plain; charset=utf-8")

        def _serve_file(self, is_head: bool, path: str, content_type: str,
                        filename: str, extra_headers: Optional[Dict[str, str]] = None):
            if not path or not os.path.exists(path):
                self._send(is_head, 404,
                           f"404 Not Found: {os.path.basename(path or '')} not generated yet.\n"
                           .encode("utf-8"), "text/plain; charset=utf-8")
                return
            try:
                body = read_bytes_with_retry(path)
            except OSError as exc:
                self._send(is_head, 503, f"503 Service Unavailable: {exc}\n".encode("utf-8"),
                           "text/plain; charset=utf-8")
                return
            self._send(is_head, 200, body, content_type, filename, extra_headers)

        def _dashboard_html(self) -> str:
            port = self.server.server_address[1]
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
                "<p><span class='badge'>🟢 运行中</span> 端口 " + str(port) + " · 只读订阅</p><hr>"
                "<h3>📲 可用订阅端点:</h3><ul>"
                "<li>💻 <b>FlClash 桌面端:</b> <a href='/flclash.yaml'>/flclash.yaml</a></li>"
                "<li>📱 <b>Clash for iOS:</b> <a href='/ios.yaml'>/ios.yaml</a></li>"
                "<li>📺 <b>Happ 电视端订阅:</b> <a href='/tv_happ.txt'>/tv_happ.txt</a>"
                "（自带自动更新/自动连接指令）</li>"
                "<li>🧩 <b>Happ Xray JSON:</b> <a href='/happ.json'>/happ.json</a>"
                "（IPv4-only DNS，mux 关闭）</li>"
                "<li>📋 <b>Base64 订阅:</b> <a href='/tv'>/tv</a></li>"
                "<li>🔗 <b>VLESS 明文列表:</b> <a href='/vless'>/vless</a></li>"
                "</ul></div></body></html>"
            )

        def do_HEAD(self):
            self._handle_request(is_head=True)

        def do_GET(self):
            self._handle_request(is_head=False)

    return SubscriptionHandler


class LANServerWorker(QObject):
    """Daemon-thread LAN HTTP subscription server."""
    started = Signal(str, int)   # ip, actual port
    error = Signal(str)
    warning = Signal(str)
    firewall = Signal(str)       # firewall check/add result

    def __init__(self, exports_dir: str, port: int = 8686, profile_mgr: Any = None,
                 profile_factory: Optional[Callable[[], Any]] = None,
                 profile_path: str = "", host: str = "0.0.0.0",
                 port_fallback: int = 10, ensure_firewall: bool = True,
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
        self.firewall_status: Dict[str, Any] = {}
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._serving = threading.Event()
        self._lan_ip = ""
        self.actual_port = 0

    def get_lan_ip(self) -> str:
        if not self._lan_ip or self._lan_ip == "127.0.0.1":
            self._lan_ip = get_real_lan_ip()
        return self._lan_ip

    def start(self):
        self._stop.clear()
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

    def _run(self):
        if self.ensure_firewall:
            try:
                info = ensure_firewall_rule_detailed(self.port, allow_uac=True)
                self.firewall_status = info
                self.firewall.emit(
                    f"防火墙 {info.get('rule')}: {info.get('status')} — {info.get('detail')}")
            except Exception as exc:
                self.firewall.emit(f"防火墙规则检查异常: {exc}")
        self._lan_ip = get_real_lan_ip()

        def _factory():
            if self.profile_factory is not None:
                return self.profile_factory()
            return self.profile_mgr

        handler_cls = make_subscription_handler(
            self.exports_dir, self.profile_mgr, self.profile_factory, self.profile_path)

        # The first request may arrive before anything was exported; build now.
        try:
            refresh_exports(self.exports_dir, self.profile_path, _factory)
        except Exception:
            pass

        ports = [self.port] + [self.port + i for i in range(1, self.port_fallback + 1)]
        last_error: Optional[Exception] = None
        for candidate in ports:
            if self._stop.is_set():
                return
            try:
                server = ReusableThreadingServer((self.host, candidate), handler_cls)
            except OSError as exc:
                last_error = exc
                self.warning.emit(f"端口 {candidate} 不可用，尝试下一个端口...")
                continue
            self._server = server
            self.actual_port = candidate
            if candidate != self.port:
                self.warning.emit(f"端口 {self.port} 被占用，已回退到 {candidate}")
            self.started.emit(self._lan_ip, candidate)
            self._serving.set()
            try:
                server.serve_forever(poll_interval=0.2)
            except Exception as exc:
                if not self._stop.is_set():
                    self.error.emit(f"订阅服务运行异常: {exc}")
            return
        self._serving.clear()
        self.error.emit(f"局域网订阅服务启动失败（{self.port}~{ports[-1]} 均不可用）: {last_error}")
