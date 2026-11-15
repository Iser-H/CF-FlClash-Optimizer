# -*- coding: utf-8 -*-
"""Synchronous cfst test engines shared by the GUI workers and the guardian.

No Qt import happens here on purpose: the background auto-guardian runs as a
plain daemon thread and must not depend on the Qt event loop.
"""

import csv
import ipaddress
import os
import socket
import ssl
import subprocess
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Optional

from cidr_pool import CF_CIDRS, subnet_of
from tun_bypass import RouteBypassContext

CFST_EXE_FALLBACK_NAME = "cfst.exe"

# Only one cfst.exe may run at a time: it rewrites bin/*.csv and injects kernel
# routes.  The GUI workers block on this lock; the guardian skips its cycle.
CFST_LOCK = threading.Lock()


class CfstBusyError(RuntimeError):
    """Raised when another cfst run holds the lock for too long."""


class _CfstSlot:
    """Context manager: wait for the single cfst slot, then release it."""

    def __init__(self, log: Optional[Callable[[str], None]] = None, timeout: float = 900.0):
        self.log = log or _noop
        self.timeout = timeout

    def __enter__(self):
        self.log("⏳ 等待测速通道空闲...")
        if not CFST_LOCK.acquire(timeout=self.timeout):
            raise CfstBusyError("另一个测速任务正在运行且等待超时，请稍后重试")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        CFST_LOCK.release()
        return False


def _noop(_msg: str) -> None:
    pass


def _not_stopped() -> bool:
    return False


def probe_tls_ws(server: str, port: int = 8443, sni: str = "", path: str = "/ws",
                 timeout: float = 4.0) -> int:
    """Fallback direct TLS handshake probe. Returns handshake latency in ms, or -1."""
    try:
        t0 = time.time()
        sock = socket.create_connection((server, int(port)), timeout=timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls = ctx.wrap_socket(sock, server_hostname=sni or server)
        tls_ms = int((time.time() - t0) * 1000)
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {sni or server}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        tls.sendall(req.encode())
        tls.settimeout(2.0)
        tls.recv(256)
        tls.close()
        return tls_ms
    except Exception:
        return -1


def _popen_kwargs() -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {}
    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    return kwargs


def verify_cfst_binary(path: str) -> Dict[str, Any]:
    """Existence/size/architecture check for the external speed-test core.

    Returned dict is safe to log (path, sizes, arch string only).
    """
    info: Dict[str, Any] = {"path": str(path or ""), "exists": False, "size": 0,
                            "machine": "", "arch": "", "ok": False, "error": ""}
    try:
        info["exists"] = bool(path) and os.path.isfile(path)
        if info["exists"]:
            info["size"] = os.path.getsize(path)
    except OSError as exc:
        info["error"] = f"无法读取文件: {exc}"
        return info
    if not info["exists"]:
        info["error"] = "文件不存在（请确认 bin\\cfst.exe 与 EXE 在同一目录）"
        return info
    if info["size"] < 1_000_000:
        info["error"] = f"文件过小（{info['size']} 字节），可能不是完整二进制"
        return info
    try:
        import struct
        with open(path, "rb") as handle:
            head = handle.read(0x400)
        if head[:2] != b"MZ":
            info["error"] = "不是有效的 Windows 可执行文件（缺少 MZ 头）"
            return info
        offset = struct.unpack_from("<I", head, 0x3C)[0]
        with open(path, "rb") as handle:
            handle.seek(offset)
            pe = handle.read(6)
        machine = struct.unpack_from("<H", pe, 4)[0]
        info["machine"] = f"0x{machine:04x}"
        info["arch"] = {0x8664: "x64", 0x014c: "x86", 0xAA64: "arm64"}.get(machine, "未知")
        if machine != 0x8664:
            info["error"] = f"架构为 {info['arch']}（{info['machine']}），期望 x64"
            return info
    except Exception as exc:
        info["error"] = f"PE 头解析失败: {exc}"
        return info
    info["ok"] = True
    return info


def _run_cfst(cmd: List[str], cwd: str, log: Callable[[str], None],
              is_stopped: Callable[[], bool],
              register_proc: Optional[Callable[[Any], None]] = None) -> int:
    """Run cfst.exe with a non-interactive stdin and surface failures.

    ``stdin=DEVNULL`` plus the caller's ``-p 0`` guarantee the helper can never
    block on the "Press Enter to exit" prompt; a non-zero exit code is logged
    with the tail of the captured output so the GUI log/status bar shows why.
    """
    exe = str(cmd[0]) if cmd else ""
    if exe and not os.path.isfile(exe):
        log(f"❌ 找不到测速核心: {exe}")
        log("   请确认 bin\\cfst.exe 与主程序在同一目录（v1.3 发布包已自带）")
        return -2
    tail: List[str] = []
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, text=True, cwd=cwd,
            encoding="utf-8", errors="replace", **_popen_kwargs(),
        )
    except OSError as exc:
        log(f"❌ 启动测速核心失败: {exc}")
        log(f"   命令: {' '.join(cmd)}")
        return -3
    if register_proc:
        try:
            register_proc(proc)
        except Exception:
            pass
    try:
        for line in proc.stdout:
            if is_stopped():
                try:
                    proc.kill()
                except Exception:
                    pass
                break
            line_str = line.rstrip()
            if line_str:
                tail.append(line_str)
                del tail[:-6]
                log(line_str)
        proc.wait()
    finally:
        if register_proc:
            try:
                register_proc(None)
            except Exception:
                pass
    if proc.returncode != 0:
        log(f"❌ 测速核心退出码 {proc.returncode}: {exe}")
        if tail:
            log("   最后输出: " + " | ".join(tail[-3:]))
    return int(proc.returncode or 0)


def parse_result_csv(path: str, sl_filter: float = 0.0) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    if not os.path.exists(path):
        return results
    with open(path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            norm = {str(k).replace(" ", ""): v for k, v in row.items() if k is not None}
            try:
                speed = float(norm.get("下载速度(MB/s)", norm.get("speed", 0) or 0))
            except (TypeError, ValueError):
                speed = 0.0
            try:
                latency = float(norm.get("平均延迟", norm.get("avg_latency", 0) or 0))
            except (TypeError, ValueError):
                latency = 0.0
            try:
                loss = float(str(norm.get("丢包率", norm.get("loss", "0"))).replace("%", ""))
            except (TypeError, ValueError):
                loss = 0.0
            norm["speed_num"] = speed
            norm["latency_num"] = latency
            norm["loss_num"] = loss
            norm["is_pass"] = speed >= float(sl_filter)
            results.append(norm)
    return results


def bypass_targets_for_ips(ips: Iterable[str], max_routes: int = 64) -> List[str]:
    """Kernel routes needed to keep candidate IPs off the TUN interface.

    One /32 route per sampled IP would mean thousands of ``route add`` calls
    for a 2000-IP sample; instead the /24s are collapsed and, when that is
    still too many, the whole Cloudflare CIDR library (a dozen routes) is
    used - cfst then probes its targets over the physical NIC.
    """
    networks = set()
    for ip in ips:
        try:
            networks.add(ipaddress.IPv4Network(f"{ipaddress.IPv4Address(str(ip).strip())}/24",
                                               strict=False))
        except ValueError:
            continue
    if not networks:
        return []
    collapsed = list(ipaddress.collapse_addresses(networks))
    if len(collapsed) <= max_routes:
        return [str(net) for net in collapsed]
    return list(CF_CIDRS)


def run_health_check(cfst_exe: str, node_info: List[Dict[str, Any]], clash_api: Any,
                     bin_dir: str, log: Optional[Callable[[str], None]] = None,
                     is_stopped: Callable[[], bool] = _not_stopped,
                     register_proc: Optional[Callable[[Any], None]] = None) -> List[Dict[str, Any]]:
    """Measure the three currently-configured IPs (latency + cfst throughput)."""
    log = log or _noop
    with _CfstSlot(log):
        delays: Dict[str, Any] = {}
        log("📡 测试节点延迟 (优先 Clash API，未通则回退直连 TLS 握手)...")
        for node in node_info:
            if is_stopped():
                return []
            name = node.get("name", "")
            ip = node.get("server", "")
            port = int(node.get("port", 8443) or 8443)
            sni = node.get("servername", "") or (node.get("ws-opts") or {}).get("headers", {}).get("Host", "")
            ws_path = (node.get("ws-opts") or {}).get("path", "/ws") or "/ws"
            delay = -1
            delay_type = "api"
            if clash_api is not None:
                try:
                    if clash_api.is_alive():
                        delay = clash_api.test_proxy_delay(name)
                except Exception:
                    delay = -1
            if delay <= 0:
                delay_type = "tls"
                delay = probe_tls_ws(ip, port, sni, ws_path)
            delays[name] = (delay_type, delay)
            if delay > 0:
                label = "Clash代理延迟" if delay_type == "api" else "隧道握手延迟"
                log(f"  {name}: {delay} ms ({label})")
            else:
                log(f"  {name}: 探测超时")

        current_ips = [str(n.get("server", "")).strip() for n in node_info if n.get("server")]
        if not current_ips:
            return []

        os.makedirs(bin_dir, exist_ok=True)
        ip_file = os.path.join(bin_dir, "current_ips.txt")
        with open(ip_file, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(current_ips) + "\n")

        result_file = os.path.join(bin_dir, "current_result.csv")
        try:
            os.remove(result_file)
        except OSError:
            pass

        log("🛡️ 注入内核路由绕过 TUN 虚拟网卡...")
        targets = bypass_targets_for_ips(current_ips)
        if targets:
            with RouteBypassContext(targets):
                log("🚀 启动 cfst.exe 检测当前 3 个已配置 IP...")
                cmd = [cfst_exe, "-f", ip_file, "-dn", str(len(current_ips)),
                       "-tl", "2000", "-sl", "0", "-dt", "4", "-p", "0",
                       "-o", result_file]
                log(f"执行命令: {' '.join(cmd)}")
                rc = _run_cfst(cmd, bin_dir, log, is_stopped, register_proc)
        else:
            cmd = [cfst_exe, "-f", ip_file, "-dn", str(len(current_ips)),
                   "-tl", "2000", "-sl", "0", "-dt", "4", "-p", "0",
                   "-o", result_file]
            rc = _run_cfst(cmd, bin_dir, log, is_stopped, register_proc)
        log("🧹 已自动清理内核临时路由")

        rows = parse_result_csv(result_file)
        if rows:
            log(f"✅ 获取到 {len(rows)} 条实测数据")
        elif rc != 0:
            log(f"❌ 体检失败：cfst.exe 退出码 {rc}（原因见上方输出）")
        else:
            log("⚠ 未生成测速结果文件")

        final: List[Dict[str, Any]] = []
        for node in node_info:
            name = node.get("name", "")
            ip = str(node.get("server", ""))
            delay_type, delay_value = delays.get(name, ("tls", -1))
            entry = {
                "name": name,
                "ip": ip,
                "proxy_delay": delay_value,
                "delay_type": delay_type,
                "cf_latency": 0.0,
                "loss": 0.0,
                "speed": 0.0,
                "subnet": subnet_of(ip) or "",
            }
            for row in rows:
                row_ip = str(row.get("IP地址", row.get("ip", ""))).strip()
                if row_ip == ip:
                    entry["cf_latency"] = row.get("latency_num", 0.0)
                    entry["loss"] = row.get("loss_num", 0.0)
                    entry["speed"] = row.get("speed_num", 0.0)
                    break
            final.append(entry)
        log("✅ 当前已配置 IP 体检完成！")
        return final


def build_speed_test_command(cfst_exe: str, ip_file: str, result_file: str,
                             threads: int = 200, tl: int = 400,
                             dn: int = 10, url: str = "") -> List[str]:
    """Full-speed-test command line with an explicit absolute ``-f`` path.

    ``-p 0`` disables cfst's "press Enter to exit" prompt; both file paths are
    absolute so a packaged (frozen) EXE never resolves them against the
    temporary ``_MEIPASS`` folder.
    """
    cmd = [str(cfst_exe), "-f", os.path.abspath(str(ip_file)),
           "-n", str(threads), "-tl", str(tl), "-sl", "0",
           "-dn", str(dn), "-p", "0", "-o", os.path.abspath(str(result_file))]
    if url:
        cmd.extend(["-url", str(url)])
    return cmd


def default_ip_list_file(bin_dir: str,
                         log: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Resolved ``ip.txt`` for the full speed test (package → data → generated)."""
    log = log or _noop
    try:
        from path_utils import resolve_ip_list_file
        info = resolve_ip_list_file(create=True, data_bin=bin_dir)
    except Exception as exc:
        info = {"path": os.path.join(bin_dir, "ip.txt"), "source": "missing",
                "exists": False, "generated": False}
        log(f"⚠ 解析 ip.txt 失败: {exc}")
    if info.get("generated"):
        log(f"📄 未找到 ip.txt，已生成内置官方 Cloudflare IPv4 CIDR 兜底: {info['path']}")
    elif info.get("exists"):
        log(f"📄 IP 列表: {info['path']}（来源: {info['source']}）")
    else:
        log(f"⚠ 缺少 IP 列表文件且无法生成: {info.get('path')}")
    return info


def run_speed_test(cfst_exe: str, bin_dir: str, ip_file: Optional[str] = None,
                   threads: int = 200, tl: int = 400, sl_filter: float = 5.0,
                   dn: int = 10, url: str = "",
                   log: Optional[Callable[[str], None]] = None,
                   is_stopped: Callable[[], bool] = _not_stopped,
                   register_proc: Optional[Callable[[Any], None]] = None) -> List[Dict[str, Any]]:
    """Full Cloudflare speed test over a prepared candidate list."""
    log = log or _noop
    if not ip_file:
        info = default_ip_list_file(bin_dir, log)
        ip_file = info.get("path") or os.path.join(bin_dir, "ip.txt")
    ip_file = os.path.abspath(str(ip_file))
    if not os.path.exists(ip_file):
        raise FileNotFoundError(f"找不到 IP 列表文件: {ip_file}")

    result_file = os.path.abspath(os.path.join(bin_dir, "result.csv"))
    if os.path.exists(result_file):
        try:
            os.remove(result_file)
        except OSError:
            pass

    with open(ip_file, "r", encoding="utf-8", errors="replace") as f:
        candidates = [line.strip() for line in f
                      if line.strip() and not line.strip().startswith("#")]
    log(f"📄 测速候选: {len(candidates)} 条（-f {ip_file}）")

    with _CfstSlot(log):
        log("🛡️ 注入候选 IP 网段的 TUN 绕过路由...")
        targets = bypass_targets_for_ips(candidates)
        with RouteBypassContext(targets):
            cmd = build_speed_test_command(cfst_exe, ip_file, result_file,
                                           threads=threads, tl=tl, dn=dn, url=url)
            log(f"🚀 启动全网测速: {' '.join(cmd)}")
            rc = _run_cfst(cmd, bin_dir, log, is_stopped, register_proc)
        log("🧹 已自动清理全网 CIDR 临时路由")

    results = parse_result_csv(result_file, sl_filter=sl_filter)
    if results:
        log(f"✅ 全网测速完成，共生成 {len(results)} 条候选结果 "
            f"(速度过滤下限: {sl_filter} MB/s)")
    elif rc != 0:
        log(f"❌ 全网测速失败：cfst.exe 退出码 {rc}（原因见上方输出）")
    else:
        log("⚠ 未生成全网测速结果文件")
    return results
