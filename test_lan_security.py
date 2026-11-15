# -*- coding: utf-8 -*-
"""Automated security tests for the LAN HTTP subscription service.

All fixture data is synthetic: TEST-NET-3 addresses (203.0.113.0/24) and a
dummy UUID. No real airport profile, UUID, password or VPS credential is used.
Firewall calls are mocked; nothing on the host firewall is changed.
"""

import base64
import concurrent.futures
import contextlib
import io
import json
import os
import socket
import sys
import tempfile
import time
from unittest import mock

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import requests

import lan_server
import path_utils
from lan_server import (
    LANServerWorker, ensure_firewall_rule_detailed, ensure_lan_token,
    firewall_rule_name, generate_token, is_valid_token, list_own_firewall_ports,
    normalize_remote_scope, remove_firewall_rule, remove_stale_firewall_rules,
)

FAILS = []

DUMMY_UUID = "00000000-0000-4000-8000-000000000000"
VLESS_LINK = (
    f"vless://{DUMMY_UUID}@203.0.113.10:443?encryption=none&security=tls"
    "&sni=test.example&type=ws&host=test.example&path=%2F&mux=0"
    "&packetEncoding=xudp#TEST-NODE"
)
SYNTHETIC_YAML = (
    "mixed-port: 7890\n"
    "proxies:\n"
    "  - name: TEST-NODE\n"
    "    type: vless\n"
    "    server: 203.0.113.10\n"
    "    port: 443\n"
    f"    uuid: {DUMMY_UUID}\n"
    "    tls: true\n"
    "    servername: test.example\n"
    "    network: ws\n"
)


def check(name: str, ok: bool, detail: str = ""):
    print(("  ✅ " if ok else "  ❌ ") + name + (f"  [{detail}]" if detail else ""))
    if not ok:
        FAILS.append(name)


def free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def other_token(token: str) -> str:
    """A guaranteed-different token (never derive one by truncation)."""
    candidate = generate_token()
    while candidate == token:
        candidate = generate_token()
    return candidate


def make_exports(tmp: str) -> str:
    exports = os.path.join(tmp, "exports")
    os.makedirs(exports, exist_ok=True)
    files = {
        "FlClash_Optimized.yaml": SYNTHETIC_YAML,
        "iOS_Clash_Config.yaml": SYNTHETIC_YAML,
        "tv_happ.txt": (
            "#subscription-auto-update-open-enable: 1\n"
            "#subscription-autoconnect-type: lowestdelay\n" + VLESS_LINK + "\n"
        ),
        "happ_xray.json": json.dumps({
            "dns": {"queryStrategy": "UseIPv4"},
            "outbounds": [{"protocol": "vless", "tag": "cf-test",
                           "mux": {"enabled": False}}],
            "routing": {"rules": []},
        }),
        "TV_VLESS_Links.txt": VLESS_LINK + "\n",
        "tv_sub.txt": base64.b64encode((VLESS_LINK + "\n").encode()).decode(),
    }
    for name, text in files.items():
        with open(os.path.join(exports, name), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    return exports


def wait_started(worker, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline and not worker.actual_port:
        time.sleep(0.05)
    return worker.actual_port


def raw_request(port: int, target: str) -> bytes:
    """Send a raw request line so `..` is NOT normalised by the client."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        sock.sendall(
            f"GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return data
    finally:
        sock.close()


# ══════════════════════════════════════════════════════════════════════
def test_defaults(tmp: str):
    print("\n📋 1. 默认安全策略")
    original = path_utils.CONFIG_FILE
    try:
        missing = os.path.join(tmp, "no-such-config.json")
        path_utils.CONFIG_FILE = missing
        cfg = path_utils.load_config()
        check("新安装 LAN 服务默认关闭", cfg.get("lan_server_enabled") is False)
        check("新安装默认自动选择局域网地址", cfg.get("lan_bind_host") == "auto")
        check("新安装无预置 Token", cfg.get("lan_auth_token") == "")
        check("无配置文件时不会意外开启 LAN", os.path.exists(missing)
              and cfg.get("lan_server_enabled") is False)

        broken = os.path.join(tmp, "broken-config.json")
        with open(broken, "w", encoding="utf-8") as f:
            f.write("{ this is not json")
        path_utils.CONFIG_FILE = broken
        cfg2 = path_utils.load_config()
        check("配置文件损坏时 LAN 仍为关闭", cfg2.get("lan_server_enabled") is False)
        check("配置损坏时监听地址不变成 0.0.0.0", cfg2.get("lan_bind_host") == "auto")
    finally:
        path_utils.CONFIG_FILE = original


def test_tokens():
    print("\n📋 2. Token 生成与校验")
    t1, t2 = generate_token(), generate_token()
    check("Token 长度 >= 43 字符（>= 256 bit）", len(t1) >= 43, str(len(t1)))
    check("Token 为 URL-safe 字符", all(c.isalnum() or c in "-_" for c in t1))
    check("两次生成互不相同", t1 != t2)
    check("强 Token 校验通过", is_valid_token(t1))
    check("弱 Token 被拒绝", not is_valid_token("short") and not is_valid_token(""))
    cfg = {"lan_auth_token": "weak"}
    saved = []
    token = ensure_lan_token(cfg, saved.append)
    check("弱 Token 会被替换并持久化",
          token != "weak" and cfg["lan_auth_token"] == token and saved)
    same = ensure_lan_token(cfg, saved.append)
    check("已存在的强 Token 保持不变", same == token and len(saved) == 1)


def test_http_security(tmp: str):
    print("\n📋 3. HTTP 接口认证与内容")
    exports = make_exports(tmp)
    holder = {"token": generate_token()}
    port = free_port()
    worker = LANServerWorker(
        exports, port, host="127.0.0.1", port_fallback=2, ensure_firewall=False,
        token_provider=lambda: holder["token"])
    worker.start()
    actual = wait_started(worker)
    check("服务已启动", actual == port, str(actual))
    root = f"http://127.0.0.1:{actual}"
    token = holder["token"]
    wrong = other_token(token)
    base = f"{root}/s/{token}"
    try:
        # 1) no token / wrong token / legacy paths
        for path, label in (("/ios.yaml", "旧无认证路径"),
                            ("/flclash.yaml", "旧 flclash 路径"),
                            ("/", "根仪表盘"),
                            (f"/s/{wrong}/ios.yaml", "错误 Token"),
                            (f"/s/{other_token(token)}/ios.yaml", "另一个 Token")):
            resp = requests.get(root + path, timeout=5)
            check(f"{label} 返回 404", resp.status_code == 404, path[:40])
            check(f"{label} 不返回配置", "proxies:" not in resp.text)
            check(f"{label} 不回显 Token", token not in resp.text)

        # 2) four formats
        specs = (
            ("flclash.yaml", "yaml", b"proxies:"),
            ("ios.yaml", "yaml", b"proxies:"),
            ("tv_happ.txt", "text", b"mux=0"),
            ("happ.json", "json", b"queryStrategy"),
        )
        for name, ctype, marker in specs:
            resp = requests.get(f"{base}/{name}", timeout=5)
            check(f"正确 Token 可下载 {name}",
                  resp.status_code == 200 and ctype in resp.headers.get("Content-Type", "")
                  and marker in resp.content)
        check("happ.json 结构有效",
              requests.get(f"{base}/happ.json", timeout=5).json()
              ["dns"]["queryStrategy"] == "UseIPv4")
        check("Base64 订阅可解码",
              base64.b64decode(requests.get(f"{base}/tv", timeout=5).text)
              .decode().count("vless://") >= 1)
        check("VLESS 列表可读",
              requests.get(f"{base}/vless", timeout=5).text.count("vless://") >= 1)

        # Multiple devices polling the same endpoint concurrently.
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            codes = list(pool.map(
                lambda _: requests.get(f"{base}/ios.yaml", timeout=10).status_code,
                range(6)))
        check("多设备并发访问均成功", codes == [200] * 6, str(codes))

        # 3) HEAD + security headers
        head = requests.head(f"{base}/ios.yaml", timeout=5)
        check("HEAD 返回 200 且无 body",
              head.status_code == 200 and head.content == b""
              and int(head.headers.get("Content-Length", 0)) > 0)
        check("无 CORS 通配符", "Access-Control-Allow-Origin" not in head.headers)
        check("响应带 nosniff",
              head.headers.get("X-Content-Type-Options") == "nosniff")
        check("服务端不泄露 Python 版本",
              "Python" not in head.headers.get("Server", ""))

        # 4) methods
        post = requests.post(f"{base}/ios.yaml", timeout=5)
        check("POST 返回 405 且声明 Allow",
              post.status_code == 405 and "GET" in post.headers.get("Allow", ""))
        check("OPTIONS 不允许跨域预检",
              requests.options(f"{base}/ios.yaml", timeout=5).status_code == 405)

        # 5) traversal
        raw = raw_request(actual, f"/s/{token}/../../ios.yaml")
        check("明文 ../ 路径被拒绝",
              b" 404 " in raw.split(b"\r\n", 1)[0] and b"proxies:" not in raw)
        raw2 = raw_request(actual, f"/s/{token}/%2e%2e/%2e%2e/ios.yaml")
        check("百分号编码穿越被拒绝",
              b" 404 " in raw2.split(b"\r\n", 1)[0] and b"proxies:" not in raw2)
        raw3 = raw_request(actual, "/s/../ios.yaml")
        check("无 Token 的斜杠路径被拒绝",
              b" 404 " in raw3.split(b"\r\n", 1)[0])

        # 6) error bodies leak nothing
        miss = requests.get(f"{base}/nope", timeout=5)
        body = miss.text
        check("404 不泄露本地目录/Token",
              exports not in body and "C:\\" not in body and token not in body)
        check("未知端点 404", miss.status_code == 404)

        # 7) logs carry no token
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            requests.get(f"{root}/s/{wrong}/ios.yaml", timeout=5)
            requests.get(f"{base}/ios.yaml", timeout=5)
            time.sleep(0.1)
        check("HTTP 日志不包含 Token", token not in captured.getvalue())

        # 8) rotation invalidates the old URL immediately
        fresh = generate_token()
        holder["token"] = fresh
        old = requests.get(f"{base}/ios.yaml", timeout=5)
        check("重新生成 Token 后旧地址立即失效",
              old.status_code == 404 and "proxies:" not in old.text)
        new = requests.get(f"{root}/s/{fresh}/ios.yaml", timeout=5)
        check("新 Token 立即可用", new.status_code == 200 and "proxies:" in new.text)
        token = fresh
        base = f"{root}/s/{token}"
    finally:
        worker.stop()
    time.sleep(0.2)
    try:
        requests.get(f"{base}/ios.yaml", timeout=2)
        closed = False
    except Exception:
        closed = True
    check("服务关闭后接口不可访问", closed)


def test_port_fallback_and_firewall_port(tmp: str):
    print("\n📋 4. 端口回退与防火墙实际端口")
    exports = make_exports(tmp)
    token = generate_token()
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("0.0.0.0", 0))
    blocker.listen(1)
    busy = blocker.getsockname()[1]
    recorded = {}

    def fake_ensure(port, allow_uac=True, dry_run=False, remote_ip="LocalSubnet"):
        recorded["port"] = int(port)
        recorded["remote"] = remote_ip
        return {"port": int(port), "rule": firewall_rule_name(port),
                "status": "exists", "detail": "mocked"}

    worker = LANServerWorker(
        exports, busy, host="0.0.0.0", port_fallback=5, ensure_firewall=True,
        token_provider=lambda: token)
    with mock.patch.object(lan_server, "ensure_firewall_rule_detailed", side_effect=fake_ensure), \
            mock.patch.object(lan_server, "remove_stale_firewall_rules", return_value=[]), \
            mock.patch.object(lan_server, "remove_firewall_rule", return_value=True):
        try:
            worker.start()
            actual = wait_started(worker)
            check("端口占用后自动回退",
                  busy < actual <= busy + 5, f"{busy} -> {actual}")
            check("防火墙规则使用实际监听端口",
                  recorded.get("port") == actual, str(recorded))
            check("防火墙远程范围仍为 LocalSubnet",
                  recorded.get("remote") == "LocalSubnet")
            resp = requests.get(
                f"http://127.0.0.1:{actual}/s/{token}/tv_happ.txt", timeout=5)
            check("回退端口仍能认证下载", resp.status_code == 200)
        finally:
            worker.stop()
            blocker.close()


def test_firewall_helpers():
    print("\n📋 5. 防火墙作用域、去重与清理")
    check("规则名绑定端口", firewall_rule_name(8686) == "CF-FlClash-LAN-8686")
    check("空/非法远程范围收敛到 LocalSubnet",
          normalize_remote_scope("") == "LocalSubnet"
          and normalize_remote_scope("not-a-cidr") == "LocalSubnet")
    check("公网 CIDR 不会被用作作用域",
          normalize_remote_scope("8.8.8.0/24") == "LocalSubnet"
          and normalize_remote_scope("0.0.0.0/0") == "LocalSubnet")
    check("私有 CIDR 原样保留",
          normalize_remote_scope("192.168.1.0/24") == "192.168.1.0/24")

    calls = []

    def fake_cmd(args, timeout=10):
        calls.append([str(a) for a in args])
        return mock.Mock(returncode=0, stdout="", stderr="")

    # Existing rule: only `set`, never a second `add`. The rule is repaired to
    # cover Private+Public (a private-only rule is ignored on "Public" Wi-Fi,
    # which is what made phones fail) while the scope stays LocalSubnet.
    with mock.patch.object(lan_server, "_run_netsh", side_effect=fake_cmd), \
            mock.patch.object(lan_server, "firewall_rule_exists", return_value=True), \
            mock.patch.object(lan_server, "firewall_rule_is_hardened",
                              side_effect=[False, True]), \
            mock.patch.object(lan_server, "firewall_rule_applies",
                              side_effect=[{"applies": False}, {"applies": True}]):
        info = ensure_firewall_rule_detailed(8686, allow_uac=False)
    check("已有规则复用而不新增",
          info.get("status") == "exists"
          and not any("add" in c for c in calls), str(calls))
    check("已有规则被收紧为 专用+公用 / LocalSubnet",
          any("set" in c and "profile=private,public" in c
              and "remoteip=LocalSubnet" in c for c in calls), str(calls))

    # Already hardened rule: no set/add at all (no repeated UAC prompt).
    calls.clear()
    with mock.patch.object(lan_server, "_run_netsh", side_effect=fake_cmd), \
            mock.patch.object(lan_server, "firewall_rule_exists", return_value=True), \
            mock.patch.object(lan_server, "firewall_rule_is_hardened", return_value=True), \
            mock.patch.object(lan_server, "firewall_rule_applies",
                              return_value={"applies": True}):
        info = ensure_firewall_rule_detailed(8686, allow_uac=True)
    check("已收紧的规则不再重复修改",
          info.get("status") == "exists" and calls == [], str(calls))

    # Missing rule: add with Private+Public and LAN-only scope.
    calls.clear()

    with mock.patch.object(lan_server, "_run_netsh", side_effect=fake_cmd), \
            mock.patch.object(lan_server, "firewall_rule_exists",
                              side_effect=[False, True]), \
            mock.patch.object(lan_server, "firewall_rule_applies",
                              return_value={"applies": True}):
        info = ensure_firewall_rule_detailed(8686, allow_uac=False)
    add_call = next((c for c in calls if "add" in c), [])
    flat = " ".join(add_call).lower()
    check("缺失规则按实际端口新增",
          info.get("status") == "added" and "localport=8686" in flat)
    check("新增规则覆盖专用+公用网络（公用 Wi-Fi 下手机可连）",
          "profile=private,public" in flat)
    check("新增规则绝不放开任意远程地址",
          "remoteip=localsubnet" in flat and "remoteip=any" not in flat
          and "profile=any" not in flat and "public" in flat)
    check("新增规则远程范围限制为本地子网",
          "remoteip=localsubnet" in flat)

    # Applicability: a private-only rule must be reported as not covering a
    # Public network, and the LAN-only scope must be the thing that protects.
    with mock.patch.object(lan_server, "_rule_scope",
                           return_value=("private", "localsubnet")), \
            mock.patch.object(lan_server, "active_network_profiles",
                              return_value=["public"]):
        private_only = lan_server.firewall_rule_applies(8686)
        check("private-only 规则在公用网络被判为不生效",
              private_only.get("applies") is False,
              str(private_only))
        check("private-only 规则给出可执行的修复说明",
              "公用" in str(private_only.get("detail", ""))
              or "public" in str(private_only.get("detail", "")).lower())
    with mock.patch.object(lan_server, "_rule_scope",
                           return_value=("private,public", "localsubnet")), \
            mock.patch.object(lan_server, "active_network_profiles",
                              return_value=["public"]):
        check("专用+公用规则在公用网络被判定生效",
              lan_server.firewall_rule_applies(8686).get("applies") is True)
    with mock.patch.object(lan_server, "_rule_scope",
                           return_value=("private,public", "any")), \
            mock.patch.object(lan_server, "active_network_profiles",
                              return_value=["public"]):
        check("远程地址 Any 的规则不算局域网加固",
              lan_server.firewall_rule_is_hardened(8686) is False)

    # Rule enumeration only accepts this program's prefix.
    with mock.patch.object(lan_server, "_run_netsh", return_value=mock.Mock(
            returncode=0,
            stdout="Rule Name: CF-FlClash-LAN-8686\nRule Name: Other-App-9999\n"
                   "CF-FlClash-LAN-8687\n", stderr="")):
        ports = list_own_firewall_ports()
    check("只枚举本程序规则端口", ports == [8686, 8687], str(ports))

    # Stale cleanup never touches the kept port or foreign names.
    removed_calls = []

    def fake_remove(port, allow_uac=False):
        removed_calls.append(int(port))
        return True

    with mock.patch.object(lan_server, "list_own_firewall_ports",
                           return_value=[8686, 8687, 9999]), \
            mock.patch.object(lan_server, "_port_in_use", return_value=False), \
            mock.patch.object(lan_server, "remove_firewall_rule", side_effect=fake_remove):
        removed = remove_stale_firewall_rules(keep_port=8687)
    check("端口回退时清理旧端口规则",
          removed == [8686, 9999] and removed_calls == [8686, 9999], str(removed))

    # Delete command names exactly one rule - no wildcard.
    calls.clear()
    with mock.patch.object(lan_server, "_run_netsh", side_effect=fake_cmd):
        ok = remove_firewall_rule(8686)
    check("删除仅针对本程序精确规则名",
          ok and calls and calls[0][:2] == ["delete", "rule"]
          and "name=CF-FlClash-LAN-8686" in calls[0]
          and "*" not in " ".join(calls[0]), str(calls))
    with mock.patch.object(lan_server, "_run_netsh", side_effect=fake_cmd):
        check("端口 0 不会生成删除命令", remove_firewall_rule(0) is False)


def test_bind_hosts(tmp: str):
    print("\n📋 6. 监听地址策略")
    with mock.patch.object(LANServerWorker, "get_lan_ip", return_value="192.168.1.50"):
        auto = LANServerWorker(tmp, host="auto")
        check("auto 优先绑定检测到的局域网地址",
              auto._candidate_hosts()[0] == "192.168.1.50")
        check("auto 失败时回退 loopback",
              auto._candidate_hosts()[-1] == "127.0.0.1")
        legacy = LANServerWorker(tmp, host="0.0.0.0")
        check("显式 0.0.0.0 仍被尊重（配合防火墙限制）",
              legacy._candidate_hosts()[0] == "0.0.0.0")
    with mock.patch.object(LANServerWorker, "get_lan_ip", return_value="127.0.0.1"):
        local = LANServerWorker(tmp, host="auto")
        check("检测不到 LAN 时只绑定 loopback",
              local._candidate_hosts() == ["127.0.0.1"])


def test_gui_defaults(tmp: str):
    print("\n📋 7. GUI 默认状态（缺省配置不启动服务）")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PySide6.QtWidgets import QApplication
        import copy
        import main_gui
    except Exception as exc:
        check("GUI 默认状态测试导入", False, str(exc))
        return
    app = QApplication.instance() or QApplication(sys.argv)
    cfg = copy.deepcopy(path_utils.load_config())
    cfg.pop("lan_server_enabled", None)      # a fresh install has no such key
    cfg["auto_guard_enabled"] = False
    calls = []
    originals = {}
    window = None
    try:
        for name, stub in (("_start_lan_server", lambda self: calls.append("lan")),
                           ("_stop_lan_server", lambda self: None),
                           ("_start_guard", lambda self: None),
                           ("_stop_guard", lambda self: None),
                           ("_build_guard", lambda self: None)):
            originals[name] = getattr(main_gui.MainWindow, name)
            setattr(main_gui.MainWindow, name, stub)
        originals["load_config"] = main_gui.load_config
        originals["save_config"] = main_gui.save_config
        main_gui.load_config = lambda: dict(cfg)
        main_gui.save_config = lambda c: None
        window = main_gui.MainWindow()
        check("缺省配置下 LAN 服务未启动", "lan" not in calls, str(calls))
        check("缺省配置下复选框未勾选", not window.lan_chk.isChecked())
        check("缺省配置下 4 条订阅复制按钮均不可用",
              len(window.lan_copy_btns) == 4
              and all(not btn.isEnabled() for btn in window.lan_copy_btns)
              and all(not btn.isEnabled() for btn in window.lan_qr_btns))
        check("缺省配置下订阅链接框为空",
              all(not edit.text() for edit in window.lan_link_edits))
        check("订阅链接框为可选中复制（只读但不禁用文本）",
              all(edit.isReadOnly() for edit in window.lan_link_edits))
    finally:
        if window is not None:
            window._force_quit = True
            window._shutdown_background()
            window._cleanup_tray()
            window.close()
            for _ in range(10):
                app.processEvents()
                time.sleep(0.02)
        for name, original in originals.items():
            if name in ("load_config", "save_config"):
                setattr(main_gui, name, original)
            else:
                setattr(main_gui.MainWindow, name, original)


def test_lan_bind_auto(tmp: str):
    print("\n📋 8. 实机局域网地址绑定（auto）")
    exports = make_exports(tmp)
    token = generate_token()
    lan_ip = lan_server.get_real_lan_ip()
    if lan_ip == "127.0.0.1":
        check("未检测到 LAN 地址，跳过实机绑定测试", True, "skipped")
        return
    worker = LANServerWorker(
        exports, free_port(), host="auto", port_fallback=2, ensure_firewall=False,
        token_provider=lambda: token)
    session = requests.Session()
    session.trust_env = False
    try:
        worker.start()
        actual = wait_started(worker)
        check("auto 模式绑定到局域网地址",
              actual > 0 and worker._bound_host == lan_ip, worker._bound_host)
        resp = session.get(f"http://{lan_ip}:{actual}/s/{token}/ios.yaml", timeout=5)
        check("通过局域网 IP 可获取订阅", resp.status_code == 200 and "proxies:" in resp.text)
        unauth = session.get(f"http://{lan_ip}:{actual}/ios.yaml", timeout=5)
        check("局域网 IP 上未认证请求仍被拒绝",
              unauth.status_code == 404 and "proxies:" not in unauth.text)
    finally:
        worker.stop()


def main() -> int:
    print("=" * 66)
    print("🔐 LAN 订阅服务安全测试（合成数据，无真实凭据）")
    print("=" * 66)
    tmp = tempfile.mkdtemp(prefix="cffo-lan-sec-")
    test_defaults(tmp)
    test_tokens()
    test_http_security(tmp)
    test_port_fallback_and_firewall_port(tmp)
    test_firewall_helpers()
    test_bind_hosts(tmp)
    test_gui_defaults(tmp)
    test_lan_bind_auto(tmp)

    total = len(FAILS)
    print("\n" + "=" * 66)
    print(f"结果: {'全部通过' if total == 0 else str(total) + ' 项失败'}")
    if total:
        print("失败项: " + "; ".join(FAILS))
    print("=" * 66)
    return 0 if total == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
