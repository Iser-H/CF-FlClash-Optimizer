# -*- coding: utf-8 -*-
"""Verification script for the token-protected LAN subscription server.

Uses only synthetic export files (TEST-NET IPs, dummy UUID) so no real airport
subscription, UUID, password or VPS credential is involved. Firewall calls are
dry-run only; nothing on the host firewall is modified.
"""

import base64
import json
import os
import socket
import sys
import tempfile
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import requests

from lan_server import (
    LANServerWorker, ensure_firewall_rule_detailed, generate_token,
    get_real_lan_ip, is_valid_token,
)

FAILS = []


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


def make_exports(tmp: str) -> str:
    exports = os.path.join(tmp, "exports")
    os.makedirs(exports, exist_ok=True)
    files = {
        "FlClash_Optimized.yaml": SYNTHETIC_YAML,
        "iOS_Clash_Config.yaml": SYNTHETIC_YAML,
        "tv_happ.txt": (
            "#subscription-auto-update-open-enable: 1\n"
            "#subscription-autoconnect: 1\n"
            "#subscription-autoconnect-type: lowestdelay\n" + VLESS_LINK + "\n"
        ),
        "happ_xray.json": json.dumps({
            "dns": {"queryStrategy": "UseIPv4"},
            "outbounds": [{"protocol": "vless", "tag": "cf-test", "settings": {
                "vnext": [{"address": "203.0.113.10", "port": 443,
                           "users": [{"id": DUMMY_UUID, "encryption": "none"}]}]},
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


def main() -> int:
    print("=" * 66)
    print("🧪 LAN Subscription Server (Token auth) — synthetic-data verification")
    print("=" * 66)
    tmp = tempfile.mkdtemp(prefix="cffo-lan-real-")
    token = generate_token()
    exports = make_exports(tmp)
    port = free_port()

    print("\n1. Token / LAN IP helpers")
    check("Token 长度 >= 43（>= 256 bit）", len(token) >= 43, str(len(token)))
    check("Token 为 URL-safe 且校验通过", is_valid_token(token))
    ip = get_real_lan_ip()
    print(f"   detected LAN IP: {ip}")
    check("IP 检测不为 TUN/APIPA", not ip.startswith(("198.18.", "169.254.")), ip)

    print("\n2. Firewall dry-run (no system change)")
    info = ensure_firewall_rule_detailed(59999, allow_uac=False, dry_run=True)
    check("dry-run 状态为 missing", info.get("status") == "missing", str(info))
    check("规则作用域固定为 LocalSubnet", info.get("remoteip") == "LocalSubnet")
    check("规则配置固定为 private", info.get("profile") == "private")

    print(f"\n3. Start server on 127.0.0.1:{port} (no firewall changes)")
    worker = LANServerWorker(exports, port, profile_mgr=None, profile_factory=None,
                             profile_path="", host="127.0.0.1", port_fallback=3,
                             ensure_firewall=False, token_provider=lambda: token)
    worker.start()
    actual = wait_started(worker)
    check("服务已监听", actual == port, str(actual))
    root = f"http://127.0.0.1:{actual}"
    base = f"{root}/s/{token}"
    try:
        print("\n4. Authentication")
        unauth = requests.get(f"{root}/ios.yaml", timeout=5)
        check("无 Token 旧路径 404", unauth.status_code == 404)
        check("无 Token 不返回配置", "proxies:" not in unauth.text)
        wrong_token = generate_token()
        while wrong_token == token:
            wrong_token = generate_token()
        wrong = requests.get(f"{root}/s/{wrong_token}/ios.yaml", timeout=5)
        check("错误 Token 404", wrong.status_code == 404 and "proxies:" not in wrong.text)
        check("根仪表盘需要 Token", requests.get(f"{root}/", timeout=5).status_code == 404)

        print("\n5. Four subscription formats")
        for name, ctype in (("flclash.yaml", "yaml"), ("ios.yaml", "yaml"),
                            ("tv_happ.txt", "text"), ("happ.json", "json")):
            resp = requests.get(f"{base}/{name}", timeout=5)
            check(f"GET /s/<token>/{name} 200", resp.status_code == 200)
            check(f"{name} Content-Type 含 {ctype}", ctype in resp.headers.get("Content-Type", ""))
        check("happ.json 可解析", requests.get(f"{base}/happ.json", timeout=5).json()
              ["dns"]["queryStrategy"] == "UseIPv4")
        check("tv_happ.txt 含 mux=0",
              "mux=0" in requests.get(f"{base}/tv_happ.txt", timeout=5).text)

        head = requests.head(f"{base}/ios.yaml", timeout=5)
        check("HEAD 无 body 且有 Content-Length",
              head.content == b"" and int(head.headers.get("Content-Length", 0)) > 0)
        check("响应不含 CORS 通配符",
              "Access-Control-Allow-Origin" not in head.headers)
        check("响应带 nosniff", head.headers.get("X-Content-Type-Options") == "nosniff")

        print("\n6. Extra formats / dashboard / 404")
        check("Base64 订阅可解码",
              base64.b64decode(requests.get(f"{base}/tv", timeout=5).text).decode().count("vless://") >= 1)
        check("VLESS 列表可读", requests.get(f"{base}/vless", timeout=5).text.count("vless://") >= 1)
        dash = requests.get(f"{base}/", timeout=5)
        check("Token 下仪表盘 200", dash.status_code == 200 and "tv_happ.txt" in dash.text)
        check("Token 下未知端点 404",
              requests.get(f"{base}/nope", timeout=5).status_code == 404)
    finally:
        worker.stop()
    time.sleep(0.2)
    try:
        requests.get(f"{base}/ios.yaml", timeout=2)
        down = False
    except Exception:
        down = True
    check("stop() 后端口不可访问", down)

    print("\n" + "=" * 66)
    print(f"结果: {'全部通过' if not FAILS else str(len(FAILS)) + ' 项失败'}")
    print("=" * 66)
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
