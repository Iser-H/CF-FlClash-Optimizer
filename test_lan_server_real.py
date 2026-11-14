# -*- coding: utf-8 -*-
"""Verification script for LAN Subscription Server & Firewall."""

import sys
import os
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import requests
import base64
import subprocess

from path_utils import EXPORTS_DIR, BACKUPS_DIR, load_config
from profile_manager import ProfileManager
from lan_server import LANServerWorker, get_real_lan_ip, ensure_firewall_rule

def run_tests():
    print("=" * 60)
    print("🧪 LAN Subscription & Firewall Real-world Verification")
    print("=" * 60)

    # 1. Test LAN IP detection
    lan_ip = get_real_lan_ip()
    print(f"1. Detected Physical LAN IP: {lan_ip}")
    assert lan_ip != "127.0.0.1", f"Expected real LAN IP, got {lan_ip}"
    assert not lan_ip.startswith("198.18."), f"TUN IP was not filtered: {lan_ip}"
    assert not lan_ip.startswith("169.254."), f"APIPA IP was not filtered: {lan_ip}"
    print("   ✅ IP resolution passed (physical interface detected)")

    cfg = load_config()
    port = int(cfg.get("lan_server_port", 8686))

    # 2. Test Firewall Rule
    print("\n2. Testing Windows Firewall Rule:")
    fw_ok = ensure_firewall_rule(port)
    print(f"   ensure_firewall_rule({port}) -> {fw_ok}")
    assert fw_ok, "Firewall rule creation failed!"

    res = subprocess.run(
        ["netsh", "advfirewall", "firewall", "show", "rule", "name=CF-FlClash-LAN-Sub"],
        capture_output=True,
        encoding="gbk",
        errors="ignore",
    )
    print("   Firewall Rule Details:")
    for line in res.stdout.splitlines():
        if any(k in line for k in ["规则名称", "已启用", "方向", "操作", "协议", "本地端口", "配置文件", "Rule Name", "Enabled", "Direction", "Action", "Protocol", "LocalPort", "Profiles"]):
            print(f"     {line.strip()}")
    assert res.returncode == 0, "Firewall rule does not exist in netsh output!"
    print("   ✅ Windows Firewall rule verified")

    # 3. Start Server
    print(f"\n3. Starting LANServerWorker on 0.0.0.0:{port}...")
    pm = ProfileManager(cfg["flclash_profile_path"], BACKUPS_DIR, cfg["cf_node_names"],
                        options=cfg)

    server_worker = LANServerWorker(EXPORTS_DIR, port, profile_mgr=pm,
                                    profile_path=cfg["flclash_profile_path"],
                                    port_fallback=5)
    server_worker.start()
    time.sleep(1.5)  # Wait for socket to bind / export refresh

    actual_port = server_worker.actual_port or port
    base_url = f"http://{lan_ip}:{actual_port}"
    print(f"   Server active at: {base_url}")

    # 4. Test HEAD /ios.yaml
    print(f"\n4. Testing HEAD {base_url}/ios.yaml:")
    resp_head = requests.head(f"{base_url}/ios.yaml", timeout=5)
    print(f"   Status: {resp_head.status_code}")
    print(f"   Headers: {dict(resp_head.headers)}")
    assert resp_head.status_code == 200, f"Expected 200, got {resp_head.status_code}"
    assert len(resp_head.content) == 0, f"HEAD response must have zero body, got {len(resp_head.content)} bytes"
    assert "Content-Length" in resp_head.headers, "Missing Content-Length in HEAD response"
    content_len = int(resp_head.headers["Content-Length"])
    assert content_len > 0, f"Content-Length must be > 0, got {content_len}"
    assert "yaml" in resp_head.headers.get("Content-Type", ""), "Content-Type must contain yaml"
    assert "CF-Optimized.yaml" in resp_head.headers.get("Content-Disposition", ""), "Missing Content-Disposition"
    assert resp_head.headers.get("Profile-Update-Interval") == "24", "Missing Profile-Update-Interval: 24"
    assert resp_head.headers.get("Access-Control-Allow-Origin") == "*", "Missing CORS header"
    print(f"   ✅ HEAD /ios.yaml passed (Content-Length: {content_len})")

    # 5. Test GET /ios.yaml
    print(f"\n5. Testing GET {base_url}/ios.yaml:")
    resp_get = requests.get(f"{base_url}/ios.yaml", timeout=5)
    print(f"   Status: {resp_get.status_code}")
    print(f"   Body Length: {len(resp_get.content)} bytes")
    assert resp_get.status_code == 200
    assert len(resp_get.content) == content_len, f"Body length {len(resp_get.content)} != Content-Length {content_len}"
    assert b"proxies:" in resp_get.content, "Body does not contain 'proxies:' key"
    print("   ✅ GET /ios.yaml passed (exact length matches HEAD)")

    # 6. Test Alias /clash
    print(f"\n6. Testing GET {base_url}/clash (alias):")
    resp_clash = requests.get(f"{base_url}/clash", timeout=5)
    assert resp_clash.status_code == 200
    assert len(resp_clash.content) == content_len
    print("   ✅ GET /clash alias passed")

    # 7. Test HEAD & GET /tv
    print(f"\n7. Testing HEAD & GET {base_url}/tv:")
    resp_tv_head = requests.head(f"{base_url}/tv", timeout=5)
    assert resp_tv_head.status_code == 200
    tv_len = int(resp_tv_head.headers.get("Content-Length", 0))
    assert tv_len > 0
    assert len(resp_tv_head.content) == 0

    resp_tv = requests.get(f"{base_url}/tv", timeout=5)
    assert resp_tv.status_code == 200
    assert len(resp_tv.content) == tv_len
    decoded_tv = base64.b64decode(resp_tv.text).decode("utf-8")
    assert "vless://" in decoded_tv
    print(f"   ✅ /tv passed (Length: {tv_len}, Decoded VLESS links present)")

    # 8. Test HEAD & GET /vless
    print(f"\n8. Testing HEAD & GET {base_url}/vless:")
    resp_vless_head = requests.head(f"{base_url}/vless", timeout=5)
    assert resp_vless_head.status_code == 200
    vless_len = int(resp_vless_head.headers.get("Content-Length", 0))
    assert vless_len > 0
    assert len(resp_vless_head.content) == 0

    resp_vless = requests.get(f"{base_url}/vless", timeout=5)
    assert resp_vless.status_code == 200
    assert len(resp_vless.content) == vless_len
    assert resp_vless.text.count("vless://") >= 3
    print(f"   ✅ /vless passed (Length: {vless_len}, 3 VLESS links present)")

    # 8.5 Test Happ subscription + Xray JSON
    print(f"\n8.5 Testing GET {base_url}/tv_happ.txt & /happ.json:")
    resp_happ = requests.get(f"{base_url}/tv_happ.txt", timeout=5)
    assert resp_happ.status_code == 200
    assert "#subscription-autoconnect-type: lowestdelay" in resp_happ.text
    assert "mux=0" in resp_happ.text
    resp_json = requests.get(f"{base_url}/happ.json", timeout=5)
    assert resp_json.status_code == 200
    assert resp_json.json()["dns"]["queryStrategy"] == "UseIPv4"
    print("   ✅ /tv_happ.txt 与 /happ.json passed")

    # 9. Test Root Dashboard /
    print(f"\n9. Testing GET {base_url}/ (Root HTML dashboard):")
    resp_root = requests.get(f"{base_url}/", timeout=5)
    assert resp_root.status_code == 200
    assert "text/html" in resp_root.headers.get("Content-Type", "")
    assert "CF-FlClash-Optimizer" in resp_root.text
    print("   ✅ GET / dashboard passed")

    # 10. Test 404
    print(f"\n10. Testing GET {base_url}/not_found:")
    resp_404 = requests.get(f"{base_url}/not_found", timeout=5)
    assert resp_404.status_code == 404
    print("   ✅ 404 handler passed")

    # Stop server
    server_worker.stop()
    print("\n" + "=" * 60)
    print("🎉 ALL LAN SUBSCRIPTION & FIREWALL TESTS PASSED 100%!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
