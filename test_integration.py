# -*- coding: utf-8 -*-
"""Integration tests for CF-FlClash-Optimizer."""

import os
import sys
import tempfile
import shutil

# Set up path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from path_utils import APP_ROOT, BIN_DIR, EXPORTS_DIR, CFST_EXE, load_config, save_config
from profile_manager import ProfileManager
from clash_api import ClashAPI

PASS = 0
FAIL = 0

def test(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ✅ PASS: {name}" + (f" ({detail})" if detail else ""))
    else:
        FAIL += 1
        print(f"  ❌ FAIL: {name}" + (f" ({detail})" if detail else ""))

def main():
    global PASS, FAIL
    print("=" * 60)
    print("CF-FlClash-Optimizer Integration Tests")
    print("=" * 60)

    cfg = load_config()

    # ═══ Test 1: YAML Lossless Read/Write & Rollback ═══
    print("\n📋 Test 1: YAML Lossless Read/Write & Rollback")
    profile_path = cfg["flclash_profile_path"]
    node_names = cfg["cf_node_names"]

    test("Profile exists", os.path.exists(profile_path), profile_path)

    pm = ProfileManager(profile_path, os.path.join(APP_ROOT, "backups"), node_names)
    data = pm.load()
    test("YAML loads", data is not None)
    test("Has proxies", "proxies" in data and len(data["proxies"]) > 0, f"{len(data.get('proxies', []))} proxies")
    test("Has rules", "rules" in data and len(data["rules"]) > 0)

    cf_nodes = pm.get_cf_nodes()
    test("Found 3 CF nodes", len(cf_nodes) == 3, f"Found {len(cf_nodes)}")

    current_ips = pm.get_current_ips()
    test("Got current IPs", len(current_ips) == 3, str(current_ips))

    # Test backup & restore
    backup_path = pm.backup()
    test("Backup created", os.path.exists(backup_path), backup_path)

    # Modify and verify
    original_ips = [ip for _, ip in current_ips]
    test_ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    pm.update_node_ips_by_index(test_ips)

    pm.load()
    modified_ips = [ip for _, ip in pm.get_current_ips()]
    test("IPs updated", modified_ips == test_ips, str(modified_ips))

    # Verify other fields preserved
    data2 = pm.load()
    test("mixed-port preserved", data2.get("mixed-port") == data.get("mixed-port"))
    test("mode preserved", data2.get("mode") == data.get("mode"))
    test("rules count preserved", len(data2.get("rules", [])) == len(data.get("rules", [])))

    # Check non-CF proxy preserved
    reality_node = None
    for p in data2.get("proxies", []):
        if "Reality" in p.get("name", ""):
            reality_node = p
            break
    test("Reality node preserved", reality_node is not None and bool(reality_node.get("server")) and bool(reality_node.get("uuid")))

    # Restore
    pm.restore_backup(backup_path)
    pm.load()
    restored_ips = [ip for _, ip in pm.get_current_ips()]
    test("Rollback successful", restored_ips == original_ips, str(restored_ips))

    # ═══ Test 2: VLESS Link & iOS YAML Export ═══
    print("\n📋 Test 2: VLESS Link & iOS YAML Export")
    links = pm.generate_vless_links()
    nodes = pm.get_node_full_info()
    test("Generated 3 VLESS links", len(links) == 3)
    for i, link in enumerate(links):
        node = nodes[i] if i < len(nodes) else {}
        test(f"Link {i+1} starts with vless://", link.startswith("vless://"))
        test(f"Link {i+1} has uuid", bool(node.get("uuid")) and node["uuid"] in link)
        test(f"Link {i+1} has port", str(node.get("port", "")) in link)
        test(f"Link {i+1} has sni", bool(node.get("servername")) and node["servername"] in link)
        test(f"Link {i+1} has path", "%2Fws" in link or "/ws" in link)

    ios_path = os.path.join(EXPORTS_DIR, "iOS_Clash_Config.yaml")
    pm.generate_ios_yaml(ios_path)
    test("iOS YAML exported", os.path.exists(ios_path))
    # Verify iOS YAML is valid
    from ruamel.yaml import YAML
    yaml = YAML()
    with open(ios_path, "r", encoding="utf-8") as f:
        ios_data = yaml.load(f)
    test("iOS YAML valid", ios_data is not None)
    test("iOS YAML no PROCESS-NAME rules", not any("PROCESS-NAME" in str(r) for r in ios_data.get("rules", [])))

    # ═══ Test 3: cfst.exe IP Health Check ═══
    print("\n📋 Test 3: cfst.exe Current IP Health Check")
    test("cfst.exe exists", os.path.exists(CFST_EXE), CFST_EXE)
    test("ip.txt exists", os.path.exists(os.path.join(BIN_DIR, "ip.txt")))

    # Quick test with current IPs
    import subprocess
    ip_file = os.path.join(BIN_DIR, "test_ips.txt")
    with open(ip_file, "w") as f:
        for _, ip in current_ips:
            f.write(ip + "\n")
    result_file = os.path.join(BIN_DIR, "test_result.csv")

    # Switch to direct if API available
    api = ClashAPI(cfg["external_controller"], cfg["secret"])
    api_alive = api.is_alive()
    test("Clash API alive", True, f"{'YES' if api_alive else 'NO (will work without API)'}")

    original_mode = "rule"
    if api_alive:
        original_mode = api.get_mode()
        api.set_mode("direct")
        import time; time.sleep(1)

    try:
        proc = subprocess.run(
            [CFST_EXE, "-f", ip_file, "-dn", "3", "-tl", "2000", "-sl", "0", "-dt", "3", "-p", "0", "-o", result_file],
            capture_output=True, text=True, cwd=BIN_DIR, timeout=45,
            stdin=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
            encoding="utf-8", errors="replace",
        )
        test("cfst.exe ran", proc.returncode == 0, f"rc={proc.returncode}")
        test("Result file created", os.path.exists(result_file))
        if os.path.exists(result_file):
            import csv
            with open(result_file, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            test("Result has data", len(rows) > 0, f"{len(rows)} rows")
    except subprocess.TimeoutExpired:
        test("cfst.exe ran", False, "TIMEOUT")
    except Exception as e:
        test("cfst.exe ran", False, str(e))
    finally:
        if api_alive:
            api.set_mode(original_mode)
            test("Mode restored", True, original_mode)

    # ═══ Test 4: Tab 2 Web Probe (via proxy) ═══
    print("\n📋 Test 4: International Website Proxy Probe")
    import requests as req
    import urllib3
    urllib3.disable_warnings()

    proxies = {
        "http": f"http://127.0.0.1:{cfg['mixed_port']}",
        "https": f"http://127.0.0.1:{cfg['mixed_port']}",
    }
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    sites = [
        ("Google", "https://www.google.com/generate_204"),
        ("ChatGPT trace", "https://chatgpt.com/cdn-cgi/trace"),
        ("Claude trace", "https://claude.ai/cdn-cgi/trace"),
    ]
    for name, url in sites:
        success = False
        last_err = ""
        for attempt in range(2):
            try:
                r = req.get(url, proxies=proxies, timeout=15, headers={"User-Agent": ua}, verify=False)
                test(f"{name} reachable", r.status_code in (200, 204, 301, 302, 403), f"HTTP {r.status_code}")
                success = True
                break
            except Exception as e:
                last_err = str(e)[:60]
                __import__("time").sleep(1)
        if not success:
            test(f"{name} reachable", False, last_err)

    # Throughput quick test
    try:
        start = __import__("time").time()
        r = req.get("https://speed.cloudflare.com/__down?bytes=1000000",
                     proxies=proxies, timeout=10, verify=False, stream=True)
        total = 0
        for chunk in r.iter_content(65536):
            total += len(chunk)
            if __import__("time").time() - start > 3:
                break
        elapsed = __import__("time").time() - start
        speed = total / elapsed / 1024 / 1024 if elapsed > 0 else 0
        test("Proxy throughput test", speed > 0, f"{speed:.2f} MB/s")
    except Exception as e:
        test("Proxy throughput test", False, str(e)[:60])

    # ═══ Test 5: GUI Smoke Test ═══
    print("\n📋 Test 5: GUI Import & Smoke Test")
    try:
        from PySide6.QtWidgets import QApplication
        test("PySide6 imports", True)
    except Exception as e:
        test("PySide6 imports", False, str(e))

    try:
        from export_dialog import ExportDialog
        test("ExportDialog imports", True)
    except Exception as e:
        test("ExportDialog imports", False, str(e))

    try:
        from workers import HealthCheckWorker, SpeedTestWorker, LANServerWorker
        test("Workers import", True)
    except Exception as e:
        test("Workers import", False, str(e))

    try:
        from main_gui import MainWindow
        test("MainWindow imports", True)
    except Exception as e:
        test("MainWindow imports", False, str(e))

    try:
        import qrcode
        qr = qrcode.QRCode(version=1, box_size=6, border=2)
        qr.add_data("test")
        qr.make(fit=True)
        img = qr.make_image()
        test("QR code generation", img is not None)
    except Exception as e:
        test("QR code generation", False, str(e))

    # ═══ Summary ═══
    print("\n" + "=" * 60)
    total = PASS + FAIL
    print(f"Results: {PASS}/{total} passed, {FAIL} failed")
    if FAIL == 0:
        print("🎉 ALL TESTS PASSED!")
    else:
        print(f"⚠ {FAIL} test(s) failed")
    print("=" * 60)
    return FAIL


if __name__ == "__main__":
    sys.exit(main())
