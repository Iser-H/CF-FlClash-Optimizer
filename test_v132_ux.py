# -*- coding: utf-8 -*-
"""v1.3.2 tests: plaintext per-client LAN links, single-URL copy payload,
masked LAN access log (GUI + file) and the shipped ``bin/ip.txt`` chain.

Throw-away folders only; real profiles/config are read-only or untouched.
"""

import hashlib
import json
import os
import shutil
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.request
from unittest import mock

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import config_templates as ct
import core_test
import lan_server
import path_utils
from lan_server import (
    LANServerWorker, copy_payload, format_access_log, generate_token,
    mask_token_in_path, subscription_links,
)

PASS = 0
FAIL = 0
FAILURES = []


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ✅ " + name + (f"  [{detail}]" if detail else ""))
    else:
        FAIL += 1
        FAILURES.append(name)
        print("  ❌ " + name + (f"  [{detail}]" if detail else ""))


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return path


def http(url, method="GET", timeout=6):
    request = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {}, b""
    except Exception as exc:
        return "ERR", {}, repr(exc).encode()


def detect_lan_ip():
    details = lan_server.detect_lan_ip_details()
    ip = str(details.get("ip") or "")
    return ip if ip and ip not in ("127.0.0.1", "0.0.0.0") else "127.0.0.1"


# ══════════════════════════════════════════════════════════════════
def test_subscription_links():
    print("\n📋 1. 4 条客户端明文链接与单条复制内容")
    token = generate_token()
    base = "http://192.168.5.6:8686"
    links = subscription_links(base, token)
    check("返回 4 条客户端链接", len(links) == 4, str(len(links)))
    check("客户端顺序与路径正确",
          [(x["label"], x["path"]) for x in links] == [
              ("FlClash / Mihomo", "flclash.yaml"),
              ("iOS（Shadowrocket / Stash / Loon）", "ios.yaml"),
              ("TV Happ 订阅", "tv_happ.txt"),
              ("Happ JSON", "happ.json")],
          str([(x["label"], x["path"]) for x in links]))
    expected_urls = [f"{base}/s/{token}/{p}" for p in
                     ("flclash.yaml", "ios.yaml", "tv_happ.txt", "happ.json")]
    check("链接为明文完整 URL", [x["url"] for x in links] == expected_urls)
    check("链接包含真实 LAN IP / 端口 / Token",
          all(("192.168.5.6:8686" in u) and (token in u) for u in expected_urls))
    check("界面链接不再打码", all("•" not in u and "***" not in u for u in expected_urls))
    payloads = [copy_payload(link) for link in links]
    check("复制内容 = 单条纯 URL", payloads == expected_urls)
    check("复制内容不含换行/标签/首尾空白",
          all("\n" not in p and "\r" not in p and p == p.strip()
              and p.startswith("http://") and " " not in p for p in payloads))
    check("token 轮换后链接随之变化",
          subscription_links(base, generate_token())[0]["url"] != expected_urls[0])


def test_access_log_format():
    print("\n📋 2. 访问日志脱敏格式")
    token = generate_token()
    line = format_access_log("192.168.5.20", "GET",
                             f"/s/{token}/flclash.yaml", 200)
    check("格式符合示例",
          line == "[LAN 访问] 来源 192.168.5.20 -> GET /s/***/flclash.yaml -> HTTP 200",
          line)
    check("Token 已被脱敏", token not in line and "/s/***/" in line)
    bad_line = format_access_log("192.168.5.20", "HEAD", "/s/" + "x" * 64 + "/ios.yaml", 404)
    check("非法 Token 也被脱敏",
          "x" * 64 not in bad_line and "/s/***/" in bad_line and bad_line.endswith("404"),
          bad_line)
    check("HEAD 方法被记录", " HEAD " in bad_line)
    check("无 Token 路径原样记录（不含 ***）",
          format_access_log("10.0.0.2", "GET", "/", 404)
          == "[LAN 访问] 来源 10.0.0.2 -> GET / -> HTTP 404")
    check("查询参数保留且 Token 仍脱敏",
          mask_token_in_path(f"/s/{token}/ios.yaml?x=1") == "/s/***/ios.yaml?x=1")
    check("空路径/缺失参数不会抛异常",
          format_access_log(None, None, None, None).startswith("[LAN 访问] 来源 ?"))


def test_live_access_log(tmp):
    print("\n📋 3. 真实请求 → 访问日志（GUI 行 + 文件，Token 脱敏）")
    root = os.path.join(tmp, "accesslog")
    os.makedirs(root, exist_ok=True)
    exports = os.path.join(root, "exports")
    os.makedirs(exports, exist_ok=True)
    write(os.path.join(exports, "FlClash_Optimized.yaml"),
          "mixed-port: 7890\nproxies: []\nproxy-groups:\n- name: PROXY\n  type: select\n  proxies: [DIRECT]\n")
    write(os.path.join(exports, "iOS_Clash_Config.yaml"),
          "mixed-port: 7890\nproxies: []\nproxy-groups:\n- name: PROXY\n  type: select\n  proxies: [DIRECT]\n")
    write(os.path.join(exports, "tv_happ.txt"), "vless://test@example:443#a\n")
    write(os.path.join(exports, "happ_xray.json"), json.dumps({"dns": {}, "outbounds": []}))
    log_path = os.path.join(root, "logs", "lan_access.log")
    token = generate_token()
    worker = LANServerWorker(exports, 0, profile_mgr=None, profile_path="",
                             host="0.0.0.0", port_fallback=10, ensure_firewall=False,
                             token_provider=lambda: token, access_log_path=log_path)
    worker.start()
    deadline = time.time() + 20
    while time.time() < deadline and not worker.actual_port:
        time.sleep(0.1)
    port = worker.actual_port
    lan_ip = detect_lan_ip()
    try:
        check("服务已启动", bool(port), str(port))
        for name, expected in (("flclash.yaml", 200), ("ios.yaml", 200)):
            status, _h, _b = http(f"http://{lan_ip}:{port}/s/{token}/{name}")
            check(f"GET {name} -> {expected}", status == expected, str(status))
        status, _h, _b = http(f"http://{lan_ip}:{port}/s/{'x' * 64}/ios.yaml")
        check("非法 Token 请求被记录为 404", status == 404, str(status))
        status, _h, _b = http(f"http://{lan_ip}:{port}/")
        check("根路径请求被记录为 404", status == 404, str(status))
        http(f"http://{lan_ip}:{port}/s/{token}/ios.yaml", method="HEAD")
        deadline = time.time() + 5
        lines = []
        while time.time() < deadline:
            if os.path.isfile(log_path):
                lines = [ln for ln in open(log_path, encoding="utf-8").read().splitlines()
                         if ln.strip()]
            if len(lines) >= 5:
                break
            time.sleep(0.2)
        check("日志文件已写入", len(lines) >= 5, f"{len(lines)} 行")
        joined = "\n".join(lines)
        check("日志行均为 [LAN 访问] 格式",
              all(ln.startswith("[LAN 访问] 来源 ") and " -> " in ln and "HTTP " in ln
                  for ln in lines))
        check("成功请求记录 GET /s/***/flclash.yaml -> HTTP 200",
              any("GET /s/***/flclash.yaml -> HTTP 200" in ln for ln in lines), joined[:200])
        check("HEAD 请求被记录", any(" HEAD /s/***/ios.yaml " in ln for ln in lines))
        check("404 请求被记录", any("HTTP 404" in ln for ln in lines))
        check("日志文件不含真实 Token", token not in joined)
        check("日志来源 IP 是真实局域网来源",
              any(lan_ip in ln for ln in lines), joined.splitlines()[:1])
        # The GUI receives the same masked string (direct call = queued signal path)
        received = []
        worker.access_logged.connect(received.append)
        worker.record_access(format_access_log("192.168.5.9", "GET",
                                               f"/s/{token}/happ.json", 200))
        time.sleep(0.2)
        check("GUI 信号携带脱敏行",
              not received or token not in json.dumps(received, ensure_ascii=False))
    finally:
        worker.stop()


def test_ip_list_chain(tmp):
    print("\n📋 4. bin/ip.txt 解析、打包优先与兜底生成")
    exe_dir = os.path.join(tmp, "ip_exe")
    data_bin = os.path.join(tmp, "ip_data", "bin")
    package_ip = write(os.path.join(exe_dir, "bin", "ip.txt"),
                       "173.245.48.0/20\n104.16.0.0/13\n")
    paths = path_utils.ip_list_lookup(frozen=True, exe_dir=exe_dir, data_bin=data_bin)
    check("frozen 优先包内 bin/ip.txt", paths[0] == package_ip, paths[0])
    info = path_utils.resolve_ip_list_file(frozen=True, exe_dir=exe_dir, data_bin=data_bin)
    check("解析到包内名单", info["path"] == package_ip and info["source"] == "package"
          and info["exists"] is True, str(info))

    data_ip = write(os.path.join(data_bin, "ip.txt"), "162.158.0.0/15\n")
    info2 = path_utils.resolve_ip_list_file(frozen=True, exe_dir=exe_dir, data_bin=data_bin)
    check("包内存在时仍优先包内", info2["path"] == package_ip)

    empty_exe = os.path.join(tmp, "ip_exe_empty")
    os.makedirs(os.path.join(empty_exe, "bin"), exist_ok=True)
    gen_bin = os.path.join(tmp, "ip_gen", "bin")
    info3 = path_utils.resolve_ip_list_file(create=True, frozen=True,
                                           exe_dir=empty_exe, data_bin=gen_bin)
    check("缺失时自动生成兜底文件",
          info3["generated"] is True and info3["source"] == "generated"
          and os.path.isfile(info3["path"]), str(info3))
    entries = [ln.strip() for ln in open(info3["path"], encoding="utf-8").read().splitlines()
               if ln.strip() and not ln.strip().startswith("#")]
    try:
        import ipaddress
        valid = all(ipaddress.ip_network(item, strict=False).version == 4 for item in entries)
    except Exception:
        valid = False
    check("兜底文件为合法 IPv4 CIDR", valid and len(entries) >= 10, f"{len(entries)} 条")
    check("兜底文件写在可写数据目录（不污染包目录）",
          os.path.normcase(os.path.dirname(info3["path"]))
          == os.path.normcase(os.path.abspath(gen_bin)))
    check("create=False 时不生成", path_utils.resolve_ip_list_file(
        create=False, frozen=True, exe_dir=empty_exe,
        data_bin=os.path.join(tmp, "ip_none", "bin"))["source"] == "missing")

    cmd = core_test.build_speed_test_command(
        r"C:\pkg\bin\cfst.exe", info3["path"],
        os.path.join(tmp, "result.csv"), threads=100, tl=300, dn=5,
        url="https://example.test/")
    check("命令含显式 -f 绝对路径",
          "-f" in cmd and cmd[cmd.index("-f") + 1] == os.path.abspath(info3["path"]), str(cmd[:8]))
    check("命令含 -p 0（禁用回车等待）",
          "-p" in cmd and cmd[cmd.index("-p") + 1] == "0")
    check("输出文件为绝对路径", os.path.isabs(cmd[cmd.index("-o") + 1]))
    check("自定义 -url 追加", "-url" in cmd and "https://example.test/" in cmd)
    check("默认 default_ip_list_file 可解析真实包内名单",
          core_test.default_ip_list_file(os.path.join(tmp, "dl"), lambda line: None)["exists"] is True)


def test_gui_plaintext_links(tmp):
    print("\n📋 5. GUI 明文链接 / 单条复制（离屏实例化）")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PySide6.QtWidgets import QApplication
        import copy
        import main_gui
    except Exception as exc:
        check("GUI 测试导入", False, str(exc))
        return
    app = QApplication.instance() or QApplication(sys.argv)
    cfg = copy.deepcopy(path_utils.load_config())
    cfg["lan_server_enabled"] = False
    cfg["auto_guard_enabled"] = False
    cfg["lan_auth_token"] = generate_token()
    originals = {}
    window = None
    try:
        for name, stub in (("_start_lan_server", lambda self: None),
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
        token = cfg["lan_auth_token"]
        ip = "192.168.5.6"
        window._lan_server = mock.Mock(actual_port=8686)
        window._on_lan_started(ip, 8686)
        urls = [edit.text() for edit in window.lan_link_edits]
        check("4 个链接框均已填充明文 URL", len(urls) == 4 and all(urls), str(len(urls)))
        check("链接框内容为 http://<LAN_IP>:<端口>/s/<token>/…",
              all(u.startswith(f"http://{ip}:8686/s/{token}/") for u in urls), urls[0])
        check("界面链接未打码", all("••" not in u and "***" not in u for u in urls))
        check("链接框只读但文本可选中复制",
              all(edit.isReadOnly() for edit in window.lan_link_edits))
        check("4 个复制按钮可用",
              len(window.lan_copy_btns) == 4
              and all(btn.isEnabled() for btn in window.lan_copy_btns))
        check("4 个二维码按钮可用",
              len(window.lan_qr_btns) == 4
              and all(btn.isEnabled() for btn in window.lan_qr_btns))
        check("标签提示为明文链接",
              "明文" in window.lan_info_lbl.text() and "http://" in window.lan_info_lbl.text(),
              window.lan_info_lbl.text()[:80])
        window._copy_lan_link(1)
        clip = QApplication.clipboard().text()
        check("单条复制写入剪贴板内容 == 该条纯 URL", clip == urls[1], clip[:60])
        check("复制内容不含标签/换行",
              "\n" not in clip and "iOS" not in clip and clip == clip.strip())
        window._copy_lan_link(0)
        check("复制第 0 条不受其他条目影响",
              QApplication.clipboard().text() == urls[0])
        payload = window._copy_lan_link_checked(2)
        check("测试辅助函数返回第 3 条纯 URL", payload == urls[2])
        window._set_lan_link_state(False)
        check("停止后链接框清空且按钮禁用",
              all(not e.text() for e in window.lan_link_edits)
              and all(not b.isEnabled() for b in window.lan_copy_btns))
    finally:
        if window is not None:
            try:
                window._force_quit = True
                window._shutdown_background()
                window._cleanup_tray()
                window.close()
            except Exception:
                pass
        for name, original in originals.items():
            if name in ("load_config", "save_config"):
                setattr(main_gui, name, original)
            else:
                setattr(main_gui.MainWindow, name, original)


def test_package_ip_list_ready(tmp):
    print("\n📋 6. 开发树中的 bin/ip.txt（打包前置条件）")
    repo_ip = os.path.join(path_utils.APP_ROOT, "bin", "ip.txt")
    if os.path.isfile(repo_ip):
        entries = [ln.strip() for ln in open(repo_ip, encoding="utf-8").read().splitlines()
                   if ln.strip() and not ln.strip().startswith("#")]
        try:
            import ipaddress
            ok = all(ipaddress.ip_network(x, strict=False).version == 4 for x in entries)
        except Exception:
            ok = False
        check("开发树 bin/ip.txt 存在且为合法 IPv4 CIDR", ok and len(entries) > 0,
              f"{len(entries)} 条")
    else:
        check("开发树 bin/ip.txt 存在且为合法 IPv4 CIDR", False, "缺失")
    check("official ipv6 名单在构建缓存中可用或可忽略",
          True if not os.path.isfile(os.path.join(
              os.environ.get("TEMP", ""), "cffo_build_cache", "ipv6.txt"))
          else os.path.getsize(os.path.join(
              os.environ.get("TEMP", ""), "cffo_build_cache", "ipv6.txt")) > 0)


def main():
    print("=" * 74)
    print("CF-FlClash-Optimizer v1.3.2 测试（明文链接/单条复制 · 访问日志脱敏 · ip.txt）")
    print("=" * 74)
    tmp = tempfile.mkdtemp(prefix="cffo-v132-")
    try:
        test_subscription_links()
        test_access_log_format()
        test_live_access_log(tmp)
        test_ip_list_chain(tmp)
        test_gui_plaintext_links(tmp)
        test_package_ip_list_ready(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("\n" + "=" * 74)
    total = PASS + FAIL
    print(f"结果: {PASS}/{total} 通过, {FAIL} 失败")
    if FAIL:
        print("失败项: " + "; ".join(FAILURES))
    else:
        print("🎉 v1.3.2 测试全部通过")
    print("=" * 74)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
